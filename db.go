package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // driver "pgx" (database/sql)
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
)

/*
 DBManager (schema público):
 - Usa sqlstore.NewWithDB(root) para o whatsmeow aplicar migrações no schema "public"
 - Tabela public.meows_instances guarda metadados das sessões
*/

type DBManager struct {
	DSN       string              // ex.: postgres://user:pass@host:5432/db?sslmode=disable
	Container *sqlstore.Container // container global do whatsmeow (schema público)
	RootDB    *sql.DB             // conexão para metadados (public.meows_instances)
}

type InstanceRow struct {
	ID         string
	JID        sql.NullString
	TokenPlain sql.NullString
	Connected  bool
	LoggedIn   bool
	MeowsVer   sql.NullString
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ---- Setup ----

func NewDBManagerFromEnv() (*DBManager, error) {
	// Monta DSN
	var dsn string
	if env := os.Getenv("PG_DSN"); env != "" {
		dsn = ensureNoSearchPath(env) // remove search_path/options se tiver
	} else {
		host := getEnv("PG_HOST", "localhost")
		port := getEnv("PG_PORT", "5432")
		user := getEnv("PG_USER", "postgres")
		pass := os.Getenv("PG_PASSWORD")
		db := getEnv("PG_DBNAME", "meows")
		ssl := getEnv("PG_SSLMODE", "disable")
		// protege @ em senhas simples
		if strings.Contains(pass, "@") && !strings.Contains(pass, "%40") {
			pass = strings.ReplaceAll(pass, "@", "%40")
		}
		dsn = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", user, pass, host, port, db, ssl)
	}

	// Abre conexão base para queries próprias e para o container whatsmeow
	root, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := root.Ping(); err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("falha ao conectar no Postgres: %w", err)
	}

	// Usa a MESMA conexão no container (schema = public)
	container := sqlstore.NewWithDB(root, "postgres", nil)

	return &DBManager{
		DSN:       dsn,
		Container: container,
		RootDB:    root,
	}, nil
}

func ensureNoSearchPath(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	q := u.Query()
	q.Del("options")
	q.Del("search_path")
	u.RawQuery = q.Encode()
	return u.String()
}

// Init: migrações do whatsmeow + tabela de metadados
func (m *DBManager) Init(ctx context.Context) error {
	// Aplica migrações do whatsmeow (cria whatsmeow_version etc. no "public")
	if err := m.Container.Upgrade(ctx); err != nil {
		return fmt.Errorf("whatsmeow migrate: %w", err)
	}

	// Cria/garante tabela de metadados
	const base = `
CREATE TABLE IF NOT EXISTS public.meows_instances (
  id            TEXT PRIMARY KEY,
  jid           TEXT,
  token_hash    TEXT,
  connected     BOOLEAN NOT NULL DEFAULT false,
  logged_in     BOOLEAN NOT NULL DEFAULT false,
  meows_version TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`
	if _, err := m.RootDB.ExecContext(ctx, base); err != nil {
		return fmt.Errorf("criar public.meows_instances: %w", err)
	}

	// Adiciona token_plain se não existir (token em texto para ADMIN)
	const addTokenPlain = `
ALTER TABLE public.meows_instances
  ADD COLUMN IF NOT EXISTS token_plain TEXT;
`
	if _, err := m.RootDB.ExecContext(ctx, addTokenPlain); err != nil {
		return fmt.Errorf("alter public.meows_instances add token_plain: %w", err)
	}

	return nil
}

// ---- Metadados (sempre schema-qualified) ----

func (m *DBManager) UpsertInstance(ctx context.Context, id, jid, tokenHash, meowsVersion, tokenPlain string) error {
	const q = `
INSERT INTO public.meows_instances (id, jid, token_hash, meows_version, token_plain)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET
  jid           = COALESCE(EXCLUDED.jid, public.meows_instances.jid),
  token_hash    = COALESCE(EXCLUDED.token_hash, public.meows_instances.token_hash),
  meows_version = COALESCE(EXCLUDED.meows_version, public.meows_instances.meows_version),
  token_plain   = COALESCE(EXCLUDED.token_plain, public.meows_instances.token_plain),
  updated_at    = NOW();
`
	_, err := m.RootDB.ExecContext(ctx, q,
		id,
		nullIfEmpty(jid),
		nullIfEmpty(tokenHash),
		nullIfEmpty(meowsVersion),
		nullIfEmpty(tokenPlain),
	)
	return err
}

func (m *DBManager) UpdateInstanceStatus(ctx context.Context, id, jid string, connected, loggedIn bool) error {
	const q = `
UPDATE public.meows_instances
   SET jid = COALESCE($2, jid), connected = $3, logged_in = $4, updated_at = NOW()
 WHERE id  = $1;
`
	_, err := m.RootDB.ExecContext(ctx, q, id, nullIfEmpty(jid), connected, loggedIn)
	return err
}

func (m *DBManager) GetInstanceJID(ctx context.Context, id string) (string, error) {
	var jid sql.NullString
	const q = `SELECT jid FROM public.meows_instances WHERE id=$1`
	err := m.RootDB.QueryRowContext(ctx, q, id).Scan(&jid)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if jid.Valid {
		return jid.String, nil
	}
	return "", nil
}

func (m *DBManager) GetInstanceTokenPlain(ctx context.Context, id string) (string, error) {
	var tok sql.NullString
	const q = `SELECT token_plain FROM public.meows_instances WHERE id=$1`
	err := m.RootDB.QueryRowContext(ctx, q, id).Scan(&tok)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if tok.Valid {
		return tok.String, nil
	}
	return "", nil
}

func (m *DBManager) DeleteInstance(ctx context.Context, id string) error {
	const q = `DELETE FROM public.meows_instances WHERE id=$1`
	_, err := m.RootDB.ExecContext(ctx, q, id)
	return err
}

// Lista todas as instâncias persistidas (para pré-carregar no boot)
func (m *DBManager) ListInstances(ctx context.Context) ([]InstanceRow, error) {
	const q = `
SELECT id, jid, token_plain, connected, logged_in, meows_version, created_at, updated_at
  FROM public.meows_instances
  ORDER BY created_at ASC;
`
	rows, err := m.RootDB.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []InstanceRow
	for rows.Next() {
		var r InstanceRow
		if err := rows.Scan(&r.ID, &r.JID, &r.TokenPlain, &r.Connected, &r.LoggedIn, &r.MeowsVer, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- Helpers ----

func HashTokenPlaintext(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func parseJIDText(s string) (*types.JID, error) {
	if s == "" {
		return nil, nil
	}
	j, err := types.ParseJID(s)
	if err != nil {
		return nil, err
	}
	return &j, nil
}
