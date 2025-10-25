package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/skip2/go-qrcode"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"

	waE2E "go.mau.fi/whatsmeow/binary/proto"
)

const meowsVersion = "whatsmeow-pg-single-schema-public-2"

func main() {
	_ = godotenv.Load()

	addr := getEnv("ADDR", ":8080")
	adminToken := os.Getenv("ADMIN_TOKEN")
	if adminToken == "" {
		log.Println("[WARN] ADMIN_TOKEN não definido — defina no .env para proteger rotas administrativas.")
	}

	// DB (public)
	dbm, err := NewDBManagerFromEnv()
	if err != nil {
		log.Fatalf("erro DB: %v", err)
	}
	if err := dbm.Init(context.Background()); err != nil {
		log.Fatalf("erro init DB/migrations: %v", err)
	}

	mgr := NewSessionManager(dbm, adminToken)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	// Admin: criar/listar
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !mgr.isAdmin(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPost:
			var body struct {
				ID    string `json:"id"`
				Token string `json:"token"` // opcional; se vazio, usa o ID como token
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.ID == "" {
				body.ID = fmt.Sprintf("sess-%d", time.Now().UnixNano())
			}
			if !isSafeID(body.ID) {
				http.Error(w, "session id inválido", http.StatusBadRequest)
				return
			}
			if body.Token == "" {
				body.Token = body.ID // default: token == id
			}

			s, err := mgr.GetOrCreate(body.ID)
			if err != nil {
				http.Error(w, fmt.Sprintf("erro criar sessão: %v", err), http.StatusInternalServerError)
				return
			}
			s.SetToken(body.Token)

			// Guarda HASH e também o token_plain (para o ADMIN ver depois)
			if err := mgr.dbm.UpsertInstance(r.Context(), s.id, "", HashTokenPlaintext(body.Token), meowsVersion, body.Token); err != nil {
				log.Printf("[warn] upsert instance meta: %v", err)
			}
			jsonWrite(w, map[string]string{
				"sessionId":    body.ID,
				"sessionToken": body.Token,
			}, http.StatusOK)

		case http.MethodGet:
			// lista com tokens (ADMIN only)
			stats := mgr.StatusAllExact()
			// injeta tokens reais (de memória) ou do banco (fallback) em cada item
			for i, st := range stats {
				idAny := st["sessionId"]
				id, _ := idAny.(string)
				if id == "" {
					continue
				}
				// tenta pegar da memória
				if s := mgr.getInMemory(id); s != nil {
					if tok := s.GetToken(); tok != "" {
						st["token"] = tok
						stats[i] = st
						continue
					}
				}
				// fallback banco
				if tok, err := mgr.dbm.GetInstanceTokenPlain(r.Context(), id); err == nil && tok != "" {
					st["token"] = tok
					stats[i] = st
				}
			}
			jsonWrite(w, map[string]any{"sessions": stats}, http.StatusOK)

		default:
			http.Error(w, "método não suportado", http.StatusMethodNotAllowed)
		}
	})

	// Rotas por sessão
	mux.HandleFunc("/sessions/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/sessions/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}
		id := parts[0]
		action := ""
		if len(parts) > 1 {
			action = parts[1]
		}

		// GET /sessions/{id}/token  (ADMIN) -> retorna o token em texto
		if action == "token" && r.Method == http.MethodGet {
			if !mgr.isAdmin(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			// tenta memória; se vazio, banco
			if s := mgr.getInMemory(id); s != nil {
				if tok := s.GetToken(); tok != "" {
					jsonWrite(w, map[string]string{"sessionId": id, "token": tok}, http.StatusOK)
					return
				}
			}
			tok, err := mgr.dbm.GetInstanceTokenPlain(r.Context(), id)
			if err != nil {
				http.Error(w, fmt.Sprintf("db: %v", err), http.StatusInternalServerError)
				return
			}
			if tok == "" {
				http.Error(w, "token não encontrado", http.StatusNotFound)
				return
			}
			jsonWrite(w, map[string]string{"sessionId": id, "token": tok}, http.StatusOK)
			return
		}

		// DELETE /sessions/{id}
		if action == "" && r.Method == http.MethodDelete {
			sess, _ := mgr.GetOrCreate(id)
			if !(mgr.isAdmin(r) || (sess != nil && sess.IsAuthorized(r))) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := mgr.DeleteSession(id); err != nil {
				http.Error(w, fmt.Sprintf("delete: %v", err), http.StatusInternalServerError)
				return
			}
			jsonWrite(w, map[string]string{"status": "deleted", "sessionId": id}, http.StatusOK)
			return
		}

		// demais rotas precisam da sessão
		sess, err := mgr.GetOrCreate(id)
		if err != nil {
			http.Error(w, fmt.Sprintf("erro abrir sessão: %v", err), http.StatusInternalServerError)
			return
		}
		if !(mgr.isAdmin(r) || sess.IsAuthorized(r)) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch action {
		case "start":
			if r.Method != http.MethodPost {
				http.Error(w, "use POST", http.StatusMethodNotAllowed)
				return
			}
			if err := sess.Start(); err != nil {
				http.Error(w, fmt.Sprintf("start: %v", err), http.StatusInternalServerError)
				return
			}
			jsonWrite(w, map[string]string{"status": "connected (se não logado, abra /sessions/" + id + "/qr.png)"}, http.StatusOK)

		case "qr.png":
			if r.Method != http.MethodGet {
				http.Error(w, "use GET", http.StatusMethodNotAllowed)
				return
			}
			code := sess.QR()
			if code == "" {
				http.Error(w, "QR ainda não disponível. Chame /sessions/"+id+"/start primeiro.", http.StatusNotFound)
				return
			}
			png, err := qrcode.Encode(code, qrcode.Medium, 256)
			if err != nil {
				http.Error(w, fmt.Sprintf("qrcode: %v", err), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "image/png")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(png)

		case "status":
			if r.Method != http.MethodGet {
				http.Error(w, "use GET", http.StatusMethodNotAllowed)
				return
			}
			st := sess.SafeStatus()
			// ADMIN também enxerga o token aqui
			if mgr.isAdmin(r) {
				if tok := sess.GetToken(); tok != "" {
					st["token"] = tok
				} else if tokdb, err := mgr.dbm.GetInstanceTokenPlain(r.Context(), id); err == nil && tokdb != "" {
					st["token"] = tokdb
				}
			}
			jsonWrite(w, st, http.StatusOK)

		case "send":
			if r.Method != http.MethodPost {
				http.Error(w, "use POST", http.StatusMethodNotAllowed)
				return
			}
			var in struct {
				To      string `json:"to"`
				Message string `json:"message"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.To == "" || in.Message == "" {
				http.Error(w, "json inválido: campos 'to' e 'message' obrigatórios", http.StatusBadRequest)
				return
			}
			resp, err := sess.SendText(in.To, in.Message)
			if err != nil {
				http.Error(w, fmt.Sprintf("send: %v", err), http.StatusInternalServerError)
				return
			}
			jsonWrite(w, resp, http.StatusOK)

		case "logout":
			if r.Method != http.MethodPost {
				http.Error(w, "use POST", http.StatusMethodNotAllowed)
				return
			}
			if err := sess.Logout(); err != nil {
				http.Error(w, fmt.Sprintf("logout: %v", err), http.StatusInternalServerError)
				return
			}
			jsonWrite(w, map[string]string{"status": "logged out"}, http.StatusOK)

		default:
			http.NotFound(w, r)
		}
	})

	handler := recoverMiddleware(mux)

	log.Printf("API multi-sessões (Postgres, schema público) ouvindo em %s", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

/* ---------- Session Manager ---------- */

type SessionManager struct {
	dbm        *DBManager
	adminToken string

	mu   sync.RWMutex
	sess map[string]*Session
}

func NewSessionManager(dbm *DBManager, adminToken string) *SessionManager {
	return &SessionManager{
		dbm:        dbm,
		adminToken: adminToken,
		sess:       make(map[string]*Session),
	}
}

func (m *SessionManager) StatusAllExact() []map[string]any {
	m.mu.RLock()
	list := make([]*Session, 0, len(m.sess))
	for _, s := range m.sess {
		list = append(list, s)
	}
	m.mu.RUnlock()

	out := make([]map[string]any, 0, len(list))
	for _, s := range list {
		if s == nil {
			continue
		}
		out = append(out, s.SafeStatus())
	}
	return out
}

func (m *SessionManager) GetOrCreate(id string) (*Session, error) {
	m.mu.RLock()
	if s, ok := m.sess[id]; ok {
		m.mu.RUnlock()
		return s, nil
	}
	m.mu.RUnlock()

	ctx := context.Background()

	// 1) pega JID salvo (se houver)
	jidStr, err := m.dbm.GetInstanceJID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("buscar jid da instância: %w", err)
	}

	// 2) pega ou cria o device
	var devStore *store.Device
	if jidStr != "" {
		if jid, err := parseJIDText(jidStr); err == nil && jid != nil {
			devStore, err = m.dbm.Container.GetDevice(ctx, *jid)
			if err != nil {
				return nil, fmt.Errorf("GetDevice: %w", err)
			}
		}
	}
	if devStore == nil {
		devStore = m.dbm.Container.NewDevice()
	}

	cli := whatsmeow.NewClient(devStore, nil)

	s := &Session{
		id:     id,
		client: cli,
		dbm:    m.dbm,

		connected: false,
		loggedIn:  false,
		jid:       jidStr,
	}
	s.registerHandlers()

	// metadata mínima (não atualiza token aqui)
	if err := m.dbm.UpsertInstance(ctx, id, jidStr, "", meowsVersion, ""); err != nil {
		log.Printf("[warn] upsert instance meta: %v", err)
	}

	m.mu.Lock()
	m.sess[id] = s
	m.mu.Unlock()
	return s, nil
}

func (m *SessionManager) DeleteSession(id string) error {
	m.mu.Lock()
	s, ok := m.sess[id]
	if ok {
		delete(m.sess, id)
	}
	m.mu.Unlock()

	if ok && s != nil {
		if err := s.Delete(); err != nil {
			return err
		}
	}
	ctx := context.Background()
	if err := m.dbm.DeleteInstance(ctx, id); err != nil {
		return err
	}
	return nil
}

func (m *SessionManager) isAdmin(r *http.Request) bool {
	bt := bearerToken(r)
	return m.adminToken != "" && bt == m.adminToken
}

func (m *SessionManager) getInMemory(id string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sess[id]
}

/* ---------- Session ---------- */

type Session struct {
	id string

	client *whatsmeow.Client

	mu       sync.RWMutex
	qrStr    string
	qrTS     time.Time
	started  bool
	stopChan chan struct{}
	token    string

	connected bool
	loggedIn  bool
	jid       string

	dbm *DBManager
}

func (s *Session) SetToken(t string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = t
}

func (s *Session) GetToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

func (s *Session) IsAuthorized(r *http.Request) bool {
	bt := bearerToken(r)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token != "" && bt == s.token
}

func (s *Session) registerHandlers() {
	s.client.AddEventHandler(func(e interface{}) {
		switch v := e.(type) {
		case *events.Message:
			log.Printf("[%s][msg] de=%s chat=%s texto=%s", s.id, v.Info.Sender.String(), v.Info.Chat.String(), safeText(v))
		case *events.Connected:
			s.mu.Lock()
			s.connected = true
			if s.client != nil {
				s.loggedIn = s.client.IsLoggedIn()
				if s.client.Store != nil {
					s.jid = s.client.Store.ID.String()
				}
			}
			jid := s.jid
			connected := s.connected
			logged := s.loggedIn
			s.mu.Unlock()
			_ = s.dbm.UpsertInstance(context.Background(), s.id, jid, "", meowsVersion, "")
			_ = s.dbm.UpdateInstanceStatus(context.Background(), s.id, jid, connected, logged)
			log.Printf("[%s][conn] conectado! jid=%s", s.id, jid)
		case *events.Disconnected:
			s.mu.Lock()
			s.connected = false
			s.loggedIn = false
			jid := s.jid
			s.mu.Unlock()
			_ = s.dbm.UpdateInstanceStatus(context.Background(), s.id, jid, false, false)
			log.Printf("[%s][conn] desconectado: %+v", s.id, v)
		}
	})
}

func (s *Session) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.stopChan = make(chan struct{})
	s.mu.Unlock()

	ctx := context.Background()
	qrChan, err := s.client.GetQRChannel(ctx)
	if err != nil {
		s.resetStarted()
		return fmt.Errorf("GetQRChannel: %w", err)
	}
	go func() {
		for item := range qrChan {
			if item.Code != "" {
				s.mu.Lock()
				s.qrStr = item.Code
				s.qrTS = time.Now()
				s.mu.Unlock()
				log.Printf("[%s][qr] novo código", s.id)
			}
			switch item.Event {
			case "success":
				s.mu.Lock()
				s.connected = true
				s.loggedIn = true
				if s.client != nil && s.client.Store != nil {
					s.jid = s.client.Store.ID.String()
				}
				jid := s.jid
				s.mu.Unlock()
				_ = s.dbm.UpsertInstance(context.Background(), s.id, jid, "", meowsVersion, "")
				_ = s.dbm.UpdateInstanceStatus(context.Background(), s.id, jid, true, true)
				log.Printf("[%s][qr] pareado com sucesso (jid=%s)", s.id, s.jid)
			case "timeout":
				log.Printf("[%s][qr] timeout; chame /sessions/%s/start novamente", s.id, s.id)
			case "error":
				if item.Error != nil {
					log.Printf("[%s][qr] erro: %v", s.id, item.Error)
				}
			}
		}
	}()

	if err := s.client.Connect(); err != nil {
		s.resetStarted()
		return fmt.Errorf("Connect: %w", err)
	}
	_ = s.client.SendPresence(types.PresenceAvailable)
	return nil
}

func (s *Session) QR() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.qrStr
}

func (s *Session) Status() map[string]any {
	s.mu.RLock()
	out := map[string]any{
		"connected": s.connected,
		"has_qr":    s.qrStr != "",
		"jid":       s.jid,
		"logged_in": s.loggedIn,
		"qr_at":     s.qrTS,
		"sessionId": s.id,
	}
	s.mu.RUnlock()
	return out
}

func (s *Session) SafeStatus() (out map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s][status] recover de panic: %v", s.id, r)
			out = map[string]any{
				"connected": false,
				"has_qr":    false,
				"jid":       "",
				"logged_in": false,
				"qr_at":     time.Time{},
				"sessionId": s.id,
			}
		}
	}()
	return s.Status()
}

func (s *Session) SendText(to, message string) (map[string]any, error) {
	s.mu.RLock()
	logged := s.loggedIn
	s.mu.RUnlock()
	if !logged {
		return nil, errors.New("não logado; faça pareamento com /start e /qr.png")
	}
	if s.client == nil {
		return nil, errors.New("sessão indisponível")
	}
	jid, err := parseUserToJID(to)
	if err != nil {
		return nil, fmt.Errorf("destino inválido: %w", err)
	}
	msg := &waE2E.Message{Conversation: proto.String(message)}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := s.client.SendMessage(ctx, jid, msg)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"status":     "ok",
		"serverTime": resp.Timestamp,
		"id":         resp.ID,
	}, nil
}

func (s *Session) Logout() error {
	if s.client == nil {
		s.mu.Lock()
		s.connected = false
		s.loggedIn = false
		jid := s.jid
		s.mu.Unlock()
		_ = s.dbm.UpdateInstanceStatus(context.Background(), s.id, jid, false, false)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_ = s.client.Logout(ctx)
	if s.client.Store != nil {
		_ = s.client.Store.Delete(ctx)
	}
	s.client.Disconnect()

	s.mu.Lock()
	s.connected = false
	s.loggedIn = false
	jid := s.jid
	s.mu.Unlock()
	_ = s.dbm.UpdateInstanceStatus(context.Background(), s.id, jid, false, false)
	return nil
}

func (s *Session) Delete() error {
	_ = s.Logout()
	s.mu.Lock()
	s.client = nil
	s.mu.Unlock()
	return nil
}

func (s *Session) resetStarted() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = false
	if s.stopChan != nil {
		close(s.stopChan)
		s.stopChan = nil
	}
}

/* ---------- helpers ---------- */

func parseUserToJID(to string) (types.JID, error) {
	if j, err := types.ParseJID(to); err == nil && j.User != "" {
		return j, nil
	}
	normalized := ""
	for _, r := range to {
		if (r >= '0' && r <= '9') || r == '+' {
			normalized += string(r)
		}
	}
	if len(normalized) == 0 {
		return types.EmptyJID, errors.New("número vazio")
	}
	if normalized[0] == '+' {
		normalized = normalized[1:]
	}
	return types.NewJID(normalized, types.DefaultUserServer), nil
}

func jsonWrite(w http.ResponseWriter, v any, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func safeText(m *events.Message) string {
	if m.Message == nil {
		return ""
	}
	if m.Message.GetConversation() != "" {
		return m.Message.GetConversation()
	}
	if ext := m.Message.GetExtendedTextMessage(); ext != nil {
		return ext.GetText()
	}
	return ""
}

func isSafeID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return ""
	}
	return strings.TrimSpace(h[len(p):])
}

func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[recover] %v", rec)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
