package main

import (
	"context"
	"database/sql"
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

const meowsVersion = "whatsmeow-pg-single-schema-public-5"
const qrTTL = 60 * time.Second // QR válido por, no máximo, 60s

func main() {
	_ = godotenv.Load()

	addr := getEnv("ADDR", ":8080")
	adminToken := os.Getenv("ADMIN_TOKEN")
	if adminToken == "" {
		log.Println("[WARN] ADMIN_TOKEN não definido — defina no .env para proteger rotas administrativas.")
	}

	// DB (schema público)
	dbm, err := NewDBManagerFromEnv()
	if err != nil {
		log.Fatalf("erro DB: %v", err)
	}
	if err := dbm.Init(context.Background()); err != nil {
		log.Fatalf("erro init DB/migrations: %v", err)
	}

	// Auto reconexão/presença sempre ligadas
	autoConnect := true
	autoPresence := true

	mgr := NewSessionManager(dbm, adminToken, autoConnect, autoPresence)

	// Pré-carrega sessões e reconecta as pareadas
	if err := mgr.PreloadFromDB(context.Background()); err != nil {
		log.Printf("[warn] preload sessions: %v", err)
	}

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
			for i, st := range stats {
				idAny := st["sessionId"]
				id, _ := idAny.(string)
				if id == "" {
					continue
				}
				if s := mgr.getInMemory(id); s != nil {
					if tok := s.GetToken(); tok != "" {
						st["token"] = tok
						stats[i] = st
						continue
					}
				}
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

		// GET /sessions/{id}/token  (ADMIN)
		if action == "token" && r.Method == http.MethodGet {
			if !mgr.isAdmin(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
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

		// precisa da sessão
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
				http.Error(w, "QR ainda não disponível ou expirado. Chame /sessions/"+id+"/start.", http.StatusNotFound)
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

	log.Printf("API multi-sessões (Postgres, schema público) ouvindo em %s | AUTO_CONNECT=on", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

/* ---------- Session Manager ---------- */

type SessionManager struct {
	dbm          *DBManager
	adminToken   string
	autoConnect  bool
	autoPresence bool

	mu   sync.RWMutex
	sess map[string]*Session
}

func NewSessionManager(dbm *DBManager, adminToken string, autoConnect, autoPresence bool) *SessionManager {
	return &SessionManager{
		dbm:          dbm,
		adminToken:   adminToken,
		autoConnect:  autoConnect,
		autoPresence: autoPresence,
		sess:         make(map[string]*Session),
	}
}

// Pré-carrega todas as instâncias persistidas (recria clients com devices existentes)
func (m *SessionManager) PreloadFromDB(ctx context.Context) error {
	rows, err := m.dbm.ListInstances(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		id := r.ID

		// já existe em memória? pula
		m.mu.RLock()
		_, ok := m.sess[id]
		m.mu.RUnlock()
		if ok {
			continue
		}

		var devStore *store.Device
		hasJID := r.JID.Valid && r.JID.String != ""
		if hasJID {
			if jid, err := parseJIDText(r.JID.String); err == nil && jid != nil {
				ds, err := m.dbm.Container.GetDevice(ctx, *jid)
				if err != nil {
					log.Printf("[warn] GetDevice(%s) falhou: %v (não criaremos NewDevice para não sobrescrever)", r.JID.String, err)
					continue
				}
				devStore = ds
			}
		}
		if !hasJID {
			// sessão nova (ainda sem parear): pode ter um device vazio
			devStore = m.dbm.Container.NewDevice()
		}
		if devStore == nil {
			continue
		}

		cli := whatsmeow.NewClient(devStore, nil)

		s := &Session{
			id:        id,
			client:    cli,
			dbm:       m.dbm,
			jid:       strOrEmpty(r.JID),
			connected: false, // runtime será atualizado por eventos/Connect()
			loggedIn:  false,
		}
		s.registerHandlers()
		if r.TokenPlain.Valid {
			s.SetToken(r.TokenPlain.String)
		}

		m.mu.Lock()
		m.sess[id] = s
		m.mu.Unlock()

		// se já tem JID (pareado), reconecta sempre
		if hasJID && m.autoConnect {
			go s.AutoReconnectOnBoot(m.autoPresence)
		}
	}
	return nil
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

	// 1) pega JID salvo (se houver)
	jidStr, err := m.dbm.GetInstanceJID(context.Background(), id)
	if err != nil {
		return nil, fmt.Errorf("buscar jid da instância: %w", err)
	}

	// 2) pega ou cria o device
	var devStore *store.Device
	if jidStr != "" {
		if jid, err := parseJIDText(jidStr); err == nil && jid != nil {
			devStore, err = m.dbm.Container.GetDevice(context.Background(), *jid)
			if err != nil {
				// se já existe JID e falhou pegar o device, não crie novo para não sobrescrever chaves
				return nil, fmt.Errorf("GetDevice: %w", err)
			}
		}
	}
	if devStore == nil {
		// sessão ainda não pareada: cria device "vazio"
		devStore = m.dbm.Container.NewDevice()
	}

	cli := whatsmeow.NewClient(devStore, nil)

	s := &Session{
		id:        id,
		client:    cli,
		dbm:       m.dbm,
		connected: false,
		loggedIn:  false,
		jid:       jidStr,
	}
	s.registerHandlers()

	// metadata mínima (não atualiza token aqui)
	if err := m.dbm.UpsertInstance(context.Background(), id, jidStr, "", meowsVersion, ""); err != nil {
		log.Printf("[warn] upsert instance meta: %v", err)
	}

	m.mu.Lock()
	m.sess[id] = s
	m.mu.Unlock()

	// se já tem JID, reconecta sempre
	if jidStr != "" && m.autoConnect {
		go s.AutoReconnectOnBoot(m.autoPresence)
	}

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
	return m.dbm.DeleteInstance(context.Background(), id)
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
			// ao conectar/logar, zera qualquer QR remanescente
			s.qrStr = ""
			s.qrTS = time.Time{}

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

// AutoReconectar no boot (para sessões com JID salvo)
func (s *Session) AutoReconnectOnBoot(sendPresence bool) {
	// Não interfere em sessões não pareadas (sem JID)
	s.mu.RLock()
	hasJID := s.jid != ""
	isConn := s.client != nil && s.client.IsConnected()
	s.mu.RUnlock()
	if !hasJID || isConn {
		return
	}

	backoffs := []time.Duration{0, 2 * time.Second, 5 * time.Second, 10 * time.Second}
	for i, d := range backoffs {
		if d > 0 {
			time.Sleep(d)
		}
		err := s.connectOnce(sendPresence)
		if err == nil {
			log.Printf("[%s][boot] reconectado (tentativa #%d)", s.id, i+1)
			return
		}
		log.Printf("[%s][boot] reconectar falhou (tentativa #%d): %v", s.id, i+1, err)
	}
	log.Printf("[%s][boot] não foi possível reconectar automaticamente (verifique rede/ban/etc.)", s.id)
}

func (s *Session) connectOnce(sendPresence bool) error {
	s.mu.RLock()
	cli := s.client
	s.mu.RUnlock()
	if cli == nil {
		return errors.New("client nil")
	}
	if cli.IsConnected() {
		return nil
	}

	// Connect() não recebe context
	if err := cli.Connect(); err != nil {
		return err
	}
	if sendPresence {
		_ = cli.SendPresence(types.PresenceAvailable)
	}
	return nil
}

// recria um client novo com um device novo (chamar com s.mu já travado)
func (s *Session) recreateClientUnlocked() {
	newDev := s.dbm.Container.NewDevice()
	s.client = whatsmeow.NewClient(newDev, nil)
	// re-registra os handlers no novo client
	s.registerHandlers()
}

func (s *Session) Start() error {
	s.mu.Lock()
	// se ficou travado como "started", decide se reusa ou reinicia
	if s.started {
		// se já está conectado, não precisa recomeçar
		if s.client != nil && s.client.IsConnected() {
			s.mu.Unlock()
			return nil
		}
		// força novo ciclo
		s.started = false
	}
	// reset QR sempre ao iniciar
	s.qrStr = ""
	s.qrTS = time.Time{}

	s.started = true
	s.stopChan = make(chan struct{})
	s.mu.Unlock()

	qrChan, err := s.client.GetQRChannel(context.Background())
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
				// QR não é mais necessário
				s.qrStr = ""
				s.qrTS = time.Time{}
				jid := s.jid
				s.mu.Unlock()

				_ = s.dbm.UpsertInstance(context.Background(), s.id, jid, "", meowsVersion, "")
				_ = s.dbm.UpdateInstanceStatus(context.Background(), s.id, jid, true, true)
				log.Printf("[%s][qr] pareado com sucesso (jid=%s)", s.id, s.jid)

			case "timeout":
				// QR venceu: zera para não servir QR expirado
				s.mu.Lock()
				s.qrStr = ""
				s.qrTS = time.Time{}
				s.mu.Unlock()
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

func (s *Session) hasValidQRLocked() bool {
	if s.qrStr == "" {
		return false
	}
	return time.Since(s.qrTS) <= qrTTL
}

func (s *Session) QR() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.hasValidQRLocked() {
		return ""
	}
	return s.qrStr
}

func (s *Session) Status() map[string]any {
	s.mu.RLock()
	hasValidQR := s.hasValidQRLocked()
	out := map[string]any{
		"connected": s.connected,
		"has_qr":    hasValidQR,
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
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// tenta encerrar sessão ativa
		_ = s.client.Logout(ctx)

		// apaga dados persistidos (chaves/sessão)
		if s.client.Store != nil {
			_ = s.client.Store.Delete(ctx)
		}

		// encerra conexões
		s.client.Disconnect()
	}

	// limpa estado
	s.connected = false
	s.loggedIn = false
	s.qrStr = ""
	s.qrTS = time.Time{}
	s.started = false
	if s.stopChan != nil {
		close(s.stopChan)
		s.stopChan = nil
	}

	// recria client zerado com device novo para próximo pareamento
	s.recreateClientUnlocked()

	// persiste status desconectado
	jid := s.jid
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

func strOrEmpty(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}
