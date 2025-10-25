<p align="center">
  <img src="https://raw.githubusercontent.com/luiis716/CiraGo/main/logo%20CiraGo.png" alt="CiraGo" width="260">
</p>

# CiraGo

CiraGo é uma implementação da biblioteca [`whatsmeow`](https://github.com/tulir/whatsmeow) como um serviço de API RESTful simples, com suporte a **múltiplos dispositivos** e **sessões simultâneas**.

O **whatsmeow** não usa Puppeteer (Chrome headless) nem emulador Android. Ele se comunica **diretamente via WebSocket** com os servidores do WhatsApp, o que torna o sistema **mais rápido** e **muito mais leve** de CPU/RAM que soluções baseadas em navegador/emulador.
A desvantagem é que **mudanças no protocolo do WhatsApp** podem exigir **atualizações da biblioteca**.

> ⚠️ **Aviso**
> O uso deste software pode violar os Termos de Serviço do WhatsApp e resultar em **banimento** do seu número. **Não** use para SPAM. Utilize por sua conta e risco. Para fins comerciais, considere provedores oficiais do **WhatsApp Business API**.

---

## Requisitos

* **Go** 1.21+ (ou superior compatível)
* **PostgreSQL** 13+
* Rede com saída para os servidores do WhatsApp (porta 443)
* Sistema com fuso horário correto (recomendado sincronização NTP)

---

## Clonar e preparar

```bash
git clone https://github.com/sua-org/cirago.git
cd cirago
```

O projeto já contém `go.mod` com versões travadas. Você só precisa gerar o `go.sum`:

```bash
go mod tidy
```

> Se estiver usando **proxy corporativo** ou rede restrita, configure `GOPROXY` conforme necessário.

---

## Configuração (.env)

Crie um arquivo `.env` na raiz do projeto com as variáveis abaixo.
O serviço usa **PostgreSQL (schema público)** e um **token de admin** para proteger as rotas administrativas.

```dotenv
# Porta de escuta da API
ADDR=:8080

# Token mestre (ADMIN) para rotas administrativas (criar/listar/remover sessões, ver tokens)
ADMIN_TOKEN=troque-este-token-super-seguro

# Postgres — use UMA das duas opções:

# Opção A) DSN completo (recomendado em produção)
# PG_DSN=postgres://usuario:senha@host:5432/cirago?sslmode=disable

# Opção B) Campos separados (o código monta o DSN)
PG_HOST=localhost
PG_PORT=5432
PG_USER=postgres
PG_PASSWORD=postgres
PG_DBNAME=cirago
PG_SSLMODE=disable
```

> Dica: para ambientes fora de dev, habilite SSL conforme sua infra (`sslmode=require`, etc).

---

## Executar

### Desenvolvimento

```bash
go run .
```

Ao iniciar, você deve ver algo como:

```
API multi-sessões (Postgres, schema público) ouvindo em :8080
```

### Produção (build estático simples)

```bash
go build -o cirago .
./cirago
```

> Você pode criar um serviço systemd, container Docker ou orquestrar com PM2/Nomad/K8s — o binário é autossuficiente.

---

## Como funciona (resumo rápido)

* **Multi-instância**: cada sessão é um *device* no mesmo conjunto de tabelas do whatsmeow (nada de criar um schema por sessão).
* **Metadados**: a tabela `public.meows_instances` guarda:

  * `id` (identificador da sessão)
  * `jid` (número pareado, quando houver)
  * `connected`, `logged_in`
  * `token_hash` (hash do token da sessão)
  * `token_plain` (token em texto, **visível apenas para ADMIN**)
  * `meows_version`, `created_at`, `updated_at`
* **Tokens**:

  * Ao criar uma sessão sem informar `token`, o **token = id**.
  * As rotas da sessão exigem `Authorization: Bearer <token-da-sessão>`.
  * Apenas rotas **ADMIN** exibem o `token_plain` para você consultar depois.

> Os **endpoints** e exemplos de uso estão no arquivo **Postman/Insomnia** incluído no repositório (JSON). Basta importar e usar.

---

## Erros comuns & Solução

* **`ERROR: relation "whatsmeow_version" does not exist`**
  Certifique-se de estar apontando para o **mesmo banco** e que o usuário tem permissão de **criar tabelas**. O serviço executa as migrações automaticamente no startup.
  Verifique seu `.env` (especialmente `PG_DSN` ou `PG_HOST/PG_DBNAME`).
  Rode novamente:

  ```bash
  go mod tidy
  go run .
  ```

* **`send: failed to prefetch sessions: relation ... does not exist`**
  Ocorre quando as migrações do whatsmeow não foram aplicadas no banco alvo.
  Garanta que o processo rodou com as credenciais corretas e sem erros no startup.

* **Token não funciona / 401**
  Use o **token em texto** (não o hash) no header `Authorization`.
  Se você não definiu um token customizado ao criar, o token é **igual ao `id`** da sessão.

---

## Segurança

* Defina um **ADMIN_TOKEN** forte e mantenha-o em segredo (use secrets do seu orquestrador).
* Restrinja o acesso de rede às rotas administrativas (por IP, VPN, mTLS, etc.).
* Faça **backup** do banco PostgreSQL regularmente (as chaves de sessão vivem lá).
* Não exponha `token_plain` publicamente — o servidor só o retorna em rotas **ADMIN**.

---

## Scripts úteis (opcional)

```bash
# rodar testes (se/quando existirem)
go test ./...

# checar vulnerabilidades das deps (se tiver govulncheck instalado)
govulncheck ./...
```

---

## Licença

Este projeto é licenciado sob a **MIT License**. Veja o arquivo [LICENSE](./LICENSE) para mais detalhes.

---
