# Integrations

Encryptoglyph is a separate app. Other GoDesk tools (Konektor, n8n, RailYard, scripts) reach it only over HTTP. Nothing here is vendored into another tool.

## API tokens (user-created)

Open the console, choose **Tokens**, give the token a name, pick scopes and an expiry (1–30 days), and press **Create token**. The token (`egt_…`) is shown once. The list shows name, prefix, scopes, expiry and last use, with a **Revoke** button. The same actions are on the API:

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `POST` | `/v1/tokens` | `x-eg-session` | Body `{"name","scopes":[…],"expires_in_days"}`. Returns the token once. |
| `GET` | `/v1/tokens` | `x-eg-session` | Metadata only. No token value or hash. |
| `DELETE` | `/v1/tokens/{id}` | `x-eg-session` | Revokes at once. |

Use a token with `Authorization: Bearer egt_…`.

| Scope | Endpoints |
| --- | --- |
| `keys:read` | `GET /v1/keys` |
| `keys:write` | `POST /v1/keys` |
| `seal` | `POST /v1/seal` |
| `open` | `POST /v1/open` |
| `rewrap` | `POST /v1/rewrap` |
| `blind-index` | `POST /v1/blind-index` |
| `backup` | `POST /v1/backup` |

Rules:

- Only the SHA-256 hash of a token is kept, in process memory, next to the session it belongs to. Nothing is written to disk.
- A token acts on the keyring of the session that created it. Custody is still process-memory, so creating a token keeps that session (and its keys) alive until the token's expiry, at most 30 days. A restart ends every session and every token; OpenBao custody (not connected yet) is what makes keys durable.
- Tokens cannot create tokens, re-authenticate, or shred keys. Those stay session-only.
- At most 20 tokens per session.

## Konektor and n8n

Konektor lists Encryptoglyph in its suite registry (health `GET /v1/status`). Paste a token into the Konektor connection or the n8n "GoDesk API" credential with the Encryptoglyph base URL. No env var is needed on Encryptoglyph for this.
