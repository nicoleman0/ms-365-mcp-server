# Phase 1 — Reconnaissance & Surface Mapping

**Target:** `@softeria/ms-365-mcp-server` v0.0.0-development (commit `812b427`)
**Date:** 2026-02-23
**Auditor:** Security audit — MSc research project

---

## 1. Server Overview

**Purpose:** MCP (Model Context Protocol) server bridging LLMs to Microsoft 365 via the Microsoft Graph API.

**Architecture:**
- TypeScript/Node.js (requires Node >= 18)
- Two transport modes: stdio (default) and HTTP (Express.js)
- Authentication via MSAL (`@azure/msal-node`) device code flow, or direct token injection
- Auto-generated Graph API client from the MS Graph OpenAPI specification
- 110 endpoints defined in `src/endpoints.json`, mapped to MCP tools via `src/graph-tools.ts`

**Key dependencies:**
| Package | Version | Role |
|---|---|---|
| `@azure/msal-node` | ^3.8.0 | OAuth 2.0 / MSAL authentication |
| `@modelcontextprotocol/sdk` | ^1.25.0 | MCP protocol implementation |
| `express` | ^5.2.1 | HTTP transport server |
| `@toon-format/toon` | ^0.8.0 | Experimental TOON output encoding |
| `zod` | ^3.24.2 | Parameter schema validation |
| `winston` | ^3.17.0 | Logging |
| `commander` | ^11.1.0 | CLI argument parsing |
| `dotenv` | ^17.0.1 | Environment variable loading |

**Optional dependencies:**
| Package | Version | Role |
|---|---|---|
| `keytar` | ^7.9.0 | OS credential store (macOS Keychain, Windows Credential Manager, Linux Secret Service) |
| `@azure/identity` | ^4.5.0 | Azure Key Vault authentication |
| `@azure/keyvault-secrets` | ^4.9.0 | Azure Key Vault secrets retrieval |

---

## 2. Transport Modes

### 2.1 Stdio Mode (Default)

**Entry:** `src/server.ts:485-489`

- Single McpServer instance created at startup (`src/server.ts:103`)
- Connected to `StdioServerTransport`
- Single-user, local process — no network listener
- Auth tools (`login`, `logout`, `verify-login`, `list-accounts`, `select-account`, `remove-account`) registered by default
- Tokens managed by `AuthManager` via MSAL device code flow

**Attack surface:**
- Prompt injection via tool responses (PI-TR) — content returned from Graph API is passed to the LLM
- Confused deputy (CD) — LLM performs privileged actions based on untrusted input in email/Teams content
- Token leakage (TL) — token cache on disk, environment variable injection
- Local process only — no remote network exposure

### 2.2 HTTP Mode (`--http`)

**Entry:** `src/server.ts:130-484`

- Express.js server listening on configurable `host:port` (default: all interfaces, port 3000)
- **New McpServer created per request** (`src/server.ts:371, 420`) — mitigates cross-request tool state leakage
- Stateless `StreamableHTTPServerTransport` (no session IDs)
- Bearer token auth middleware at `/mcp` endpoint (`src/lib/microsoft-auth.ts:9-36`)
- Per-request token isolation via `AsyncLocalStorage` (`src/request-context.ts`)
- Auth tools disabled by default in HTTP mode (re-enabled with `--enable-auth-tools`)

**Exposed endpoints:**
| Endpoint | Method | Auth Required | Purpose |
|---|---|---|---|
| `/` | GET | No | Health check |
| `/.well-known/oauth-authorization-server` | GET | No | OAuth discovery metadata |
| `/.well-known/oauth-protected-resource` | GET | No | Protected resource metadata |
| `/authorize` | GET | No | Redirects to Microsoft OAuth |
| `/token` | POST | No | Token exchange (auth code → access token) |
| `/register` | POST | No | Dynamic client registration (optional) |
| `/mcp` | GET, POST | **Bearer token** | MCP protocol endpoint |
| `/auth/*` | Various | Varies | MCP SDK auth router |

**Attack surface (additional to stdio):**
- Network-accessible endpoint on all interfaces by default
- CORS defaults to `Access-Control-Allow-Origin: *` (`src/server.ts:139`)
- Unauthenticated endpoints: health check, OAuth discovery, `/authorize`, `/token`, `/register`
- Bearer token middleware does **no server-side validation** — token validity is deferred to Graph API calls (`src/lib/microsoft-auth.ts:23` — comment: "we don't validate the token here")
- `trust proxy` enabled (`src/server.ts:134`) — trusts `X-Forwarded-For` headers
- Refresh token passed via custom header `x-microsoft-refresh-token` (`src/lib/microsoft-auth.ts:27`)

---

## 3. Tool Inventory

### 3.1 Summary

| Category | Total | GET (read) | POST/PUT/PATCH/DELETE (write) |
|---|---|---|---|
| **Personal tools** | 73 | 45 | 28 |
| **Org-mode-only tools** | 37 | 27 | 10 |
| **Total** | 110 | 66 | 44 |

Note: `search-query` has both `scopes` and `workScopes` — it works in personal mode with limited scope, and gains additional org-mode capabilities.

Additionally, in stdio mode 6 **auth tools** are registered: `login`, `logout`, `verify-login`, `list-accounts`, `select-account`, `remove-account` (`src/auth-tools.ts`).

In **discovery mode** (`--discovery`), only 2 meta-tools are registered: `search-tools` and `execute-tool`, which can invoke any of the 110+ tools dynamically.

### 3.2 Complete Tool Listing

#### Mail (Personal) — 21 tools

| Tool | Method | Graph Path | Scopes | Risk |
|---|---|---|---|---|
| `list-mail-messages` | GET | `/me/messages` | Mail.Read | Exfil |
| `list-mail-folders` | GET | `/me/mailFolders` | Mail.Read | |
| `list-mail-child-folders` | GET | `/me/mailFolders/{id}/childFolders` | Mail.Read | |
| `list-mail-folder-messages` | GET | `/me/mailFolders/{id}/messages` | Mail.Read | Exfil |
| `get-mail-message` | GET | `/me/messages/{id}` | Mail.Read | Exfil, PI-TR |
| `send-mail` | POST | `/me/sendMail` | Mail.Send | **Destructive** |
| `create-draft-email` | POST | `/me/messages` | Mail.ReadWrite | |
| `delete-mail-message` | DELETE | `/me/messages/{id}` | Mail.ReadWrite | **Destructive** |
| `move-mail-message` | POST | `/me/messages/{id}/move` | Mail.ReadWrite | |
| `update-mail-message` | PATCH | `/me/messages/{id}` | Mail.ReadWrite | |
| `add-mail-attachment` | POST | `/me/messages/{id}/attachments` | Mail.ReadWrite | |
| `list-mail-attachments` | GET | `/me/messages/{id}/attachments` | Mail.Read | Exfil |
| `get-mail-attachment` | GET | `/me/messages/{id}/attachments/{id}` | Mail.Read | Exfil |
| `delete-mail-attachment` | DELETE | `/me/messages/{id}/attachments/{id}` | Mail.ReadWrite | **Destructive** |
| `forward-mail-message` | POST | `/me/messages/{id}/forward` | Mail.Send | **Destructive** |
| `reply-mail-message` | POST | `/me/messages/{id}/reply` | Mail.Send | **Destructive** |
| `reply-all-mail-message` | POST | `/me/messages/{id}/replyAll` | Mail.Send | **Destructive** |
| `create-forward-draft` | POST | `/me/messages/{id}/createForward` | Mail.ReadWrite | |
| `create-reply-draft` | POST | `/me/messages/{id}/createReply` | Mail.ReadWrite | |
| `create-reply-all-draft` | POST | `/me/messages/{id}/createReplyAll` | Mail.ReadWrite | |
| `send-draft-message` | POST | `/me/messages/{id}/send` | Mail.Send | **Destructive** |

#### Mail (Org-mode — Shared Mailbox) — 4 tools

| Tool | Method | Graph Path | Work Scopes | Risk |
|---|---|---|---|---|
| `list-shared-mailbox-messages` | GET | `/users/{user-id}/messages` | Mail.Read.Shared | Exfil, Pivot |
| `list-shared-mailbox-folder-messages` | GET | `/users/{user-id}/mailFolders/{id}/messages` | Mail.Read.Shared | Exfil, Pivot |
| `get-shared-mailbox-message` | GET | `/users/{user-id}/messages/{id}` | Mail.Read.Shared | Exfil, PI-TR |
| `send-shared-mailbox-mail` | POST | `/users/{user-id}/sendMail` | Mail.Send.Shared | **Destructive**, Pivot |

#### Calendar — 15 tools

| Tool | Method | Scopes | Risk |
|---|---|---|---|
| `list-calendar-events` | GET | Calendars.Read | Exfil |
| `get-calendar-event` | GET | Calendars.Read | Exfil |
| `create-calendar-event` | POST | Calendars.ReadWrite | **Destructive** |
| `update-calendar-event` | PATCH | Calendars.ReadWrite | **Destructive** |
| `delete-calendar-event` | DELETE | Calendars.ReadWrite | **Destructive** |
| `list-specific-calendar-events` | GET | Calendars.Read | Exfil |
| `get-specific-calendar-event` | GET | Calendars.Read | Exfil |
| `create-specific-calendar-event` | POST | Calendars.ReadWrite | **Destructive** |
| `update-specific-calendar-event` | PATCH | Calendars.ReadWrite | **Destructive** |
| `delete-specific-calendar-event` | DELETE | Calendars.ReadWrite | **Destructive** |
| `get-calendar-view` | GET | Calendars.Read | Exfil |
| `get-specific-calendar-view` | GET | Calendars.Read | Exfil |
| `list-calendar-event-instances` | GET | Calendars.Read | |
| `list-calendars` | GET | Calendars.Read | |
| `find-meeting-times` | POST | Calendars.Read.Shared (org) | |

#### Files / OneDrive — 7 tools

| Tool | Method | Scopes | Risk |
|---|---|---|---|
| `list-drives` | GET | Files.Read | |
| `get-drive-root-item` | GET | Files.Read | |
| `get-root-folder` | GET | Files.Read | |
| `list-folder-files` | GET | Files.Read | Exfil |
| `download-onedrive-file-content` | GET | Files.Read | **Exfil** |
| `delete-onedrive-file` | DELETE | Files.ReadWrite | **Destructive** |
| `upload-file-content` | PUT | Files.ReadWrite | **Destructive** |

#### Excel — 5 tools

| Tool | Method | Scopes | Risk |
|---|---|---|---|
| `create-excel-chart` | POST | Files.ReadWrite | |
| `format-excel-range` | PATCH | Files.ReadWrite | |
| `sort-excel-range` | PATCH | Files.ReadWrite | |
| `get-excel-range` | GET | Files.Read | Exfil |
| `list-excel-worksheets` | GET | Files.Read | |

#### OneNote — 6 tools

| Tool | Method | Scopes | Risk |
|---|---|---|---|
| `list-onenote-notebooks` | GET | Notes.Read | |
| `list-onenote-notebook-sections` | GET | Notes.Read | |
| `list-onenote-section-pages` | GET | Notes.Read | |
| `get-onenote-page-content` | GET | Notes.Read | Exfil, PI-TR |
| `create-onenote-page` | POST | Notes.Create | |
| `create-onenote-section-page` | POST | Notes.Create | |

#### Tasks (To Do) — 6 tools

| Tool | Method | Scopes | Risk |
|---|---|---|---|
| `list-todo-task-lists` | GET | Tasks.Read | |
| `list-todo-tasks` | GET | Tasks.Read | |
| `get-todo-task` | GET | Tasks.Read | |
| `create-todo-task` | POST | Tasks.ReadWrite | |
| `update-todo-task` | PATCH | Tasks.ReadWrite | |
| `delete-todo-task` | DELETE | Tasks.ReadWrite | |

#### Planner — 7 tools

| Tool | Method | Scopes | Risk |
|---|---|---|---|
| `list-planner-tasks` | GET | Tasks.Read | |
| `get-planner-plan` | GET | Tasks.Read | |
| `list-plan-tasks` | GET | Tasks.Read | |
| `get-planner-task` | GET | Tasks.Read | |
| `create-planner-task` | POST | Tasks.ReadWrite | |
| `update-planner-task` | PATCH | Tasks.ReadWrite | |
| `update-planner-task-details` | PATCH | Tasks.ReadWrite | |

#### Contacts — 5 tools

| Tool | Method | Scopes | Risk |
|---|---|---|---|
| `list-outlook-contacts` | GET | Contacts.Read | Exfil |
| `get-outlook-contact` | GET | Contacts.Read | Exfil |
| `create-outlook-contact` | POST | Contacts.ReadWrite | |
| `update-outlook-contact` | PATCH | Contacts.ReadWrite | |
| `delete-outlook-contact` | DELETE | Contacts.ReadWrite | |

#### User — 1 tool (personal)

| Tool | Method | Scopes | Risk |
|---|---|---|---|
| `get-current-user` | GET | User.Read | |

#### Search — 1 tool (personal + org)

| Tool | Method | Scopes | Work Scopes | Risk |
|---|---|---|---|---|
| `search-query` | POST | Mail.Read, Calendars.Read, Files.Read.All, People.Read | Sites.Read.All, Chat.Read, ChannelMessage.Read.All | **Exfil** (cross-service) |

#### Teams / Chat (Org-mode) — 14 tools

| Tool | Method | Work Scopes | Risk |
|---|---|---|---|
| `list-chats` | GET | Chat.Read | Exfil |
| `get-chat` | GET | Chat.Read | |
| `list-chat-messages` | GET | ChatMessage.Read | Exfil, PI-TR |
| `get-chat-message` | GET | ChatMessage.Read | PI-TR |
| `send-chat-message` | POST | ChatMessage.Send | **Destructive** |
| `list-joined-teams` | GET | Team.ReadBasic.All | |
| `get-team` | GET | Team.ReadBasic.All | |
| `list-team-channels` | GET | Channel.ReadBasic.All | |
| `get-team-channel` | GET | Channel.ReadBasic.All | |
| `list-channel-messages` | GET | ChannelMessage.Read.All | Exfil, PI-TR |
| `get-channel-message` | GET | ChannelMessage.Read.All | PI-TR |
| `send-channel-message` | POST | ChannelMessage.Send | **Destructive** |
| `reply-to-channel-message` | POST | ChannelMessage.Send | **Destructive** |
| `list-team-members` | GET | TeamMember.Read.All | Exfil |

#### Chat Replies (Org-mode) — 2 tools

| Tool | Method | Work Scopes | Risk |
|---|---|---|---|
| `list-chat-message-replies` | GET | ChatMessage.Read | PI-TR |
| `reply-to-chat-message` | POST | ChatMessage.Send | **Destructive** |

#### SharePoint (Org-mode) — 12 tools

| Tool | Method | Work Scopes | Risk |
|---|---|---|---|
| `search-sharepoint-sites` | GET | Sites.Read.All | Exfil |
| `get-sharepoint-site` | GET | Sites.Read.All | |
| `list-sharepoint-site-drives` | GET | Sites.Read.All | |
| `get-sharepoint-site-drive-by-id` | GET | Sites.Read.All | |
| `list-sharepoint-site-items` | GET | Sites.Read.All | Exfil |
| `get-sharepoint-site-item` | GET | Sites.Read.All | Exfil |
| `list-sharepoint-site-lists` | GET | Sites.Read.All | |
| `get-sharepoint-site-list` | GET | Sites.Read.All | |
| `list-sharepoint-site-list-items` | GET | Sites.Read.All | Exfil |
| `get-sharepoint-site-list-item` | GET | Sites.Read.All | Exfil |
| `get-sharepoint-site-by-path` | GET | Sites.Read.All | |
| `get-sharepoint-sites-delta` | GET | Sites.Read.All | |

#### Groups (Org-mode) — 3 tools

| Tool | Method | Work Scopes | Risk |
|---|---|---|---|
| `list-group-conversations` | GET | Group.Read.All | Exfil |
| `list-group-threads` | GET | Group.Read.All | Exfil |
| `reply-to-group-thread` | POST | Group.ReadWrite.All | **Destructive** |

#### Users Directory (Org-mode) — 1 tool

| Tool | Method | Work Scopes | Risk |
|---|---|---|---|
| `list-users` | GET | User.Read.All | **Exfil** (full directory) |

### 3.3 High-Risk Tool Summary

**Destructive tools (can send messages, delete data, upload files):**
- `send-mail`, `forward-mail-message`, `reply-mail-message`, `reply-all-mail-message`, `send-draft-message`
- `send-shared-mailbox-mail` (org — impersonate shared mailbox)
- `send-chat-message`, `send-channel-message`, `reply-to-channel-message`, `reply-to-chat-message`
- `reply-to-group-thread`
- `delete-mail-message`, `delete-onedrive-file`, `delete-calendar-event`, `delete-specific-calendar-event`, `delete-todo-task`, `delete-outlook-contact`, `delete-mail-attachment`
- `upload-file-content`

**High exfiltration potential:**
- `list-users` — full organisational directory
- `search-query` — cross-service search (mail, calendar, files, people, sites, chat, channels)
- `download-onedrive-file-content` — file download
- `list-mail-messages` / `list-channel-messages` / `list-chat-messages` — bulk message access
- `list-outlook-contacts` — contact list

**Prompt injection vectors (PI-TR):**
- `get-mail-message`, `list-mail-messages` — email body content returned to LLM
- `get-shared-mailbox-message` — shared mailbox email content
- `list-chat-messages`, `get-chat-message`, `list-chat-message-replies` — Teams chat content
- `list-channel-messages`, `get-channel-message` — Teams channel content
- `get-onenote-page-content` — OneNote page HTML content

---

## 4. Authentication Pathways

### 4.1 MSAL Device Code Flow (Stdio mode, default)

**Source:** `src/auth.ts:391-427`

1. `AuthManager.acquireTokenByDeviceCode()` initiates device code flow
2. User visits `https://microsoft.com/devicelogin` and enters the code
3. MSAL exchanges the device code for an access token
4. Token cached via `saveTokenCache()` (keytar or file fallback)
5. Subsequent calls use `acquireTokenSilent()` for token refresh

**Scopes requested:** Built dynamically from `endpoints.json` by `buildScopesFromEndpoints()` (`src/auth.ts:108-165`). Includes all scopes for enabled tools, with hierarchy deduplication (e.g. `Mail.ReadWrite` subsumes `Mail.Read`).

### 4.2 Direct Token Injection (`MS365_MCP_OAUTH_TOKEN`)

**Source:** `src/auth.ts:195-197, 336-339`

- Environment variable `MS365_MCP_OAUTH_TOKEN` sets a raw access token
- **Bypasses MSAL entirely** — no device code flow, no token cache, no token refresh
- **No validation performed:** no audience check, no expiry check, no scope check, no issuer check
- Token returned as first priority in `getToken()` — takes precedence over cached MSAL tokens
- In HTTP mode, per-request Bearer tokens via `AsyncLocalStorage` take precedence

### 4.3 HTTP Bearer Token (HTTP mode)

**Source:** `src/lib/microsoft-auth.ts:9-36`, `src/server.ts:363-459`

1. Client sends `Authorization: Bearer <token>` header to `/mcp`
2. Middleware extracts token — **no server-side validation** (comment at line 23: "we don't validate the token here - we'll let the API calls fail if it's invalid")
3. Optional refresh token in `x-microsoft-refresh-token` custom header
4. Token stored in `AsyncLocalStorage` via `requestContext.run()` for request isolation
5. `GraphClient.makeRequest()` reads from `AsyncLocalStorage` first, then falls back to `AuthManager.getToken()`

### 4.4 OAuth Authorization Code Flow (HTTP mode)

**Source:** `src/server.ts:220-351`, `src/oauth-provider.ts`

1. Client redirected to `/authorize` → redirected to Microsoft OAuth
2. Authorization code returned to client's `redirect_uri`
3. Client exchanges code at `/token` endpoint
4. Server proxies the token exchange to Microsoft's token endpoint
5. `MicrosoftOAuthProvider.verifyAccessToken()` validates by calling Graph API `/me` endpoint (`src/oauth-provider.ts:22-48`)
6. **Calls `authManager.setOAuthToken(token)`** on verification — this sets the token globally on the shared AuthManager instance, not per-request (potential issue for concurrent users)

---

## 5. Token Storage & File I/O

### 5.1 Token Cache

**Source:** `src/auth.ts:210-242, 277-329`

| Storage Method | Location | Permissions | Priority |
|---|---|---|---|
| OS Credential Store (keytar) | macOS Keychain / Windows Credential Manager / Linux Secret Service | OS-managed | Primary |
| File fallback | `~/.token-cache.json` (or `MS365_MCP_TOKEN_CACHE_PATH`) | `0o600` | Secondary |

- Keytar is lazy-loaded and optional (`src/auth.ts:12-28`)
- If keytar import fails, silently falls back to file storage with info-level log
- File fallback parent directory created with `0o700` permissions (`src/auth.ts:79`)
- Default file path: `<project-root>/.token-cache.json` (adjacent to `dist/`, not in home directory)

### 5.2 Selected Account

| Storage Method | Location | Permissions |
|---|---|---|
| OS Credential Store (keytar) | Service: `ms-365-mcp-server`, Account: `selected-account` | OS-managed |
| File fallback | `~/.selected-account.json` (or `MS365_MCP_SELECTED_ACCOUNT_PATH`) | `0o600` |

### 5.3 Log Files

**Source:** `src/logger.ts`

| File | Content |
|---|---|
| `<project>/logs/error.log` | Error-level logs |
| `<project>/logs/mcp-server.log` | All-level logs |

**Security note:** Logs include request parameters (`src/graph-tools.ts:92`), Graph API URLs (`src/graph-client.ts:161`), and client registration request bodies (`src/server.ts:204`). Token values themselves are not directly logged, but client IDs and partial secrets are logged at startup (`src/server.ts:119-124`).

---

## 6. Built-in Azure AD App Registration

**Source:** `src/cloud-config.ts:49-52`

| Property | Value |
|---|---|
| **Global client ID** | `084a3e9f-a9f4-43f7-89f9-d229cf97853e` |
| **China client ID** | `f3e61a6e-bc26-4281-8588-2c7359a02141` |
| **Tenant** | `common` (multi-tenant — personal + work accounts) |
| **Controlled by** | Softeria |
| **App type** | Public client (no client secret by default) |

**Implications:**
- All default installations share this app registration
- Softeria controls the app registration in Azure AD/Entra
- If the app registration is modified (new redirect URIs, new permissions), revoked, or compromised, **all default installations are affected**
- This is architecturally analogous to the `gmail.gongrzhe.com` callback concern in the Gmail MCP server audit — a third-party trust anchor embedded in the default configuration
- Scopes granted to this app in Entra cannot be determined from code alone — requires dynamic testing (Phase 3)
- The `common` tenant means tokens are issued for any Microsoft account type (personal MSA or work/school AAD)

---

## 7. Dynamic Client Registration

**Source:** `src/server.ts:201-218`

- **Enabled by:** `--enable-dynamic-registration` flag
- **Endpoint:** `POST /register` — **explicitly unauthenticated** (no auth middleware applied; sits outside the `/mcp` route which has `microsoftBearerTokenAuthMiddleware`)
- **Purpose:** RFC 7591 Dynamic Client Registration for Open WebUI compatibility

**Behaviour:**
1. Accepts any JSON body without validation
2. Echoes back fields from the request: `redirect_uris`, `grant_types`, `response_types`, `token_endpoint_auth_method`, `client_name`
3. Generates client ID: `mcp-client-${Date.now()}` — **predictable, timestamp-based**
4. Logs the entire request body (`src/server.ts:204`)
5. Returns 201 with the registration response

**No validation performed on:**
- `redirect_uris` — any URIs accepted
- `client_name` — any string accepted (could contain LLM-influencing content)
- `grant_types` / `response_types` — echoed back without validation
- `token_endpoint_auth_method` — echoed back without enforcement
- No rate limiting on registration

---

## 8. Discovery Mode

**Source:** `src/graph-tools.ts:517-638`

- **Enabled by:** `--discovery` flag (experimental)
- Replaces the 110+ individual tools with 2 meta-tools:

### 8.1 `search-tools`
- Searches the tool registry by name, path, description, or category
- Returns up to 50 results
- Read-only, information-only

### 8.2 `execute-tool`
- Executes any tool by name with provided parameters
- Validates tool name exists in registry (`src/graph-tools.ts:619-620`)
- Respects `readOnly` and `orgMode` filters (applied when building registry at `src/graph-tools.ts:491-515`)
- `destructiveHint: true` and `openWorldHint: true` set in tool annotations

**Security implications:**
- LLM sees only the 2 meta-tool descriptions in its initial context window (not the 110 individual tool descriptions). The full tool registry with descriptions is only exposed on-demand via `search-tools` results. This changes the TDM attack surface — `llmTip` content in tool descriptions is not directly in the LLM system prompt but can be surfaced via search.
- LLM can dynamically discover and invoke tools not visible in its initial context window, enabling dynamic capability expansion.
- Tool name validation (`toolsRegistry.get(tool_name)`) prevents invocation of tools outside the registry. The registry is built once at startup from `api.endpoints` filtered by `readOnly` and `orgMode` — there is no mechanism to add tools to the registry at runtime, so this validation cannot be bypassed by manipulating the registry. However, the tool name is a simple string lookup and the parameter object is passed directly to `executeGraphTool` without further validation against the specific tool's schema.
- The `readOnly` filter is enforced at registry build time (tools excluded from the Map), not at execution time — a tool that passes registry validation will execute regardless of its HTTP method.

---

## 9. External Calls

### 9.1 Microsoft Identity Infrastructure

**Source:** `src/cloud-config.ts:32-43`

| Environment | Authority (OAuth) | Graph API |
|---|---|---|
| Global | `https://login.microsoftonline.com` | `https://graph.microsoft.com` |
| China (21Vianet) | `https://login.chinacloudapi.cn` | `https://microsoftgraph.chinacloudapi.cn` |

### 9.2 Azure Key Vault (Optional)

**Source:** `src/secrets.ts:53-92`

- Only contacted if `MS365_MCP_KEYVAULT_URL` environment variable is set
- Uses `@azure/identity` `DefaultAzureCredential` for authentication
- Retrieves `ms365-mcp-client-id`, `ms365-mcp-tenant-id`, `ms365-mcp-client-secret`, `ms365-mcp-cloud-type`

### 9.3 No Other External Domains

The server contacts **only** Microsoft infrastructure. No telemetry, no third-party analytics, no external callback domains.

---

## 10. Environment Variables

| Variable | Source File | Purpose | Default |
|---|---|---|---|
| `MS365_MCP_CLIENT_ID` | `secrets.ts:35` | Azure AD app client ID | `084a3e9f-...` (Softeria's app) |
| `MS365_MCP_CLIENT_SECRET` | `secrets.ts:37` | Client secret (confidential clients) | None |
| `MS365_MCP_TENANT_ID` | `secrets.ts:36` | Azure AD tenant ID | `common` |
| `MS365_MCP_CLOUD_TYPE` | `secrets.ts:33` | Cloud environment | `global` |
| `MS365_MCP_KEYVAULT_URL` | `secrets.ts:99` | Azure Key Vault URL | None |
| `MS365_MCP_OAUTH_TOKEN` | `auth.ts:195` | **Direct token injection** — bypasses MSAL | None |
| `MS365_MCP_TOKEN_CACHE_PATH` | `auth.ts:61` | Token cache file path | `<project>/.token-cache.json` |
| `MS365_MCP_SELECTED_ACCOUNT_PATH` | `auth.ts:70` | Selected account file path | `<project>/.selected-account.json` |
| `MS365_MCP_ORG_MODE` | `cli.ts:117` | Enable org mode | `false` |
| `MS365_MCP_FORCE_WORK_SCOPES` | `cli.ts:122` | Legacy org mode alias (deprecated) | `false` |
| `MS365_MCP_OUTPUT_FORMAT` | `cli.ts:132` | Output format | `json` |
| `MS365_MCP_CORS_ORIGIN` | `server.ts:139` | CORS origin header | `*` |
| `ENABLED_TOOLS` | `cli.ts:113` | Tool filter regex | None (all tools) |
| `READ_ONLY` | `cli.ts:109` | Read-only mode | `false` |
| `LOG_LEVEL` | `logger.ts:14` | Winston log level | `info` |
| `SILENT` | `logger.ts:38` | Suppress console output | `false` |

---

## 11. Preliminary Risk Notes

These observations will be investigated in depth during Phase 2 (Static Analysis) and Phase 3 (Dynamic Testing).

### Critical Observations

1. **Token injection without validation (TL, SE):** `MS365_MCP_OAUTH_TOKEN` accepts any token without audience, expiry, scope, or issuer validation. In a multi-server MCP environment, a malicious co-located server that can set environment variables could inject a crafted token granting access to a different tenant or with broader scopes.

2. **No server-side Bearer token validation in HTTP mode (TL):** The middleware at `src/lib/microsoft-auth.ts:9-36` extracts but does not validate the Bearer token. Any string is accepted and forwarded to Graph API. This means the server provides no additional access control layer.

3. **CORS `*` default in HTTP mode (II):** `Access-Control-Allow-Origin: *` allows any website to make cross-origin requests to the MCP endpoint. Combined with the lack of server-side token validation, this means any web page can call the MCP endpoint if it has a valid Bearer token.

4. **`MicrosoftOAuthProvider.verifyAccessToken()` calls `authManager.setOAuthToken()` globally** (`src/oauth-provider.ts:34`) — in HTTP mode with concurrent users, this could cause token cross-contamination as `setOAuthToken` modifies the shared AuthManager instance's `oauthToken` field, potentially leaking one user's token to another's request if timing aligns unfavorably with the AsyncLocalStorage mechanism.

5. **Dynamic client registration without validation (II, TDM):** The `/register` endpoint accepts arbitrary `client_name` (potential LLM prompt injection if the name is surfaced in OAuth discovery metadata or log output that reaches an LLM), arbitrary `redirect_uris` (no domain restrictions — could redirect auth codes to attacker-controlled endpoints), and predictable client IDs (`mcp-client-${Date.now()}`). When combined with `--enable-auth-tools`, a registered rogue client could initiate auth flows whose metadata may influence LLM tool selection.

### High Observations

6. **110 tools with 44 destructive operations — no confirmation logic (CD):** All destructive tools are callable silently with no user confirmation, approval workflow, or rate limiting. The LLM can send emails, delete files, post to Teams channels, and reply to group threads based purely on its interpretation of the conversation.

7. **Org-mode blast radius (SE, CD):** Enabling `--org-mode` adds 37 tools spanning shared mailboxes, Teams, SharePoint, and the full user directory. A single prompt injection in an email or Teams message could trigger `list-users` → `send-mail` to exfiltrate directory data, or `send-channel-message` to post to organisation-wide channels.

8. **Shared mailbox `user-id` parameter pivot potential (SE):** `list-shared-mailbox-messages` and `send-shared-mailbox-mail` accept a `user-id` path parameter. Access control relies solely on Graph API permissions — if `Mail.Read.Shared` or `Mail.Send.Shared` delegates are broadly granted, arbitrary mailbox access may be possible.

9. **`search-query` cross-service scope (SE, CD):** This tool requests scopes spanning mail, calendar, files, people, sites, chat, and channel messages. A single tool invocation can search across all of these services, making it a high-value exfiltration vector.

10. **Tool descriptions contain LLM-influencing content (TDM):** Multiple tools have `llmTip` fields that inject instructions into tool descriptions (e.g., "CRITICAL: Do not try to guess the email address of the recipients. Use the list-users tool to find the email address of the recipients."). While well-intentioned, this pattern demonstrates that tool descriptions directly influence LLM behaviour — a malicious tool description could exploit this channel.

### Medium Observations

11. **Parameter name sanitisation in `hack.ts` (II):** `src/generated/hack.ts:18` strips `$` and `_` from parameter names (`parameter.name.replace(/[$_]+/g, '')`). This is a compatibility workaround but could mask injection vectors if parameter names are used in path construction.

12. **`skipEncoding` parameter in endpoint config (II):** `get-excel-range` has `skipEncoding: ["address"]` (`endpoints.json:350`), meaning the `address` parameter is not URL-encoded before being interpolated into the Graph API path. This could enable path traversal or injection in the Graph API URL.

13. **Logs directory created without restrictive permissions:** `src/logger.ts:9-11` creates the logs directory without specifying permissions (defaults to umask), unlike the token cache directory which uses `0o700`.

14. **TOON output format:** The experimental `@toon-format/toon` encoder (`src/graph-client.ts:177-183`) produces output that the LLM must parse. If malicious content in Graph API responses exploits parsing ambiguities in TOON format differently than JSON, this could be a novel PI-TR vector.

15. **Pagination fetches up to 100 pages:** `src/graph-tools.ts:281` — the `fetchAllPages` parameter can trigger up to 100 sequential Graph API requests, potentially enabling data exfiltration of very large result sets.

---

## Appendix A: File Reference

| File | Lines | Purpose |
|---|---|---|
| `src/server.ts` | 494 | Main server — transport setup, HTTP endpoints |
| `src/cli.ts` | 143 | CLI argument parsing |
| `src/auth.ts` | 585 | AuthManager — MSAL, token cache, device code |
| `src/graph-tools.ts` | 639 | Tool registration, discovery mode, Graph execution |
| `src/graph-client.ts` | 305 | Graph API HTTP client |
| `src/secrets.ts` | 133 | Secrets management (env vars, Key Vault) |
| `src/cloud-config.ts` | 104 | Cloud endpoint configuration |
| `src/request-context.ts` | 13 | AsyncLocalStorage for per-request tokens |
| `src/logger.ts` | 44 | Winston logging configuration |
| `src/lib/microsoft-auth.ts` | 134 | Bearer token middleware, token exchange |
| `src/oauth-provider.ts` | 60 | MCP SDK OAuth provider wrapper |
| `src/auth-tools.ts` | 211 | Auth MCP tools (login, logout, etc.) |
| `src/tool-categories.ts` | 104 | Preset tool category definitions |
| `src/endpoints.json` | 704 | Tool endpoint definitions (110 tools) |
| `src/generated/hack.ts` | 50 | Parameter name sanitisation shim |
