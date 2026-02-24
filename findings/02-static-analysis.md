# Phase 2 — Static Analysis

**Target:** `@softeria/ms-365-mcp-server` v0.0.0-development (commit `812b427`)
**Date:** 2026-02-23
**Auditor:** Security audit — MSc research project

---

## 1. Authentication & Token Handling

### 1.1 MSAL Token Cache — Persistence & Permissions

**Files:** `src/auth.ts:210-301`

**Storage hierarchy:**

| Priority | Method | Location | Permissions |
|---|---|---|---|
| 1 | OS Credential Store (keytar) | macOS Keychain / Windows Credential Manager / Linux Secret Service | OS-managed ACLs |
| 2 | File fallback | `MS365_MCP_TOKEN_CACHE_PATH` or `<project-dir>/.token-cache.json` | `0o600` (file), `0o700` (parent dir) |

**Findings:**

1. **Keytar failure is silent (Informational).** When keytar import fails (`src/auth.ts:21-24`), the error is logged at `info` level — not `warn` or `error`. A user running in a CI environment or a Docker container would silently fall back to file storage without any prominent notification. The variable is set to `undefined as any` which works but is a type-safety concern.

2. **Default token cache path is project-relative, not user-relative (Low — TL).** `DEFAULT_TOKEN_CACHE_PATH` is `path.join(FALLBACK_DIR, '..', '.token-cache.json')` (`src/auth.ts:53`), which resolves to the package installation directory (adjacent to `dist/`), not to `~/.token-cache.json`. This means:
   - On a globally installed npm package, the token file lands in a system-wide npm directory
   - On a cloned repo, it lands in the project root (likely tracked by git if `.gitignore` doesn't exclude it)
   - The `.gitignore` **does not** list `.token-cache.json` or `.selected-account.json` — risk of accidental commit of cached MSAL tokens to version control

3. **File permissions are correctly set (Good).** `writeFileSync` with `{ mode: 0o600 }` at `src/auth.ts:288,297,315,324` and parent directory with `0o700` at `src/auth.ts:79`. This is correct on Unix systems. On Windows, Node.js `mode` parameter is largely ignored — but the Windows fallback is to use Credential Manager via keytar, so this is acceptable.

4. **Token cache contains full MSAL serialized state.** The `msalApp.getTokenCache().serialize()` call produces a JSON blob containing access tokens, refresh tokens, ID tokens, and account metadata. If the file fallback is used, all of this is on disk in a single file.

### 1.2 Token Leakage Fix in HTTP Mode (AsyncLocalStorage)

**Files:** `src/request-context.ts`, `src/graph-client.ts:52-56`, `src/server.ts:363-459`

**Background:** A prior release fixed a bug where "OAuth tokens leaked over to other users' requests" in HTTP mode. The fix uses `AsyncLocalStorage` to isolate per-request tokens.

**Current implementation analysis:**

```
Request flow (HTTP mode):
1. microsoftBearerTokenAuthMiddleware extracts Bearer token → req.microsoftAuth
2. server.ts:386/435 calls requestContext.run({accessToken, refreshToken}, handler)
3. handler creates new McpServer + StreamableHTTPServerTransport per request
4. GraphClient.makeRequest() calls getRequestTokens() first (AsyncLocalStorage)
5. Falls back to authManager.getToken() if no context tokens
```

**Assessment: The fix is architecturally sound but has a residual risk path.**

- **Per-request McpServer creation** (`src/server.ts:371,420`) prevents tool state leakage between requests
- **AsyncLocalStorage** correctly scopes tokens to the async execution context of each request
- **Token priority chain** in `makeRequest()` (`src/graph-client.ts:54-55`):
  ```typescript
  let accessToken = options.accessToken ?? contextTokens?.accessToken ?? (await this.authManager.getToken());
  ```
  This correctly prioritises: explicit options → AsyncLocalStorage context → AuthManager fallback

**Residual risk — `MicrosoftOAuthProvider.verifyAccessToken()` global token mutation (High — TL):**

At `src/oauth-provider.ts:34`:
```typescript
await authManager.setOAuthToken(token);
```

This sets `this.oauthToken = token` and `this.isOAuthMode = true` on the **shared** `AuthManager` instance. In HTTP mode with concurrent users:

1. User A's token verification calls `setOAuthToken(tokenA)` → sets `authManager.oauthToken = tokenA`
2. User B's request arrives before User A's request completes
3. User B's token verification calls `setOAuthToken(tokenB)` → overwrites `authManager.oauthToken = tokenB`
4. If any code path falls through to `authManager.getToken()` (the fallback in `makeRequest()`), it returns `tokenB` — which may be User B's token delivered to User A's request context

This is a **race condition in the OAuth provider flow**. The `AsyncLocalStorage` fix protects the `microsoftBearerTokenAuthMiddleware` path (Bearer tokens), but the `MicrosoftOAuthProvider` path (MCP SDK auth router at `/auth/*`) still mutates shared state.

**Severity:** High — only affects the MCP SDK auth router path, not the primary Bearer token path, but is a token cross-contamination vulnerability under concurrent load.

### 1.3 `MS365_MCP_OAUTH_TOKEN` Injection — No Validation (Critical — TL, SE)

**File:** `src/auth.ts:195-197, 336-339`

```typescript
// Constructor
const oauthTokenFromEnv = process.env.MS365_MCP_OAUTH_TOKEN;
this.oauthToken = oauthTokenFromEnv ?? null;
this.isOAuthMode = oauthTokenFromEnv != null;

// getToken()
if (this.isOAuthMode && this.oauthToken) {
  return this.oauthToken;
}
```

**No validation whatsoever is performed on this token:**
- No audience (`aud`) claim check — token could target any API, not just Microsoft Graph
- No expiry (`exp`) check — expired tokens are passed through to Graph API
- No issuer (`iss`) check — token could originate from any identity provider
- No scope check — token may have different scopes than what the server tools expect
- No signature verification — token is used as an opaque bearer string

**Attack scenario — Multi-server MCP token injection:**
In a multi-server MCP configuration (e.g., Claude Desktop with multiple servers configured in `claude_desktop_config.json`), environment variables may be shared or accessible across servers. A malicious or compromised co-located MCP server that can write to the environment (or to a shared `.env` file loaded by `dotenv/config` at `src/index.ts:3`) could:

1. Set `MS365_MCP_OAUTH_TOKEN` to an attacker-controlled token
2. The ms-365 server would use this token for all Graph API requests
3. If the attacker token has broader scopes (e.g., obtained via a separate app registration with application permissions), this effectively escalates privileges

**Impact:** Complete authentication bypass. Any string is accepted as a token and used directly for all API calls. The token takes **first priority** over MSAL-acquired tokens.

### 1.4 `MS365_MCP_CLIENT_SECRET` Handling

**Files:** `src/secrets.ts:37`, `src/server.ts:119-124`, `src/lib/microsoft-auth.ts:65-67,114-115`

**Logging exposure:**
- At `src/server.ts:121`: `CLIENT_SECRET: this.secrets?.clientSecret ? 'SET' : 'NOT SET'` — the secret value itself is not logged, only its presence. **Good practice.**
- At `src/server.ts:306-307`: `hasClientSecret: !!clientSecret` — again, presence only. **Good.**
- At `src/graph-client.ts:133-137`: Logs whether using public or confidential client, not the secret value. **Good.**

**Transmission:**
- The client secret is sent to Microsoft's token endpoint via `URLSearchParams` in `exchangeCodeForToken()` and `refreshAccessToken()` (`src/lib/microsoft-auth.ts:65-67,114-115`). This is correct — it should only go to Microsoft infrastructure.

**Unused secret scenario:**
- If `MS365_MCP_CLIENT_SECRET` is set but the flow is public client (device code), the secret is loaded into `AppSecrets` but never used by the device code flow (MSAL `PublicClientApplication` doesn't accept a client secret). No harm, but the secret sits in memory unnecessarily.

**Assessment:** Client secret handling is satisfactory. No leakage found.

### 1.5 Token Scope — Global vs. Per-Tool Enforcement

**File:** `src/auth.ts:108-165`

**How scopes are built:**
`buildScopesFromEndpoints()` iterates all enabled endpoints and collects their `scopes` (and `workScopes` if org-mode). The union of all scopes is requested during the device code flow.

**Critical finding — No per-tool scope enforcement (High — SE):**
- All tools share a **single token** with the **union of all scopes** for all enabled tools
- There is no check at tool execution time that the current token has the specific scope required by that tool
- The `scopes` field in `endpoints.json` is used **only** for building the initial token request — it is never checked at runtime
- This means: if the user has `Mail.ReadWrite` + `Files.ReadWrite` + `Calendars.ReadWrite` etc. in a single token, any tool can use any scope the token has, regardless of which scopes that specific tool was designed to need

**Scope aggregation with hierarchy deduplication:**
```typescript
const SCOPE_HIERARCHY: ScopeHierarchy = {
  'Mail.ReadWrite': ['Mail.Read'],
  'Calendars.ReadWrite': ['Calendars.Read'],
  'Files.ReadWrite': ['Files.Read'],
  'Tasks.ReadWrite': ['Tasks.Read'],
  'Contacts.ReadWrite': ['Contacts.Read'],
};
```
When both ReadWrite and Read scopes are in the set, Read is removed (the higher scope subsumes it). This is correct behaviour but means that if any write tool is enabled, the read-only tools of the same category get ReadWrite access implicitly.

**`readOnly` mode does not reduce scopes:**
Setting `--read-only` filters out write tools at registration time (`src/graph-tools.ts:400-404`) but `buildScopesFromEndpoints()` is called before tool registration and does **not** receive the `readOnly` flag. The token still requests ReadWrite scopes even in read-only mode. The mitigation is that write endpoints are not registered, but the token itself would permit writes if used directly.

---

## 2. Input Validation

### 2.1 Path Parameter Injection

**File:** `src/graph-tools.ts:139-148`

Path parameters are interpolated into Graph API URL paths:

```typescript
case 'Path': {
  const shouldSkipEncoding = config?.skipEncoding?.includes(paramName) ?? false;
  const encodedValue = shouldSkipEncoding
    ? (paramValue as string)
    : encodeURIComponent(paramValue as string);
  path = path
    .replace(`{${paramName}}`, encodedValue)
    .replace(`:${paramName}`, encodedValue);
  break;
}
```

**Finding — Parameters are URL-encoded by default (Good):** `encodeURIComponent()` prevents path traversal in the general case (e.g., `../` in a message ID would be encoded to `..%2F`).

**Exception — `skipEncoding` for Excel `address` parameter (Medium — II):**

`endpoints.json:350`:
```json
"skipEncoding": ["address"]
```

The `get-excel-range` tool's path pattern is:
```
/drives/{drive-id}/items/{driveItem-id}/workbook/worksheets/{workbookWorksheet-id}/range(address='{address}')
```

The `address` parameter (e.g., `A1:B5`) is **not URL-encoded** before interpolation. This is intentional (Excel range addresses use characters like `:` and `!` that would break if encoded), but it means:

- An LLM-supplied `address` value like `A1')/malicious-path?` would be interpolated directly into the URL path
- The Graph API URL would become: `.../range(address='A1')/malicious-path?')`
- This could potentially traverse the Graph API path structure

**Mitigation:** The Microsoft Graph API itself likely validates and rejects malformed paths, but the server provides no server-side validation of the `address` parameter format before sending it.

### 2.2 Query Parameter Construction

**File:** `src/graph-tools.ts:212-216`

```typescript
const queryString = Object.entries(queryParams)
  .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
  .join('&');
path = `${path}${path.includes('?') ? '&' : '?'}${queryString}`;
```

**Assessment:** Both keys and values are `encodeURIComponent()`-encoded. This is correct and prevents query string injection. **No vulnerability.**

### 2.3 OData Query Parameters — `$filter`, `$search`, `$expand`

OData parameters (`$filter`, `$search`, `$expand`, `$orderby`, `$select`, `$top`, `$skip`, `$count`, `$format`) are treated as Query parameters and URL-encoded. The values are **not validated against any schema** — they are passed as-is to the Graph API.

**Finding — OData injection potential (Low — II):**
An LLM could be prompted (via email/Teams content injection) to construct a `$filter` or `$search` value that retrieves data beyond the user's intent. For example:
- `$filter=from/emailAddress/address eq 'ceo@company.com'` — targeting specific users' mail
- `$search="confidential"` — searching across mail for sensitive keywords

This is not a traditional injection vulnerability (the Graph API handles its own authorisation), but in the confused deputy context, the LLM can be manipulated into constructing queries that the user did not intend.

### 2.4 Body Parameter Handling

**File:** `src/graph-tools.ts:158-177`

Body parameters are parsed via Zod schema if available:
```typescript
if (paramDef.schema) {
  const parseResult = paramDef.schema.safeParse(paramValue);
  if (!parseResult.success) {
    const wrapped = { [paramName]: paramValue };
    const wrappedResult = paramDef.schema.safeParse(wrapped);
    if (wrappedResult.success) {
      body = wrapped;
    } else {
      body = paramValue; // Falls through without validation
    }
  }
}
```

**Finding — Schema validation failure is non-blocking (Medium — II):**
If the Zod schema validation fails for both the raw value and the wrapped value, the raw value is still passed through as the body (`body = paramValue`). This means malformed or malicious body content reaches the Graph API even when schema validation is available. This is a permissive fail-open behaviour.

### 2.5 `user-id` Parameter — Shared Mailbox Pivot

**File:** `endpoints.json:42-67`

The shared mailbox tools use `{user-id}` as a path parameter:
- `list-shared-mailbox-messages`: `/users/{user-id}/messages`
- `send-shared-mailbox-mail`: `/users/{user-id}/sendMail`
- `list-shared-mailbox-folder-messages`: `/users/{user-id}/mailFolders/{mailFolder-id}/messages`
- `get-shared-mailbox-message`: `/users/{user-id}/messages/{message-id}`

**No server-side validation of `user-id`:**
- The parameter is a standard Path parameter — any string is accepted
- It is `encodeURIComponent()`-encoded (preventing path traversal) but not validated against an allowlist of shared mailboxes
- Access control relies entirely on the Graph API checking `Mail.Read.Shared` / `Mail.Send.Shared` delegated permissions
- If the authenticated user has been granted delegate access to any mailbox (including non-shared personal mailboxes via admin configuration), the server will happily proxy the request

**Finding (Medium — SE):** The server provides no additional access boundary beyond what the Graph API token permits. In org-mode with broad `Mail.Read.Shared` delegation, an attacker who controls the LLM input (via prompt injection) could enumerate users via `list-users` and then access their mailboxes via `list-shared-mailbox-messages` with arbitrary `user-id` values.

### 2.6 Free-Form Content Parameters

Email body (`send-mail`), Teams message content (`send-chat-message`, `send-channel-message`), OneNote page content (`create-onenote-page`, `create-onenote-section-page`) — all accept free-form content.

**No server-side sanitisation:**
- Email body content is passed directly as JSON body to Graph API's `sendMail` endpoint
- OneNote page content is sent with `Content-Type: text/html` (`endpoints.json:388,395`) — raw HTML
- Teams messages are passed as-is to the channel/chat message creation endpoint

**Finding (Informational):** This is expected behaviour — the server is a proxy to Graph API. Content sanitisation is the responsibility of the Graph API and the consuming clients (Outlook, Teams). However, in the MCP context, this means a prompt injection attack can cause the LLM to craft arbitrary email content (including phishing content, malicious links, etc.) with no server-side guardrails.

### 2.7 `timezone` Header Injection

**File:** `src/graph-tools.ts:192-193`

```typescript
headers['Prefer'] = `outlook.timezone="${params.timezone}"`;
```

The `timezone` parameter is string-interpolated directly into the `Prefer` header value without validation.

**Finding (Low — II):** A crafted timezone value containing `"` followed by additional header directives could potentially inject content into the Prefer header. However, the Node.js `fetch` API and Graph API are likely to reject malformed Prefer header values. Low severity but demonstrates the pattern of direct interpolation without validation.

### 2.8 Parameter Name Sanitisation in `hack.ts`

**File:** `src/generated/hack.ts:18`

```typescript
parameter.name = parameter.name.replace(/[$_]+/g, '');
```

This strips `$` and `_` from parameter names for MCP client compatibility (some clients don't support `$` in parameter names).

**Finding (Low — II):** This is a one-way transformation — the original parameter name is lost. The OData parameter restoration logic in `graph-tools.ts:117-131` attempts to re-add `$` for known OData parameters, but this relies on a hardcoded list. If a non-OData parameter originally had `$` or `_`, the mapping would fail silently. No exploitable vulnerability identified, but the approach is fragile.

---

## 3. Tool Descriptions as Attack Surface

### 3.1 LLM Tips — Injected Instructions in Tool Descriptions

**File:** `src/graph-tools.ts:461-463`, `endpoints.json` (various)

```typescript
if (endpointConfig?.llmTip) {
  toolDescription += `\n\n💡 TIP: ${endpointConfig.llmTip}`;
}
```

**Tool descriptions with `llmTip` content:**

| Tool | llmTip Content | Risk Assessment |
|---|---|---|
| `send-mail` | "CRITICAL: Do not try to guess the email address of the recipients. Use the list-users tool to find the email address of the recipients." | **TDM — Cross-tool invocation directive.** Instructs the LLM to call `list-users`, exposing the user directory as a prerequisite for sending mail. |
| `send-shared-mailbox-mail` | Same as `send-mail` | Same risk |
| `create-calendar-event` | Same as `send-mail` | Same risk |
| `update-calendar-event` | Same as `send-mail` | Same risk |
| `create-specific-calendar-event` | Same as `send-mail` | Same risk |
| `update-specific-calendar-event` | Same as `send-mail` | Same risk |
| `list-mail-messages` | Extensive KQL search syntax instructions | Informational — teaches LLM how to construct powerful search queries |
| `list-users` | "CRITICAL: This request requires the ConsistencyLevel header set to eventual..." + KQL search syntax | Informational |
| `forward-mail-message` | "Forward an email preserving full HTML formatting and attachments..." | Informational |
| `reply-mail-message` | "Reply to an email preserving full HTML formatting..." | Informational |
| Various calendar tools | CalendarView usage instructions, timezone, recurring events | Informational |

**Finding — Tool Description Manipulation (Medium — TDM):**

The `send-mail` tool's `llmTip` says: *"CRITICAL: Do not try to guess the email address of the recipients. Use the list-users tool to find the email address of the recipients."*

While well-intentioned (preventing the LLM from hallucinating email addresses), this demonstrates that **tool descriptions directly instruct the LLM to invoke other tools**. This establishes a pattern:

1. Any tool description can contain instructions that cause the LLM to invoke other tools
2. The `CRITICAL:` prefix is used to give the instruction high priority in the LLM's processing
3. In a discovery mode scenario, a crafted `search-tools` result containing a malicious tool description could inject cross-tool invocation instructions

This is not an active exploit in the current codebase (the descriptions are controlled by the server operator), but it establishes that the TDM attack vector is architecturally viable: if an attacker could modify `endpoints.json` (e.g., via supply chain attack on the npm package, or by modifying the generated files in a local installation), they could inject instructions that cause the LLM to take arbitrary actions.

### 3.2 Tool Count and Confused Deputy Surface

With 110 tools registered simultaneously (or 116 with auth tools in stdio mode), the LLM context window contains a large volume of tool descriptions. Each description potentially influences LLM behaviour.

**Finding — Large tool surface amplifies confused deputy risk (High — CD):**
- 44 destructive tools are callable with **no confirmation logic**, approval workflow, or rate limiting
- The MCP server sets `destructiveHint: true` for write operations (`src/graph-tools.ts:473`) — this is an MCP annotation that clients can use to prompt for confirmation, but it is advisory only
- No tool requires a "confirm" parameter or two-step invocation pattern
- A single prompt injection in an email body could chain: `list-mail-messages` → `forward-mail-message` (to attacker address) with no server-side barrier

---

## 4. Transport Mode Security (HTTP)

### 4.1 Bearer Token Middleware — No Server-Side Validation

**File:** `src/lib/microsoft-auth.ts:9-36`

```typescript
// For Microsoft Graph, we don't validate the token here - we'll let the API calls fail if it's invalid
const accessToken = authHeader.substring(7);
```

**Finding (High — TL):**
- Any string after `Bearer ` is accepted
- No JWT signature verification
- No audience claim check
- No issuer check
- No expiry check
- The token is passed directly to Graph API requests

This is a deliberate design choice (documented in the comment) — the server acts as a transparent proxy. However, it means:
- The server cannot distinguish between legitimate and stolen tokens
- There is no additional security layer between the MCP client and Graph API
- If the HTTP endpoint is exposed (which it is, on all interfaces by default), any party with a valid Microsoft token can access the full tool suite

### 4.2 CORS — Wildcard Default

**File:** `src/server.ts:139`

```typescript
const corsOrigin = process.env.MS365_MCP_CORS_ORIGIN || '*';
```

**Finding (High — II):**
- `Access-Control-Allow-Origin: *` is the default
- Combined with Bearer token acceptance, any web page can make cross-origin requests to the MCP endpoint
- If a user has the MCP server running locally and visits a malicious website, that website could call `http://localhost:3000/mcp` with a Bearer token if it can obtain one (e.g., from a browser cookie or local storage)
- CORS headers also allow `Authorization` header (line 145)

### 4.3 `trust proxy` Enabled

**File:** `src/server.ts:134`

```typescript
app.set('trust proxy', true);
```

**Finding (Low):** With `trust proxy` set to `true`, Express trusts `X-Forwarded-For`, `X-Forwarded-Proto`, and similar headers from any source. If the server is deployed without a reverse proxy, an attacker can spoof client IP addresses and protocol information.

### 4.4 Dynamic Client Registration — Unvalidated

**File:** `src/server.ts:201-218`

**Previously documented in Phase 1.** Key static analysis additions:

1. **No rate limiting:** The `/register` endpoint has no rate limiting — an attacker could register thousands of clients to exhaust resources or pollute logs
2. **`client_name` injection:** The `client_name` field is echoed back without sanitisation. If this name is later displayed in an OAuth consent screen or logged in a way that reaches an LLM, it could contain prompt injection payloads
3. **Request body logged in full:** `logger.info('Client registration request', { body })` at `src/server.ts:204` — the entire registration body is logged, including potentially malicious content
4. **No PKCE enforcement:** Registered clients are not required to use PKCE (`code_challenge_methods_supported` includes `S256` but isn't enforced)
5. **`redirect_uris` are not validated:** Any URI is accepted — could redirect to `file://`, `javascript:`, or attacker-controlled domains

### 4.5 Health Check Endpoint — Information Disclosure

**File:** `src/server.ts:462-464`

```typescript
app.get('/', (req, res) => {
  res.send('Microsoft 365 MCP Server is running');
});
```

**Finding (Informational):** The health check endpoint identifies the server type without authentication. Minor information disclosure.

---

## 5. Confused Deputy Potential

### 5.1 Destructive Tools — No Confirmation Logic

**All 44 write/delete tools** are registered with the same pattern:
```typescript
server.tool(name, description, paramSchema, annotations, async (params) => executeGraphTool(...))
```

No tool implements:
- Confirmation parameter (e.g., `confirm: true`)
- Two-step invocation (preview → confirm → execute)
- Rate limiting
- Audit logging of destructive operations (only standard info-level logging)
- User notification mechanism

**Finding (High — CD):** The MCP server relies entirely on the LLM client (e.g., Claude Desktop, Cursor) to implement tool approval UIs. If the client auto-approves tool calls (as some configurations allow), or if the LLM is manipulated by prompt injection, destructive operations execute immediately.

### 5.2 Org-Mode Blast Radius

In org-mode, the following attack chain is possible via a single prompt injection (e.g., in an email body):

1. `list-users` → enumerate all users in the organisation (User.Read.All)
2. `list-shared-mailbox-messages` with target `user-id` → read another user's mailbox
3. `send-mail` / `send-shared-mailbox-mail` → exfiltrate data to external address
4. `send-channel-message` → post to organisation-wide Teams channels
5. `search-query` → cross-service search across mail, files, chat, channels

**Finding (High — CD, SE):** The combination of `list-users` (enumeration) + `send-mail` (exfiltration) + `search-query` (cross-service data access) creates a high-severity confused deputy chain. A single prompt injection in any content that reaches the LLM (email body, Teams message, OneNote page) could trigger this full chain.

### 5.3 `search-query` — Cross-Service Scope

**File:** `endpoints.json:682-684`

```json
"scopes": ["Mail.Read", "Calendars.Read", "Files.Read.All", "People.Read"],
"workScopes": ["Sites.Read.All", "Chat.Read", "ChannelMessage.Read.All"]
```

**Finding (Medium — SE):** `search-query` is a single tool that can search across 7+ services. In org-mode, the token has `Sites.Read.All`, `Chat.Read`, `ChannelMessage.Read.All` — a single `search-query` invocation can exfiltrate data from SharePoint sites, Teams chats, and channel messages simultaneously. This represents a significant scope aggregation risk.

### 5.4 Pagination — 100-Page Bulk Exfiltration

**File:** `src/graph-tools.ts:273-325`

```typescript
while (nextLink && pageCount < 100) { ... }
```

**Finding (Medium — CD):** The `fetchAllPages` parameter allows up to 100 sequential Graph API page fetches. Default Graph API page sizes are typically 10-50 items, so this could return up to 5,000+ items in a single tool call. For mail or chat messages, this represents a significant bulk exfiltration capability that an attacker could trigger via prompt injection.

---

## 6. Discovery Mode Analysis

### 6.1 Parameter Bypass in `execute-tool`

**File:** `src/graph-tools.ts:618-635`

```typescript
async ({ tool_name, parameters = {} }) => {
  const toolData = toolsRegistry.get(tool_name);
  if (!toolData) { /* error */ }
  return executeGraphTool(toolData.tool, toolData.config, graphClient, parameters);
}
```

**Finding (Medium — II):** The `parameters` parameter is typed as `z.record(z.any())` — any key-value pairs are accepted. These are passed directly to `executeGraphTool()` without validation against the specific tool's parameter schema. While `executeGraphTool()` does look up parameter definitions and route them accordingly, extra parameters that don't match any `paramDef` are silently ignored (except `body`, which is a catch-all at line 184-187).

This means: in discovery mode, an attacker could include a `body` parameter for any tool, even those that don't normally accept one. The body would be set via the catch-all path and sent in the Graph API request. For GET requests, the body is not sent (`if (options.method !== 'GET' && body)` at line 232), but for POST/PATCH/DELETE tools, arbitrary body content could be injected.

### 6.2 `readOnly` Enforcement — Build-Time Only

**File:** `src/graph-tools.ts:507-509`

```typescript
if (readOnly && tool.method.toUpperCase() !== 'GET') {
  continue;  // Not added to registry
}
```

**Finding (Low):** Read-only mode excludes write tools from the registry map at build time. Since `execute-tool` validates against the registry (`toolsRegistry.get(tool_name)`), a write tool cannot be invoked in read-only mode. This is correct — the enforcement is at the registry level, not at execution time, but since the registry is immutable after construction, this is secure.

---

## 7. TOON Output Format

**File:** `src/graph-client.ts:176-186`

```typescript
private serializeData(data: unknown, outputFormat: 'json' | 'toon', pretty = false): string {
  if (outputFormat === 'toon') {
    try {
      return toonEncode(data);
    } catch (error) {
      logger.warn(`Failed to encode as TOON, falling back to JSON: ${error}`);
      return JSON.stringify(data, null, pretty ? 2 : undefined);
    }
  }
}
```

**Finding (Low — PI-TR):** TOON (Token-Oriented Object Notation) is an experimental format designed for LLM consumption. If the TOON encoder produces output with structural ambiguities that the LLM interprets differently from the intended data structure, malicious content in Graph API responses (e.g., email bodies, file names) could exploit these parsing ambiguities to inject instructions.

**Assessment:** Without a detailed analysis of the `@toon-format/toon` encoder's escaping rules, this remains a theoretical risk. The JSON fallback on TOON encoding failure (`catch` block) is a good safety measure. This should be tested dynamically in Phase 3.

---

## 8. Dependency Audit

### 8.1 `npm audit` Results

| Package | Severity | Issue | Fix Available |
|---|---|---|---|
| `@isaacs/brace-expansion` 5.0.0 | High | Uncontrolled Resource Consumption | Yes |
| `ajv` <6.14.0 / >=7.0.0-alpha.0 <8.18.0 | Moderate | ReDoS with `$data` option | Yes |
| `fast-xml-parser` 4.1.3-5.3.5 | **Critical** | DoS via entity expansion in DOCTYPE; regex injection in entity names | Yes |
| `hono` <4.11.10 | Moderate | Timing comparison in basicAuth/bearerAuth | Yes |
| `minimatch` <10.2.1 | High | ReDoS via repeated wildcards | **No fix (eslint dependency chain)** |
| `qs` 6.7.0-6.14.1 | Moderate | arrayLimit bypass DoS | Yes |

### 8.2 Direct Dependency Analysis

| Dependency | Pinning | Current | Latest (2026-02) | Risk |
|---|---|---|---|---|
| `@azure/msal-node` | `^3.8.0` | Semver range | — | OAuth/MSAL — critical dependency |
| `@modelcontextprotocol/sdk` | `^1.25.0` | Semver range | — | MCP protocol — critical dependency |
| `express` | `^5.2.1` | Express 5 (recently released) | — | HTTP transport |
| `@toon-format/toon` | `^0.8.0` | Experimental/pre-1.0 | — | Output encoding — pre-stable API |
| `keytar` | `^7.9.0` | Optional | — | Native addon — OS credential store |
| `dotenv` | `^17.0.1` | Semver range | — | Loads `.env` files |
| `zod` | `^3.24.2` | Semver range | — | Schema validation |

**Findings:**

1. **All runtime dependencies use caret (`^`) semver ranges (Medium):** This means `npm install` will pull the latest minor/patch version within the major version. For security-critical packages (`@azure/msal-node`, `express`, `@modelcontextprotocol/sdk`), unexpected minor version changes could introduce vulnerabilities or behavioural changes. Consider pinning exact versions for security-critical dependencies.

2. **`@toon-format/toon` is pre-1.0 (Low):** Semver conventions for pre-1.0 packages allow breaking changes in minor versions. The `^0.8.0` range could pull `0.9.0` with breaking encoding changes.

3. **`fast-xml-parser` critical vulnerability:** This is a transitive dependency (via `openapi-sampler` in devDependencies). It affects the build/generation toolchain, not the runtime server. **No runtime risk**, but the build pipeline is vulnerable to XML bomb attacks if processing untrusted OpenAPI specs.

4. **`keytar` is a native addon:** It requires node-gyp and platform-specific build tools. Failure to build/load is handled gracefully (file fallback), but the native dependency is a supply chain risk vector.

5. **No `package-lock.json` integrity checks enforced:** The standard npm lockfile is present, but there's no `npm ci`-only enforcement in CI scripts.

---

## 9. Logging Security

### 9.1 Sensitive Data in Logs

| Location | What's Logged | Risk |
|---|---|---|
| `src/graph-tools.ts:92` | `JSON.stringify(params)` — all tool parameters | May contain email content, message bodies, file content |
| `src/graph-tools.ts:269` | Full Graph API URL | Contains path parameters (message IDs, user IDs) |
| `src/graph-client.ts:161` | `[GRAPH CLIENT] Final URL being sent to Microsoft: ${url}` | Full URL with path parameters |
| `src/server.ts:204` | `Client registration request: ${body}` | Full registration body |
| `src/auth.ts:187` | `And scopes are ${scopes.join(', ')}` | All requested scopes |
| `src/auth.ts:407-409` | Requested and granted scopes | Scope information |
| `src/server.ts:300-307` | Token endpoint parameters (with redaction) | `redirect_uri`, presence of code/verifier |

**Finding (Medium — TL):**
- Tool parameters are logged in full at info level — this includes email body content, Teams message text, file content being uploaded, etc.
- Logs directory (`src/logger.ts:9-11`) is created with default `umask` permissions — **unlike** the token cache directory which uses `0o700`
- Log files persist across server restarts and are not rotated by default (Winston file transport without `maxsize` or `maxFiles`)
- An attacker with read access to the logs directory could extract sensitive data from tool invocations

### 9.2 Token Values Not Directly Logged (Good)

Access tokens are not logged directly. The Bearer token value, MSAL tokens, and OAuth tokens are handled without string interpolation into log messages. This is good practice.

---

## 10. Summary of Findings

### Critical

| # | Finding | Class | File:Line |
|---|---|---|---|
| SA-01 | `MS365_MCP_OAUTH_TOKEN` accepts any token without validation (audience, expiry, scope, issuer) | TL, SE | `src/auth.ts:195-197,336-339` |

### High

| # | Finding | Class | File:Line |
|---|---|---|---|
| SA-02 | `MicrosoftOAuthProvider.verifyAccessToken()` mutates shared AuthManager state — token cross-contamination in concurrent HTTP requests via MCP SDK auth path | TL | `src/oauth-provider.ts:34` |
| SA-03 | No per-tool scope enforcement — all tools share a single token with union of all scopes | SE | `src/auth.ts:108-165`, `src/graph-tools.ts:86-368` |
| SA-04 | Bearer token middleware performs no server-side validation | TL | `src/lib/microsoft-auth.ts:9-36` |
| SA-05 | CORS defaults to `Access-Control-Allow-Origin: *` in HTTP mode | II | `src/server.ts:139` |
| SA-06 | 44 destructive tools callable with no confirmation logic — confused deputy via prompt injection | CD | `src/graph-tools.ts:466-477` |
| SA-07 | Org-mode enables enumeration (`list-users`) + exfiltration (`send-mail`, `search-query`) chain | CD, SE | `endpoints.json:69-73,35-39,680-684` |

### Medium

| # | Finding | Class | File:Line |
|---|---|---|---|
| SA-08 | `skipEncoding` for Excel `address` parameter allows unencoded path interpolation | II | `endpoints.json:350`, `src/graph-tools.ts:141-143` |
| SA-09 | Body parameter schema validation failure is non-blocking — malformed bodies pass through | II | `src/graph-tools.ts:158-177` |
| SA-10 | `user-id` in shared mailbox tools accepts any value — pivot to arbitrary mailboxes | SE | `endpoints.json:42-67` |
| SA-11 | `search-query` aggregates scopes across 7+ services in a single tool | SE | `endpoints.json:682-684` |
| SA-12 | `fetchAllPages` allows up to 100 sequential pages — bulk exfiltration | CD | `src/graph-tools.ts:273-325` |
| SA-13 | Discovery mode `execute-tool` passes parameters without per-tool schema validation | II | `src/graph-tools.ts:618-635` |
| SA-14 | Tool parameters logged in full (including email bodies, message content) | TL | `src/graph-tools.ts:92` |
| SA-15 | Logs directory created without restrictive permissions | TL | `src/logger.ts:9-11` |
| SA-16 | Dynamic client registration accepts arbitrary `redirect_uris` and `client_name` | II, TDM | `src/server.ts:201-218` |
| SA-17 | Tool descriptions contain cross-tool invocation directives (`llmTip`) establishing TDM pattern | TDM | `endpoints.json:39,66,190,197,226,233` |

### Low

| # | Finding | Class | File:Line |
|---|---|---|---|
| SA-18 | Default token cache path is project-relative — risk of git commit | TL | `src/auth.ts:53` |
| SA-19 | `trust proxy` enabled without reverse proxy verification | II | `src/server.ts:134` |
| SA-20 | `timezone` parameter interpolated into Prefer header without validation | II | `src/graph-tools.ts:192-193` |
| SA-21 | Parameter name stripping in `hack.ts` is a fragile one-way transformation | II | `src/generated/hack.ts:18` |
| SA-22 | TOON output format may have parsing ambiguities exploitable for PI-TR | PI-TR | `src/graph-client.ts:176-186` |
| SA-23 | `readOnly` mode does not reduce requested token scopes | SE | `src/auth.ts:108-165`, `src/index.ts:19` |

### Informational

| # | Finding | File:Line |
|---|---|---|
| SA-24 | Keytar failure logged at info level, not warn | `src/auth.ts:22` |
| SA-25 | Health check endpoint identifies server type | `src/server.ts:462-464` |
| SA-26 | `fast-xml-parser` critical vuln in devDependencies (build-time only) | `package.json` (transitive) |
| SA-27 | All runtime deps use caret semver ranges | `package.json:36-44` |
| SA-28 | Free-form content parameters (email body, Teams messages) unsanitised | Various |
| SA-29 | Client secret handling is satisfactory — no leakage found | `src/secrets.ts`, `src/server.ts`, `src/lib/microsoft-auth.ts` |

---

## Appendix A: Scope Inventory

**Full scope set requested in default personal mode:**

```
User.Read, Mail.ReadWrite, Mail.Send, Calendars.ReadWrite, Files.ReadWrite,
Tasks.ReadWrite, Contacts.ReadWrite, Notes.Read, Notes.Create, People.Read,
Files.Read.All
```

**Additional scopes in org-mode:**

```
Mail.Read.Shared, Mail.Send.Shared, User.Read.All, Chat.Read,
ChatMessage.Read, ChatMessage.Send, Team.ReadBasic.All,
Channel.ReadBasic.All, ChannelMessage.Read.All, ChannelMessage.Send,
TeamMember.Read.All, Sites.Read.All, Group.Read.All, Group.ReadWrite.All,
Calendars.Read.Shared
```

**Total unique scopes (org-mode):** ~25 delegated permissions

## Appendix B: Sensitive Code Locations for Annotated Source

| File | Lines | Annotation |
|---|---|---|
| `src/auth.ts` | 195-197 | Token injection — no validation |
| `src/auth.ts` | 336-339 | Token returned without checks |
| `src/auth.ts` | 53 | Project-relative token cache path |
| `src/oauth-provider.ts` | 34 | Global token mutation — race condition |
| `src/lib/microsoft-auth.ts` | 21-23 | Bearer token extraction — no validation |
| `src/graph-tools.ts` | 92 | Full parameter logging |
| `src/graph-tools.ts` | 141-143 | skipEncoding bypass |
| `src/graph-tools.ts` | 158-177 | Schema validation fail-open |
| `src/graph-tools.ts` | 273-325 | 100-page pagination |
| `src/graph-tools.ts` | 461-463 | llmTip injection into descriptions |
| `src/graph-tools.ts` | 618-635 | execute-tool parameter bypass |
| `src/server.ts` | 134 | trust proxy |
| `src/server.ts` | 139 | CORS wildcard |
| `src/server.ts` | 201-218 | Dynamic registration — no validation |
| `src/logger.ts` | 9-11 | Logs dir — no restrictive permissions |
