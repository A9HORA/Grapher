# Grapher

**GraphQL Operation Harvester for Burp Suite**

## Author: A9hora

## What is Grapher?

Modern web applications increasingly use GraphQL APIs, but discovering the full attack surface is difficult — operations are scattered across HTTP POST bodies, minified JavaScript bundles, WebSocket connections, and persisted query systems. Introspection is often disabled in production, leaving pentesters blind to what queries and mutations the application actually supports.

Grapher solves this by passively monitoring all traffic flowing through Burp Suite and automatically extracting every GraphQL operation it can find. It pulls operations from live HTTP requests, parses them out of compiled JavaScript bundles (including heavily minified Webpack/Rollup output), captures WebSocket-based subscriptions, and detects persisted query IDs used by Apollo, Relay, and Meta's platforms. Everything appears in a single sortable, filterable table inside Burp — no introspection required.

The extension is completely passive. It never modifies, replays, or injects into any request or response. It observes traffic, extracts operations, and presents them for the tester to act on.

---

## Key Features

* **Automatic operation extraction** from HTTP POST/GET bodies, JavaScript files, minified bundles, and WebSocket messages
* **Execute JS Bundles** — runs captured JavaScript files through a sandboxed Node.js VM to discover dynamically assembled GraphQL operations that regex-based parsing can't reconstruct (requires Node.js)
* **Inline fragment detection** — captures standalone inline fragments (`... on TypeName { ... }`) stored as JS variables, common in apps that dynamically assemble queries via `.concat()` or template literals
* **Meta/Relay doc_id support** — captures `doc_id`, `queryId`, and `document_id` persisted operations used by Facebook, Instagram, and Relay-based applications
* **Send to Repeater / Intruder** — right-click any discovered operation to send it directly to Burp's testing tools with correct authentication headers, endpoint, and variable placeholders
* **Smart variable placeholders** — constructs ready-to-fill variable templates based on the operation signature (`String!` → `""`, `Int` → `0`, `Boolean` → `false`, complex types → `{}`), supporting both comma-separated and space-separated variable declarations
* **Inferred schema export** — generates a `.graphql` SDL file from all captured operations, ready to import into GraphQL Voyager for visual API mapping
* **CSV export and import** — save your findings and reload them in a future session without re-browsing the target
* **No external dependencies** — pure Java, zero third-party libraries, single self-contained JAR

---

## How It Works

Grapher registers an HTTP handler and a WebSocket handler in Burp Suite. As you browse the target application through Burp's proxy, Grapher inspects every request and response:

**HTTP requests** are checked for GraphQL POST bodies and GET parameters. The JSON body is parsed to extract the operation type, name, variables, and any persisted query hashes. This runs inline in the request handler since it's fast string matching.

**HTTP responses** with JavaScript content types are passed to a background thread where Grapher runs regex-based extraction against the full JS content. It looks for template literals, property assignments, compact operations, Relay compiled module nodes (`{kind:"Request",name:"...",id:"..."}`), and Meta's `queryID`/`doc_id` fields. The background thread prevents large JS bundles from blocking Burp's UI.

**WebSocket messages** sent from client to server are checked for GraphQL payloads using the `graphql-ws` and `subscriptions-transport-ws` message formats.

The same operation discovered from different sources (for example, an HTTP POST to /graphql and a JS file at /static/app.js) appears as separate entries because they carry different context — the HTTP entry has the real request with auth headers, while the JS entry shows where in the codebase the operation lives. Operations from the same source and endpoint are deduplicated to prevent table flooding during active testing.

When you right-click a finding and choose "Send to Repeater," Grapher constructs a proper GraphQL POST request using a real endpoint it observed during your browsing session. The constructed request carries the correct Host header, cookies, authorization tokens, and any custom headers the target expects — because it copies them from a real request template. The `gqlOp=` URL parameter is automatically updated to match the operation being sent. For `doc_id` operations, the request body uses `{"doc_id":"..."}` format instead of `{"query":"..."}`.

---

## Setup

### Prerequisites

* Burp Suite Professional or Community Edition
* Java 17 or later (bundled with Burp Suite 2024+)
* Node.js v16+ (optional — only needed for the "Execute JS Bundles" feature)

### Building from Source

Clone the repository and build with Gradle:

```
git clone https://github.com/A9HORA/Grapher.git
cd Grapher
./gradlew jar
```

On Windows:

```
gradlew.bat jar
```

The compiled JAR is produced at `build/libs/Grapher-1.0.0.jar`.

If you don't have the Gradle wrapper, install Gradle 8+ and run `gradle jar`.

### Installing in Burp Suite

1. Open Burp Suite
2. Go to **Extensions** → **Installed**
3. Click **Add**
4. Set extension type to **Java**
5. Select `build/libs/Grapher-1.0.0.jar`
6. A new **Grapher** tab appears in the Burp Suite top bar

No additional configuration is needed. Grapher starts capturing immediately.

---

## Usage Guide

### Basic Workflow

1. **Browse the target** through Burp's proxy as you normally would. Grapher captures operations in the background — no extra steps needed.
2. **Open the Grapher tab** to see all captured operations in a table. Each row shows the endpoint, HTTP method, source (HTTP POST, JS file, WebSocket, etc.), operation type (query/mutation/subscription), operation name, and the full operation body.
3. **Click any row** to see the full operation detail in the bottom pane, including the complete query body, the URL it was found in, and how it would be sent to the server.
4. **Filter results** using the Source and Type dropdowns in the toolbar. For example, filter by "mutation" to see only write operations, or by "Minified/Obfuscated JS" to see operations that were hidden in compiled JavaScript.

### Testing Operations

5. **Right-click any operation** → **Send to Repeater** to test it. Grapher constructs a ready-to-send GraphQL POST request with the correct endpoint, authentication, headers, and variable placeholders from your browsing session. Modify variables, strip fields, or alter the query directly in Repeater to test for authorization bypass, IDOR, or field-level access control issues.
6. **Right-click** → **Send to Intruder** to set up automated testing with Burp's Intruder tool.

### Execute JS Bundles (Node.js)

7. **Click "Execute JS Bundles"** in the toolbar to run captured JavaScript files through a sandboxed Node.js VM. This discovers dynamically assembled GraphQL operations that regex-based static parsing can't reconstruct — for example, queries built at runtime using `.concat()`, ternary expressions, or variable references.

   The feature works as follows:
   - Grapher extracts a companion Node.js script (`grapher-executor.js`) from the JAR
   - For each captured JS file with a response body, it saves the body to a temp file
   - Runs `node grapher-executor.js <temp_file>` in a sandboxed `vm.createContext()` environment
   - The sandbox intercepts `JSON.stringify()` and `fetch()` calls to capture assembled GraphQL operations
   - After execution, it scans all Webpack module exports for GraphQL strings
   - Captured operations appear in the table with source "JS Executed (Node.js)"

   **Node.js path discovery**: Grapher automatically searches common Node.js installation paths (`/usr/local/bin/node`, `/opt/homebrew/bin/node`, `~/.nvm/`, etc.) since Burp's JRE does not inherit the user's shell PATH. If auto-discovery fails, a file chooser dialog lets you manually locate the `node` binary.

   **Security**: The sandbox has no access to the real file system, network, `process`, or `require`. The JS file is read **outside** the sandbox by trusted code; the untrusted bundle runs **inside** the sandbox with only fake browser globals. A 10-second VM timeout kills runaway execution.

### Exporting Results

8. **Export CSV** saves all captured operations to a CSV file for reporting or archival. **Import CSV** reloads a previously exported file, so you can resume testing across Burp sessions without re-browsing.
9. **Export .graphql** generates an inferred SDL schema from all captured operations. Import this file into [GraphQL Voyager](https://apis.guru/graphql-voyager/) to visualize the API's type structure as an interactive graph — without needing introspection access.

### What Grapher Captures

| Source | Examples |
| --- | --- |
| HTTP POST Body | `{"query":"query GetUser($id:ID!){user(id:$id){name email}}","variables":{"id":"123"}}` |
| HTTP GET Params | `?query=query+GetUser{user{name}}&extensions={"persistedQuery":{"sha256Hash":"abc..."}}` |
| JS/Static Files | `` gql`query GetUser { user { name } }` ``  embedded in React/Angular/Vue bundles |
| Minified JS | `a.b="query GetUser{user{name}}"` in Webpack/Rollup compiled output |
| WebSocket | `{"type":"subscribe","payload":{"query":"subscription OnMessage{newMessage{id text}}"}}` |
| Meta/Relay doc_id | `{"doc_id":"1234567890","variables":{},"operationName":"GetUser"}` |
| JS Executed (Node.js) | Dynamically assembled operations captured via sandboxed JS execution |

### Detected Operation Types

| Type | Color | Meaning |
| --- | --- | --- |
| query | Blue | Read operations |
| mutation | Red | Write operations — high-value targets for testing |
| subscription | Green | Real-time WebSocket subscriptions |
| fragment | Purple | Reusable fragment definitions and inline fragments (`... on TypeName`) |
| persisted | Orange | Apollo APQ sha256 hashes |
| doc_id | Dark Blue | Relay/Meta persisted document IDs |

---

## Technical Details

### Architecture

```
GrapherExtension.java         — Entry point: registers handlers, tab, unload hook
├── GqlHttpHandler             — HTTP handler: parses POST bodies, GET params
│   └── Background thread      — JS parsing offloaded to a daemon thread
├── GqlWebSocketCreatedHandler — WebSocket handler: monitors subscription messages
├── GraphQLParser.java         — Stateless regex-based parser (15+ patterns)
├── GraphQLEntry.java          — Immutable data model with builder pattern
├── GraphQLTableModel.java     — Thread-safe JTable model with dedup and body upgrade
├── GraphQLPanel.java          — Swing UI: table, filters, detail pane, context menu, JS execution
├── SchemaInferrer.java        — Walks captured operations, builds merged SDL
└── grapher-executor.js        — Node.js sandbox script (bundled as JAR resource)
```

### Detection Pipeline

Grapher uses multiple extraction strategies optimized for different content types:

**HTTP POST/GET**: `JSON_QUERY_FIELD` regex with possessive quantifiers extracts the `"query"` field from JSON bodies. Persisted hashes are matched via `PERSISTED_HASH` and `PERSISTED_HASH_ALT` patterns. Relay/Meta doc_ids are matched via `JSON_DOC_ID`, `JSON_QUERY_ID`, and `JSON_DOCUMENT_ID` patterns.

**JS files**: Two-pass extraction — `parseJsContent` handles clean patterns (gql tagged templates, raw operation declarations) while `parseMinifiedJsContent` handles obfuscated patterns (property assignments, escaped strings, compact operations, object literal query fields, AST body fields, Relay compiled text, and Apollo-style hex IDs). All extracted content is sanitized via `cleanJsArtifacts` which strips JS operators, template syntax, `.concat()` calls, and ternary expressions.

**Compact operations**: `MINIFIED_COMPACT_OP` detects tightly packed operations like `query Foo{bar{id}}`, then `extractBalancedOp` walks nested braces for correct extraction. Region is capped at 50K chars to prevent performance issues on large files.

**Inline fragments**: `MINIFIED_PROP_ASSIGN` matches variable assignments containing inline fragments (`var y = "... on TypeName { ... }"`). `parseQueryString` detects bodies starting with `...` and creates fragment entries with the type name.

**Variable placeholders**: `buildVariablePlaceholders` parses the operation signature to generate type-appropriate placeholders. The variable regex `[^$,)]+` correctly handles both comma-separated (`$a: String!, $b: Int`) and space-separated (`$a: String! $b: Int`) variable declarations.

### Regex Safety

All string-matching patterns use possessive quantifiers (`*+`, `++`, `[^}]*+`) to prevent catastrophic backtracking on large inputs. The `cleanJsArtifacts` character-level sanitizer walks the string once without backtracking. JS files over 5MB are skipped entirely via `MAX_JS_SIZE`. The background JS parser thread catches `Throwable` (not just `Exception`) to survive `StackOverflowError` from deeply nested content.

### BApp Store Compliance

* **Threading**: JS parsing runs in a background daemon thread, never in HttpHandler callbacks. The Swing EDT is only used for UI updates via `SwingUtilities.invokeLater`.
* **Unload**: Implements `ExtensionUnloadingHandler`. On unload, the background thread pool is terminated and all data structures are cleared.
* **Thread safety**: All access to the shared entries list is synchronized on a dedicated lock object.
* **Large projects**: `HttpRequestResponse` objects are stored via `copyToTempFile()` to prevent unbounded memory growth.
* **GUI parenting**: All popup dialogs (`JOptionPane`, `JFileChooser`) are parented to `SwingUtils.suiteFrame()` for correct multi-monitor behavior.
* **Networking**: No outbound HTTP requests. The "Execute JS Bundles" feature runs a local Node.js process — it does not make any network calls.
* **Offline**: No online service dependencies. Everything runs locally.
* **Dependencies**: Zero external dependencies. Pure JDK 17 + Montoya API 2026.2.
* **Passive only**: Never modifies, injects, replays, or alters any request or response.

### Build Configuration

* **Build tool**: Gradle
* **API artifact**: `net.portswigger.burp.extensions:montoya-api:2026.2`
* **Java**: 17 (source and target compatibility)
* **Output**: Single uber JAR with no runtime dependencies (the `grapher-executor.js` script is bundled as a JAR resource)

---

## Known Limitations

* **Dynamically assembled queries**: Operations built at runtime through JS variable references and ternary expressions (e.g., `.concat(condition ? fragmentVar : "")`) cannot be fully reconstructed by regex. The "Execute JS Bundles" feature addresses this for cases where Webpack module factories execute the assembly code, but operations gated behind React hook lifecycles or user actions may not be captured.
* **Inferred schema types**: Fields in the exported `.graphql` schema show as `Unknown` type because only introspection reveals return types. The schema is useful for field discovery and structure mapping, not as a type-complete definition.
* **Imported CSV entries**: Operations loaded via CSV import have null request/response data. Send to Repeater uses the constructed request path with a discovered endpoint template.
* **Node.js requirement**: The "Execute JS Bundles" feature requires Node.js v16+ installed on the host machine. If Node.js is not found, Grapher continues to work with regex-based extraction only.
