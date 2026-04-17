# Grapher

**GraphQL Operation Harvester for Burp Suite**

Author: A9hora
---

## What is Grapher?

Modern web applications increasingly use GraphQL APIs, but discovering the full attack surface is difficult — operations are scattered across HTTP POST bodies, minified JavaScript bundles, WebSocket connections, and persisted query systems. Introspection is often disabled in production, leaving pentesters blind to what queries and mutations the application actually supports.

Grapher solves this by passively monitoring all traffic flowing through Burp Suite and automatically extracting every GraphQL operation it can find. It pulls operations from live HTTP requests, parses them out of compiled JavaScript bundles (including heavily minified Webpack/Rollup output), captures WebSocket-based subscriptions, and detects persisted query IDs used by Apollo, Relay, and Meta's platforms. Everything appears in a single sortable, filterable table inside Burp — no introspection required.

The extension is completely passive. It never modifies, replays, or injects into any request or response. It observes traffic, extracts operations, and presents them for the tester to act on.

---

## Key Features

- **Automatic operation extraction** from HTTP POST/GET bodies, JavaScript files, minified bundles, and WebSocket messages
- **Meta/Relay doc_id support** — captures `doc_id`, `queryId`, and `document_id` persisted operations used by Facebook, Instagram, and Relay-based applications
- **Send to Repeater / Intruder** — right-click any discovered operation to send it directly to Burp's testing tools with correct authentication headers and endpoint
- **Inferred schema export** — generates a `.graphql` SDL file from all captured operations, ready to import into GraphQL Voyager for visual API mapping
- **CSV export and import** — save your findings and reload them in a future session without re-browsing the target
- **No external dependencies** — pure Java, zero third-party libraries, single self-contained JAR

---

## How It Works

Grapher registers an HTTP handler and a WebSocket handler in Burp Suite. As you browse the target application through Burp's proxy, Grapher inspects every request and response:

**HTTP requests** are checked for GraphQL POST bodies and GET parameters. The JSON body is parsed to extract the operation type, name, variables, and any persisted query hashes. This runs inline in the request handler since it's fast string matching.

**HTTP responses** with JavaScript content types are passed to a background thread where Grapher runs regex-based extraction against the full JS content. It looks for template literals, common patterns, Relay compiled module nodes (`{kind:"Request",name:"...",id:"..."}`), and Meta's `queryID`/`doc_id` fields. The background thread prevents large JS bundles from blocking Burp's UI.

**WebSocket messages** sent from client to server are checked for GraphQL payloads using the `graphql-ws` and `subscriptions-transport-ws` message formats.

The same operation discovered from different sources (for example, an HTTP POST to /graphql and a JS file at /static/app.js) appears as separate entries because they carry different context — the HTTP entry has the real request with auth headers, while the JS entry shows where in the codebase the operation lives. Operations from the same source and endpoint are deduplicated to prevent table flooding during active testing.

When you right-click a finding and choose "Send to Repeater," Grapher constructs a proper GraphQL POST request using a real endpoint it observed during your browsing session. The constructed request carries the correct Host header, cookies, authorization tokens, and any custom headers the target expects — because it copies them from a real request template. For `doc_id` operations, the request body uses `{"doc_id":"..."}` format instead of `{"query":"..."}`.

---

## Setup

### Prerequisites

- Burp Suite Professional or Community Edition
- Java 17 or later (bundled with Burp Suite 2024+)

### Building from Source

Clone the repository and build with Gradle:

```bash
git clone https://github.com/YOUR_USERNAME/Grapher.git
cd Grapher
./gradlew jar 
OR
gradle build jar
```

On Windows:
```bash
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

5. **Right-click any operation** → **Send to Repeater** to test it. Grapher constructs a ready-to-send GraphQL POST request with the correct endpoint, authentication, and headers from your browsing session. Modify variables, strip fields, or alter the query directly in Repeater to test for authorization bypass, IDOR, or field-level access control issues.

6. **Right-click** → **Send to Intruder** to set up automated testing with Burp's Intruder tool.

### Exporting Results

7. **Export CSV** saves all captured operations to a CSV file for reporting or archival. **Import CSV** reloads a previously exported file, so you can resume testing across Burp sessions without re-browsing.

8. **Export .graphql** generates an inferred SDL schema from all captured operations. Import this file into [GraphQL Voyager](https://apis.guru/graphql-voyager/) to visualize the API's type structure as an interactive graph — without needing introspection access.

### What Grapher Captures

| Source | Examples |
|---|---|
| HTTP POST Body | `{"query":"query GetUser($id:ID!){user(id:$id){name email}}","variables":{"id":"123"}}` |
| HTTP GET Params | `?query=query+GetUser{user{name}}&extensions={"persistedQuery":{"sha256Hash":"abc..."}}` |
| JS/Static Files | ``gql`query GetUser { user { name } }` `` embedded in React/Angular/Vue bundles |
| Minified JS | `a.b="query GetUser{user{name}}"` in Webpack/Rollup compiled output |
| WebSocket | `{"type":"subscribe","payload":{"query":"subscription OnMessage{newMessage{id text}}"}}` |
| Meta/Relay doc_id | `{"doc_id":"1234567890","variables":{},"operationName":"GetUser"}` |

### Detected Operation Types

| Type | Color | Meaning |
|---|---|---|
| query | Blue | Read operations |
| mutation | Red | Write operations — high-value targets for testing |
| subscription | Green | Real-time WebSocket subscriptions |
| fragment | Purple | Reusable fragment definitions |
| persisted | Orange | Apollo APQ sha256 hashes |
| doc_id | Dark Blue | Relay/Meta persisted document IDs |

---

## Technical Details

### Architecture

```
GrapherExtension.java       — Entry point: registers handlers, tab, unload hook
├── GqlHttpHandler           — HTTP handler: parses POST bodies, GET params
│   └── Background thread    — JS parsing offloaded to a daemon thread
├── GqlWebSocketCreatedHandler — WebSocket handler: monitors subscription messages
├── GraphQLParser.java        — Stateless regex-based parser (15+ patterns)
├── GraphQLEntry.java         — Immutable data model with builder pattern
├── GraphQLTableModel.java    — Thread-safe JTable model with dedup
├── GraphQLPanel.java         — Swing UI: table, filters, detail pane, context menu
└── SchemaInferrer.java       — Walks captured operations, builds merged SDL
```

### BApp Store Compliance

- **Threading**: JS parsing runs in a background daemon thread, never in HttpHandler callbacks. The Swing EDT is only used for UI updates via `SwingUtilities.invokeLater`.
- **Unload**: Implements `ExtensionUnloadingHandler`. On unload, the background thread pool is terminated and all data structures are cleared.
- **Thread safety**: All access to the shared entries list is synchronized on a dedicated lock object.
- **Large projects**: `HttpRequestResponse` objects are stored via `copyToTempFile()` to prevent unbounded memory growth.
- **GUI parenting**: All popup dialogs (`JOptionPane`, `JFileChooser`) are parented to `SwingUtils.suiteFrame()` for correct multi-monitor behavior.
- **Networking**: No outbound HTTP requests. URL decoding uses `java.net.URLDecoder` (utility only, not networking).
- **Offline**: No online service dependencies. Everything runs locally.
- **Dependencies**: Zero external dependencies. Pure JDK 17 + Montoya API 2026.2.
- **Regex safety**: All string-matching patterns use possessive quantifiers (`*+`, `++`) to prevent catastrophic backtracking. JS files over 5MB are skipped.
- **Passive only**: Never modifies, injects, replays, or alters any request or response.

### Build Configuration

- **Build tool**: Gradle
- **API artifact**: `net.portswigger.burp.extensions:montoya-api:2026.2`
- **Java**: 17 (source and target compatibility)
- **Output**: Single uber JAR with no runtime dependencies

---
