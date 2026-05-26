# Grapher

**Discover the GraphQL operations your target actually uses — without introspection.**

A Burp Suite extension that passively harvests every GraphQL operation from your proxy traffic: live API requests, compiled JavaScript bundles, WebSocket subscriptions, and persisted query systems. One table. Zero noise.

**Author:** [A9hora](https://github.com/A9HORA)

---

## The Problem

You're testing a GraphQL API. Introspection is disabled. You have no schema. The only way to find operations is to click through the app and hope you trigger them all — but you won't. Mutations hide behind workflows you haven't explored. Queries live in JS bundles the browser loaded but never executed. Persisted query IDs fly past in requests you didn't notice. The attack surface is invisible.

Existing tools don't solve this:

| Tool | Approach | When introspection is disabled |
|------|----------|-------------------------------|
| InQL | Sends introspection query to discover schema | Limited — can't discover what it can't query |
| GraphQL Raider | Pretty-prints GraphQL requests you already captured | No discovery — only formats what you already have |
| AutoGQL | Teaches Burp's scanner to fuzz GraphQL fields | Needs operations first — doesn't find them |

**Grapher takes a different approach.** It doesn't ask the server what it supports. It watches your traffic and extracts every operation the application knows about — from every source the application uses to deliver them.

---

## What Grapher Finds

Grapher captures operations from **six different sources** simultaneously:

| What | How other tools handle it | How Grapher handles it |
|------|--------------------------|----------------------|
| **Live API requests** | Most tools see these | Captured automatically with full auth context |
| **JS/Static bundles** | Ignored by other tools | Parsed from compiled Webpack, Rollup, and Vite output |
| **Dynamically assembled queries** | Invisible to all tools | Resolved when built from string variables and concatenation chains in JS |
| **WebSocket subscriptions** | Ignored by other tools | Captured from `graphql-ws` and subscription transport messages |
| **Persisted query hashes** | Ignored by other tools | Apollo APQ sha256 hashes and Relay/Meta doc_id captured |
| **Minified/obfuscated code** | Ignored by other tools | Extracted from production builds where operation names are mangled |

The result: Grapher typically discovers **2-5x more operations** than what appears in your HTTP history from manual browsing alone.

---

## Key Capabilities

### Passive Discovery
Grapher never sends a single request. It reads traffic flowing through Burp's proxy and extracts operations from both requests and responses. Load it, browse the target, and operations appear. No configuration needed.

### JS Bundle Analysis
Modern web apps compile their GraphQL operations into JavaScript bundles during the build process. These bundles contain every query and mutation the app can send — including operations behind features you haven't triggered, admin endpoints you can't reach, and authenticated flows you haven't explored. Grapher extracts them all.

### Dynamic Query Reconstruction
Some applications assemble GraphQL queries at runtime from fragments stored in separate variables. Other tools see broken pieces. Grapher resolves variable references, follows concatenation chains, and reconstructs the complete operation within the same JavaScript file. Queries that are computed through runtime logic — such as loops, array methods, or cross-module imports — are captured from live traffic when the browser executes them.

### Execute JS Bundles
For operations that resist static analysis, Grapher can execute captured JavaScript files in a sandboxed Node.js environment. The sandbox intercepts GraphQL operations as they're assembled at runtime, capturing queries that only exist in memory during execution. No network access, no file system access — just operation capture.

### Smart Send to Repeater
Right-click any discovered operation and send it to Repeater with the correct endpoint, authentication headers, cookies, and variable placeholders — all copied from real requests observed during your session. Operations discovered from multiple sources are automatically merged to produce the most complete version with all fields and fragments combined.

### Operation Merging
The same operation captured from different sources often has different levels of completeness. Grapher merges all versions — combining variables, fields, inline fragments, and arguments from every source into a single unified operation. This merged view powers both Send to Repeater and CSV/schema exports.

### Schema Export
Generate a `.graphql` SDL file from all captured operations — ready to import into [GraphQL Voyager](https://apis.guru/graphql-voyager/) for visual API mapping. Build an API map without introspection access.

### Search and Filter
Filter operations by source, type (query/mutation/subscription/fragment), or search by operation name. Instantly see how many versions of the same operation exist across different sources and compare their bodies side by side.

---

## Operation Types Detected

| Type | Meaning |
|------|---------|
| **query** | Read operations — data fetching |
| **mutation** | Write operations — state changes, high-value targets |
| **subscription** | Real-time WebSocket data streams |
| **fragment** | Reusable field sets and inline type fragments |
| **persisted** | Apollo-style sha256 operation hashes |
| **doc_id** | Relay/Meta persisted document identifiers |

---

## Setup

### Prerequisites

- Burp Suite Professional or Community Edition
- Java 17+ (bundled with Burp Suite 2024+)
- Node.js v16+ (optional — only for Execute JS Bundles)

### Build

```
git clone https://github.com/A9HORA/Grapher.git
cd Grapher
./gradlew jar
```

Output: `build/libs/Grapher-1.0.0.jar`

### Install

1. Burp Suite → **Extensions** → **Add**
2. Type: **Java**
3. Select `Grapher-1.0.0.jar`

Grapher starts capturing immediately. No configuration required.

---

## Usage

### 1. Browse
Browse the target through Burp's proxy. Grapher captures operations in the background from every source — HTTP requests, JS files, WebSocket messages.

### 2. Discover
Open the **Grapher** tab. Every captured operation appears in a sortable, filterable table showing the source, type, name, endpoint, and full operation body.

### 3. Analyze
Use the **Search** bar to find all versions of an operation across sources. Compare the JS-extracted version against the live HTTP version. Filter by **mutation** to see write operations. Filter by source to focus on JS-discovered operations that never appeared in your HTTP history.

### 4. Test
Right-click → **Send to Repeater**. Grapher constructs the request using merged operation bodies and real authentication from your session. Test for IDOR, authorization bypass, field-level access control, and injection.

### 5. Execute JS Bundles
Click **Execute JS Bundles** for deeper extraction. Grapher runs captured JavaScript through a sandboxed Node.js environment, capturing operations that static analysis couldn't reconstruct. Results appear in the same table.

### 6. Export
- **Export CSV** — deduplicated, merged operations for reporting
- **Export .graphql** — inferred SDL schema for [GraphQL Voyager visualization](https://apis.guru/graphql-voyager/)
- **Import CSV** — reload findings from a previous session

---

## Real-World Impact

On a typical modern web application using GraphQL:

- **Manual browsing** captures 5-10 operations from HTTP POST traffic
- **Grapher** discovers significantly more operations from the same session — including mutations behind protected workflows, admin queries in shared bundles, authenticated variants with additional parameters, and subscription endpoints
- Operations found only in JS bundles often reveal **additional fields, alternative resolvers, and undocumented parameters** not visible in the live traffic

Every additional operation is a potential authorization bypass, IDOR, or injection point that would have been invisible without Grapher.

---

## Compliance

- **Completely passive** — never modifies, replays, or injects into any traffic
- **No outbound requests** — the extension makes zero network calls
- **Clean unload** — all resources released when the extension is removed
- **Thread-safe** — background processing never blocks Burp's UI
- **Memory-safe** — designed for large projects and extended testing sessions
- **Zero dependencies** — single self-contained JAR, no external libraries
- **Offline capable** — no internet connection required

---

## FAQ

**Does Grapher need introspection to be enabled?**
No. Grapher discovers operations from traffic analysis, not from the server's schema. It works on targets where introspection is completely disabled.

**Does it work with Apollo, Relay, urql, and other GraphQL clients?**
Yes. Grapher captures operations from any GraphQL client that sends standard query requests — including Apollo, Relay, urql, graphql-request, TanStack Query, and others. Clients that generate queries dynamically at runtime (such as gqty) are supported through live traffic capture when the browser executes the query.

**Does it modify any requests or responses?**
No. Grapher is entirely passive. It only reads traffic — it never injects, modifies, or replays anything.

**What about operations built at runtime using dynamic JavaScript?**
Grapher resolves variable references and string concatenation chains to reconstruct dynamically assembled queries from JS bundles. For operations that resist static analysis, the Execute JS Bundles feature runs the code in a sandboxed environment to capture additional operations. Queries built through runtime computation — such as loops or conditional logic based on user state — are captured from live traffic when the browser sends them.

**Can I use it alongside InQL or other GraphQL extensions?**
Yes. Grapher focuses on discovery. InQL and others focus on testing. They complement each other — use Grapher to find the full attack surface, then use other tools to test it.

---

## License

See [LICENSE](LICENSE) for details.
