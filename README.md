# Grapher

**GraphQL Operation Harvester for Burp Suite**

## Author: A9hora

## What is Grapher?

Modern web applications increasingly use GraphQL APIs, but discovering the full attack surface is difficult — operations are scattered across HTTP POST bodies, minified JavaScript bundles, WebSocket connections, and persisted query systems. Introspection is often disabled in production, leaving pentesters blind to what queries and mutations the application actually supports.

Grapher solves this by passively monitoring all traffic flowing through Burp Suite and automatically extracting every GraphQL operation it can find — from live HTTP requests, compiled JavaScript bundles, WebSocket subscriptions, and persisted query systems. Everything appears in a single sortable, filterable table inside Burp. No introspection required.

The extension is completely passive. It never modifies, replays, or injects into any request or response.

---

## Key Features

* **Automatic operation extraction** from HTTP POST/GET bodies, JavaScript files, minified bundles, and WebSocket messages
* **Execute JS Bundles** — runs captured JavaScript files through a sandboxed Node.js environment to discover dynamically assembled operations that static parsing can't reconstruct (requires Node.js)
* **Inline fragment detection** — captures standalone inline fragments (`... on TypeName { ... }`) stored as JS variables
* **Meta/Relay support** — captures `doc_id`, `queryId`, and `document_id` persisted operations
* **Send to Repeater / Intruder** — right-click any operation to send it with correct authentication, endpoint, and variable placeholders
* **Smart variable placeholders** — generates ready-to-fill variable templates from the operation signature
* **Schema export** — generates a `.graphql` SDL file for use with GraphQL Voyager
* **CSV export and import** — save and reload findings across sessions
* **Zero dependencies** — pure Java, single self-contained JAR

---

## How It Works

Grapher registers handlers in Burp Suite that inspect traffic as you browse:

**HTTP requests** are checked for GraphQL POST bodies and GET parameters, extracting operation types, names, variables, and persisted query hashes.

**HTTP responses** containing JavaScript are parsed in a background thread to extract embedded GraphQL operations from compiled JS bundles.

**WebSocket messages** are checked for GraphQL subscription payloads.

Operations discovered from different sources appear as separate entries — an HTTP POST entry has the real request with auth headers, while a JS entry shows where in the codebase the operation lives. Duplicate operations from the same source and endpoint are merged.

When you send a finding to Repeater, Grapher constructs a proper GraphQL POST request using a real endpoint it observed during your session, carrying the correct headers, cookies, and authentication tokens.

---

## Setup

### Prerequisites

* Burp Suite Professional or Community Edition
* Java 17+ (bundled with Burp Suite 2024+)
* Node.js v16+ (optional — only for "Execute JS Bundles")

### Build

```
git clone https://github.com/A9HORA/Grapher.git
cd Grapher
./gradlew jar
```

On Windows: `gradlew.bat jar`

Output: `build/libs/Grapher-1.0.0.jar`

### Install

1. Burp Suite → **Extensions** → **Add**
2. Type: **Java**
3. Select `Grapher-1.0.0.jar`

Grapher starts capturing immediately.

---

## Usage Guide

### Capture

Browse the target through Burp's proxy as you normally would. Grapher captures operations in the background. Open the **Grapher** tab to see results.

### Filter

Use the Source and Type dropdowns to narrow results — filter by "mutation" to see write operations, or by source to see what came from JS bundles vs live traffic.

### Test

Right-click any operation → **Send to Repeater**. Grapher constructs a ready-to-send request with the correct endpoint, headers, cookies, and variable placeholders. Modify variables, strip fields, or alter the query to test for authorization bypass, IDOR, or field-level access control issues.

Right-click → **Send to Intruder** for automated testing.

### Execute JS Bundles

Click **Execute JS Bundles** to run captured JavaScript files through Node.js. This reconstructs operations that are dynamically assembled at runtime — queries built using variable references, string concatenation, and conditional expressions that static parsing can't resolve.

The feature resolves variable assignments in the source code, reconstructs concatenation chains, and handles conditional branches (including both sides of ternary expressions). It also executes the bundle in a sandboxed environment to capture operations that are assembled through runtime logic.

Grapher searches common Node.js paths automatically. If not found, a file browser lets you locate it manually.

### Export

* **Export CSV** — save all findings for reporting or reloading later
* **Import CSV** — reload a previously exported session
* **Export .graphql** — generate an inferred schema for [GraphQL Voyager](https://apis.guru/graphql-voyager/)

---

## What Grapher Captures

| Source | Description |
| --- | --- |
| HTTP POST/GET | GraphQL operations from live API requests |
| JS/Static Files | Operations embedded in JavaScript bundles |
| Minified JS | Operations in obfuscated bundler output |
| WebSocket | Real-time subscription messages |
| Meta/Relay doc_id | Persisted query identifiers |
| JS Executed | Dynamically assembled operations captured via Node.js execution |

### Operation Types

| Type | Color | Meaning |
| --- | --- | --- |
| query | Blue | Read operations |
| mutation | Red | Write operations — high-value targets for testing |
| subscription | Green | Real-time subscriptions |
| fragment | Purple | Reusable fragment definitions and inline fragments |
| persisted | Orange | Persisted query hashes |
| doc_id | Dark Blue | Relay/Meta persisted document IDs |

---

## BApp Store Compliance

* Passive only — never modifies any traffic
* Background threading for JS parsing
* Clean unload with resource cleanup
* Thread-safe data structures
* Memory-safe storage for large projects
* No outbound network requests
* No external dependencies
* Fully offline — no online service dependencies

---

## Known Limitations

* Operations assembled across multiple JavaScript chunk files may not be fully reconstructed — browse the target to trigger them and Grapher captures the complete operation from the HTTP request
* Exported schema field types show as `Unknown` — only introspection reveals return types
* Execute JS Bundles requires Node.js v16+ on the host machine
