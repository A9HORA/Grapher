package grapher;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Stateless parser that extracts GraphQL operations from various content types.
 * All methods are static — no instance state needed.
 */
public class GraphQLParser {

    // --- JSON-level patterns ---
    // Uses possessive quantifiers (*+, ++) to prevent catastrophic backtracking
    // on large JS files. Standard * and *? cause exponential backtracking on
    // alternation groups like (?:[^"\\]|\\.)* when the input is large.

    // Matches "query" : "..." in JSON bodies
    private static final Pattern JSON_QUERY_FIELD = Pattern.compile(
            "\"query\"\\s*:\\s*\"((?:[^\"\\\\]++|\\\\.)++)\"",
            Pattern.DOTALL
    );

    // operationName field in JSON
    private static final Pattern JSON_OP_NAME = Pattern.compile(
            "\"operationName\"\\s*:\\s*\"([^\"]+)\""
    );

    // Persisted query hash in extensions block
    private static final Pattern PERSISTED_HASH = Pattern.compile(
            "\"sha256Hash\"\\s*:\\s*\"([0-9a-fA-F]{64})\""
    );

    // Alternative: extensions.persistedQuery.sha256Hash
    private static final Pattern PERSISTED_HASH_ALT = Pattern.compile(
            "\"hash\"\\s*:\\s*\"([0-9a-fA-F]{64})\""
    );

    // --- Relay / Meta doc_id patterns ---
    private static final Pattern JSON_DOC_ID = Pattern.compile(
            "\"doc_id\"\\s*:\\s*\"([^\"]+)\""
    );

    private static final Pattern JSON_QUERY_ID = Pattern.compile(
            "\"queryId\"\\s*:\\s*\"([^\"]+)\""
    );

    private static final Pattern JSON_DOCUMENT_ID = Pattern.compile(
            "\"document_id\"\\s*:\\s*\"([^\"]+)\""
    );

    // Relay compiled module node — uses possessive [^}]*+ to prevent backtracking
    private static final Pattern RELAY_NODE_ID = Pattern.compile(
            "(?:kind\\s*:\\s*\"Request\"|\"kind\"\\s*:\\s*\"Request\")" +
            "[^}]*+" +
            "(?:name\\s*:\\s*\"([A-Za-z_]\\w*)\"|\"name\"\\s*:\\s*\"([A-Za-z_]\\w*)\")" +
            "[^}]*+" +
            "(?:id\\s*:\\s*\"([^\"]+)\"|\"id\"\\s*:\\s*\"([^\"]+)\")",
            Pattern.DOTALL
    );

    private static final Pattern RELAY_NODE_ID_REV = Pattern.compile(
            "(?:kind\\s*:\\s*\"Request\"|\"kind\"\\s*:\\s*\"Request\")" +
            "[^}]*+" +
            "(?:id\\s*:\\s*\"([^\"]+)\"|\"id\"\\s*:\\s*\"([^\"]+)\")" +
            "[^}]*+" +
            "(?:name\\s*:\\s*\"([A-Za-z_]\\w*)\"|\"name\"\\s*:\\s*\"([A-Za-z_]\\w*)\")",
            Pattern.DOTALL
    );

    private static final Pattern META_QUERY_ID = Pattern.compile(
            "(?:queryID|queryId)\\s*[=:]\\s*\"([^\"]+)\""
    );

    private static final Pattern META_DOC_ID_JS = Pattern.compile(
            "doc_id\\s*[=:]\\s*\"([^\"]+)\""
    );

    // --- GraphQL operation detection in raw query strings ---
    private static final Pattern GQL_OP_PATTERN = Pattern.compile(
            "\\b(query|mutation|subscription)\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*[({]"
    );

    private static final Pattern GQL_ANON_PATTERN = Pattern.compile(
            "\\b(query|mutation|subscription)\\s*[({]"
    );

    private static final Pattern GQL_FRAGMENT_PATTERN = Pattern.compile(
            "\\bfragment\\s+([A-Za-z_][A-Za-z0-9_]*)\\s+on\\s+"
    );

    // --- JS file embedded GraphQL ---
    private static final Pattern JS_GQL_TAG = Pattern.compile(
            "(?:gql|graphql)\\s*`([^`]{10,}+)`",
            Pattern.DOTALL
    );

    private static final Pattern JS_GQL_STRING = Pattern.compile(
            "(?:query|mutation|subscription)\\s+[A-Za-z_]\\w*\\s*(?:\\([^)]*+\\))?\\s*\\{",
            Pattern.DOTALL
    );

    // GET request ?query=... parameter
    private static final Pattern URL_QUERY_PARAM = Pattern.compile(
            "[?&]query=([^&]+)"
    );

    // Persisted query via GET
    private static final Pattern URL_EXTENSIONS_HASH = Pattern.compile(
            "[?&]extensions=[^&]*+sha256Hash[\"':]+([0-9a-fA-F]{64})"
    );

    // --- Minified/Obfuscated JS patterns — all use possessive quantifiers ---

    private static final Pattern MINIFIED_PROP_ASSIGN = Pattern.compile(
            "[a-zA-Z_$][a-zA-Z0-9_$.]*\\s*=\\s*\"((?:query|mutation|subscription|fragment)(?:[^\"\\\\]++|\\\\.)++)\"",
            Pattern.DOTALL
    );

    private static final Pattern MINIFIED_ESCAPED_GQL = Pattern.compile(
            "\"((?:query|mutation|subscription|fragment)\\s+[A-Za-z_]\\w*(?:[^\"\\\\]++|\\\\.)++)\"",
            Pattern.DOTALL
    );

    // MINIFIED_COMPACT_OP pattern kept for reference but extraction now uses
    // GQL_OP_PATTERN + extractBalancedOp in parseMinifiedJsContent
    private static final Pattern MINIFIED_COMPACT_OP = Pattern.compile(
            "\\b(query|mutation|subscription)\\s+([A-Za-z_]\\w*)\\s*\\{([^}]{3,}+)\\}",
            Pattern.DOTALL
    );

    private static final Pattern MINIFIED_OBJ_QUERY = Pattern.compile(
            "\\bquery\\s*:\\s*\"((?:query|mutation|subscription|fragment)(?:[^\"\\\\]++|\\\\.)++)\"",
            Pattern.DOTALL
    );

    private static final Pattern MINIFIED_LOC_BODY = Pattern.compile(
            "body\\s*:\\s*\"((?:query|mutation|subscription|fragment)(?:[^\"\\\\]++|\\\\.)++)\"",
            Pattern.DOTALL
    );

    private static final Pattern MINIFIED_RELAY_TEXT = Pattern.compile(
            "(?:text|queryText|operationText)\\s*[=:]\\s*\"((?:query|mutation|subscription|fragment)(?:[^\"\\\\]++|\\\\.)++)\"",
            Pattern.DOTALL
    );

    private static final Pattern MINIFIED_APOLLO_ID = Pattern.compile(
            "id\\s*:\\s*\"([0-9a-fA-F]{64})\""
    );

    // Maximum JS file size to process (5MB) — prevents regex engine overload
    private static final int MAX_JS_SIZE = 5 * 1024 * 1024;

    private GraphQLParser() {}

    /**
     * Extract GraphQL operations from an HTTP POST body (JSON).
     */
    public static List<ParsedOp> parseJsonBody(String body) {
        List<ParsedOp> results = new ArrayList<>();
        if (body == null || body.isEmpty()) return results;

        // Check for Apollo persisted query hashes (extensions.persistedQuery.sha256Hash)
        Matcher hashMatcher = PERSISTED_HASH.matcher(body);
        if (!hashMatcher.find()) {
            hashMatcher = PERSISTED_HASH_ALT.matcher(body);
        }
        if (hashMatcher.find()) {
            String hash = hashMatcher.group(1);
            String opName = extractJsonOpName(body);
            results.add(new ParsedOp("persisted", opName, hash, "Persisted: " + hash));
        }

        // Check for Relay/Meta doc_id (replaces query string entirely)
        // {"doc_id":"1234567890","variables":{...}}
        Matcher docIdMatcher = JSON_DOC_ID.matcher(body);
        if (docIdMatcher.find()) {
            String docId = docIdMatcher.group(1);
            String opName = extractJsonOpName(body);
            results.add(new ParsedOp("doc_id", opName, docId,
                    "doc_id: " + docId + (opName.isEmpty() ? "" : " (" + opName + ")")));
        }

        // Check for queryId variant (some Relay implementations)
        // {"queryId":"5eb63bbbe01eeed093cb22bb8f5acdc3","variables":{...}}
        Matcher queryIdMatcher = JSON_QUERY_ID.matcher(body);
        if (queryIdMatcher.find()) {
            String queryId = queryIdMatcher.group(1);
            String opName = extractJsonOpName(body);
            results.add(new ParsedOp("doc_id", opName, queryId,
                    "queryId: " + queryId + (opName.isEmpty() ? "" : " (" + opName + ")")));
        }

        // Check for document_id variant
        // {"document_id":"operation.id","variables":{...}}
        Matcher documentIdMatcher = JSON_DOCUMENT_ID.matcher(body);
        if (documentIdMatcher.find()) {
            String documentId = documentIdMatcher.group(1);
            String opName = extractJsonOpName(body);
            results.add(new ParsedOp("doc_id", opName, documentId,
                    "document_id: " + documentId + (opName.isEmpty() ? "" : " (" + opName + ")")));
        }

        // Extract the query field value
        Matcher qm = JSON_QUERY_FIELD.matcher(body);
        while (qm.find()) {
            String rawQuery = unescapeJson(qm.group(1));
            String opName = extractJsonOpName(body);
            List<ParsedOp> ops = parseQueryString(rawQuery, opName);
            results.addAll(ops);
        }

        // Handle batched queries (JSON array of operations)
        if (body.trim().startsWith("[")) {
            String[] parts = body.split("\\},\\s*\\{");
            for (String part : parts) {
                Matcher qmBatch = JSON_QUERY_FIELD.matcher(part);
                while (qmBatch.find()) {
                    String rawQuery = unescapeJson(qmBatch.group(1));
                    String opName = extractJsonOpName(part);
                    results.addAll(parseQueryString(rawQuery, opName));
                }
                // Also check batched doc_id requests
                Matcher docIdBatch = JSON_DOC_ID.matcher(part);
                if (docIdBatch.find()) {
                    String docId = docIdBatch.group(1);
                    String opName = extractJsonOpName(part);
                    results.add(new ParsedOp("doc_id", opName, docId,
                            "doc_id: " + docId + (opName.isEmpty() ? "" : " (" + opName + ")")));
                }
            }
        }

        return results;
    }

    /**
     * Extract GraphQL operations from GET request URL parameters.
     */
    public static List<ParsedOp> parseUrlParams(String url) {
        List<ParsedOp> results = new ArrayList<>();
        if (url == null) return results;

        // Check for persisted query in extensions param
        Matcher extHash = URL_EXTENSIONS_HASH.matcher(url);
        if (extHash.find()) {
            results.add(new ParsedOp("persisted", "anonymous", extHash.group(1),
                    "Persisted GET: " + extHash.group(1)));
        }

        // Check for inline query param
        Matcher qp = URL_QUERY_PARAM.matcher(url);
        if (qp.find()) {
            String decoded = urlDecode(qp.group(1));
            results.addAll(parseQueryString(decoded, null));
        }

        return results;
    }

    /**
     * Extract GraphQL operations embedded in JS/static file content.
     */
    public static List<ParsedOp> parseJsContent(String content) {
        List<ParsedOp> results = new ArrayList<>();
        if (content == null || content.isEmpty()) return results;
        if (content.length() > MAX_JS_SIZE) return results; // skip oversized files

        // Tagged template literals: gql`...` or graphql`...`
        Matcher tagMatcher = JS_GQL_TAG.matcher(content);
        while (tagMatcher.find()) {
            String gqlBody = cleanJsArtifacts(tagMatcher.group(1));
            results.addAll(parseQueryString(gqlBody, null));
        }

        // Raw query/mutation/subscription declarations in JS strings
        Matcher rawMatcher = JS_GQL_STRING.matcher(content);
        while (rawMatcher.find()) {
            // Extract from match start to end of content — no artificial limit.
            // extractBalancedOp walks until braces balance, so it self-limits.
            String region = content.substring(rawMatcher.start());
            String fullOp = extractBalancedOp(region);
            String cleaned = cleanJsArtifacts(fullOp);
            results.addAll(parseQueryString(cleaned, null));
        }

        // Also check for persisted hashes in JS bundles
        Matcher hashMatcher = PERSISTED_HASH.matcher(content);
        while (hashMatcher.find()) {
            results.add(new ParsedOp("persisted", "anonymous", hashMatcher.group(1),
                    "JS Persisted: " + hashMatcher.group(1)));
        }

        return results;
    }

    /**
     * Extract GraphQL operations from minified/obfuscated JS bundles.
     *
     * Targets patterns that standard parseJsContent misses:
     *   - Webpack/Rollup compiled output with escaped newlines
     *   - Short-variable property assignments (e.g. n.query="mutation...")
     *   - Tightly packed operations with no whitespace (e.g. "query Foo{bar{id}}")
     *   - Relay-style compiled artifacts (operation.text = "query...")
     *   - AST-compiled graphql-tag output (body:"query...")
     *   - Object literal query fields (query:"mutation Baz{...}")
     *   - Apollo-style persisted query IDs embedded as 64-char hex
     *
     * Called separately from parseJsContent so findings get the MINIFIED_JS source label.
     * Dedup between the two happens at the table model level.
     */
    public static List<ParsedOp> parseMinifiedJsContent(String content) {
        List<ParsedOp> results = new ArrayList<>();
        if (content == null || content.isEmpty()) return results;
        if (content.length() > MAX_JS_SIZE) return results; // skip oversized files

        // 1. Property assignments: a.b = "query Foo { ... }"
        Matcher propMatcher = MINIFIED_PROP_ASSIGN.matcher(content);
        while (propMatcher.find()) {
            String raw = cleanJsArtifacts(unescapeMinified(propMatcher.group(1)));
            results.addAll(parseQueryString(raw, null));
        }

        // 2. Escaped GQL strings: "query GetUser {\\n  user ...}"
        Matcher escapedMatcher = MINIFIED_ESCAPED_GQL.matcher(content);
        while (escapedMatcher.find()) {
            String raw = cleanJsArtifacts(unescapeMinified(escapedMatcher.group(1)));
            if (raw.length() > 15) {
                results.addAll(parseQueryString(raw, null));
            }
        }

        // 3. Compact operations: query Foo{bar{id}}
        // 3. Compact operations in minified JS: query Foo{bar{baz{id}}}
        //    Use GQL_OP_PATTERN to find the start, then extractBalancedOp for the full body.
        //    This handles arbitrarily deep nesting unlike the old [^}] regex.
        Matcher compactMatcher = GQL_OP_PATTERN.matcher(content);
        while (compactMatcher.find()) {
            String opType = compactMatcher.group(1);
            String opName = compactMatcher.group(2);
            // Extract from the operation keyword to the balanced closing brace
            String region = content.substring(compactMatcher.start());
            String fullOp = extractBalancedOp(region);
            String cleaned = cleanJsArtifacts(fullOp);
            results.add(new ParsedOp(opType, opName, null, cleaned));
        }

        // 4. Object literal query fields: query:"mutation Baz($id:ID!){...}"
        Matcher objMatcher = MINIFIED_OBJ_QUERY.matcher(content);
        while (objMatcher.find()) {
            String raw = cleanJsArtifacts(unescapeMinified(objMatcher.group(1)));
            results.addAll(parseQueryString(raw, null));
        }

        // 5. AST body fields: body:"query Foo{...}"
        Matcher locMatcher = MINIFIED_LOC_BODY.matcher(content);
        while (locMatcher.find()) {
            String raw = cleanJsArtifacts(unescapeMinified(locMatcher.group(1)));
            results.addAll(parseQueryString(raw, null));
        }

        // 6. Relay compiled text: text:"query FooQuery{...}"
        Matcher relayMatcher = MINIFIED_RELAY_TEXT.matcher(content);
        while (relayMatcher.find()) {
            String raw = cleanJsArtifacts(unescapeMinified(relayMatcher.group(1)));
            results.addAll(parseQueryString(raw, null));
        }

        // 7. Apollo-style 64-char hex IDs near GraphQL-related context
        Matcher apolloIdMatcher = MINIFIED_APOLLO_ID.matcher(content);
        while (apolloIdMatcher.find()) {
            int pos = apolloIdMatcher.start();
            int contextStart = Math.max(0, pos - 100);
            int contextEnd = Math.min(content.length(), pos + 100);
            String context = content.substring(contextStart, contextEnd);
            if (context.contains("query") || context.contains("mutation") ||
                context.contains("operationName") || context.contains("persistedQuery")) {
                String hash = apolloIdMatcher.group(1);
                Matcher nearbyName = JSON_OP_NAME.matcher(context);
                String opName = nearbyName.find() ? nearbyName.group(1) : "anonymous";
                results.add(new ParsedOp("persisted", opName, hash,
                        "Minified Persisted: " + hash));
            }
        }

        // 8. Relay compiled module nodes: {kind:"Request",name:"FooQuery",id:"hash",text:null}
        //    These appear when relay-compiler pre-compiles operations with persistConfig.
        //    The query text is null (replaced by the id), so we capture the id + name.
        Matcher relayNodeMatcher = RELAY_NODE_ID.matcher(content);
        while (relayNodeMatcher.find()) {
            String name = relayNodeMatcher.group(1) != null ? relayNodeMatcher.group(1) : relayNodeMatcher.group(2);
            String id = relayNodeMatcher.group(3) != null ? relayNodeMatcher.group(3) : relayNodeMatcher.group(4);
            if (name != null && id != null) {
                results.add(new ParsedOp("doc_id", name, id,
                        "Relay doc_id: " + id + " (" + name + ")"));
            }
        }
        // Try reverse order (id before name in the object)
        Matcher relayNodeRevMatcher = RELAY_NODE_ID_REV.matcher(content);
        while (relayNodeRevMatcher.find()) {
            String id = relayNodeRevMatcher.group(1) != null ? relayNodeRevMatcher.group(1) : relayNodeRevMatcher.group(2);
            String name = relayNodeRevMatcher.group(3) != null ? relayNodeRevMatcher.group(3) : relayNodeRevMatcher.group(4);
            if (name != null && id != null) {
                results.add(new ParsedOp("doc_id", name, id,
                        "Relay doc_id: " + id + " (" + name + ")"));
            }
        }

        // 9. Meta's queryID/queryId in JS bundles
        //    Format: queryID:"12345" or queryId:"abc123"
        //    Common in Meta/Facebook/Instagram __d() module definitions
        Matcher metaQueryIdMatcher = META_QUERY_ID.matcher(content);
        while (metaQueryIdMatcher.find()) {
            String queryId = metaQueryIdMatcher.group(1);
            int pos = metaQueryIdMatcher.start();
            // Look for a nearby operation name within 200 chars
            int contextStart = Math.max(0, pos - 200);
            int contextEnd = Math.min(content.length(), pos + 200);
            String context = content.substring(contextStart, contextEnd);
            // Try to find name:"OperationName" or operationName:"..." nearby
            String opName = "anonymous";
            Matcher nameMatcher = Pattern.compile(
                    "(?:name|operationName)\\s*[=:]\\s*\"([A-Za-z_]\\w*)\"").matcher(context);
            if (nameMatcher.find()) {
                opName = nameMatcher.group(1);
            }
            results.add(new ParsedOp("doc_id", opName, queryId,
                    "Meta queryID: " + queryId + " (" + opName + ")"));
        }

        // 10. Meta's doc_id in JS bundles
        //     Format: doc_id:"1234567890" or doc_id:"abc123hash"
        Matcher metaDocIdMatcher = META_DOC_ID_JS.matcher(content);
        while (metaDocIdMatcher.find()) {
            String docId = metaDocIdMatcher.group(1);
            int pos = metaDocIdMatcher.start();
            int contextStart = Math.max(0, pos - 200);
            int contextEnd = Math.min(content.length(), pos + 200);
            String context = content.substring(contextStart, contextEnd);
            String opName = "anonymous";
            Matcher nameMatcher = Pattern.compile(
                    "(?:name|operationName)\\s*[=:]\\s*\"([A-Za-z_]\\w*)\"").matcher(context);
            if (nameMatcher.find()) {
                opName = nameMatcher.group(1);
            }
            results.add(new ParsedOp("doc_id", opName, docId,
                    "Meta doc_id: " + docId + " (" + opName + ")"));
        }

        return results;
    }

    /**
     * Unescape minified JS strings — handles both JSON escapes and
     * literal \\n sequences found in Webpack output.
     */
    private static String unescapeMinified(String s) {
        return s.replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\'", "'")
                .replace("\\\\", "\\");
    }

    /**
     * Extract GraphQL operations from WebSocket text messages.
     * Handles both graphql-ws and subscriptions-transport-ws protocols.
     */
    public static List<ParsedOp> parseWebSocketMessage(String message) {
        List<ParsedOp> results = new ArrayList<>();
        if (message == null || message.isEmpty()) return results;

        // WebSocket GraphQL messages typically have {"type":"...", "payload":{"query":"..."}}
        // We look for the query field anywhere in the message
        Matcher qm = JSON_QUERY_FIELD.matcher(message);
        while (qm.find()) {
            String rawQuery = unescapeJson(qm.group(1));
            String opName = extractJsonOpName(message);
            results.addAll(parseQueryString(rawQuery, opName));
        }

        // Persisted hashes in WS messages
        Matcher hashMatcher = PERSISTED_HASH.matcher(message);
        if (hashMatcher.find()) {
            results.add(new ParsedOp("persisted", extractJsonOpName(message),
                    hashMatcher.group(1), "WS Persisted: " + hashMatcher.group(1)));
        }

        return results;
    }

    // --- Internal helpers ---

    /**
     * Parse a raw GraphQL query string to identify operations.
     */
    static List<ParsedOp> parseQueryString(String query, String fallbackName) {
        List<ParsedOp> ops = new ArrayList<>();
        if (query == null || query.isEmpty()) return ops;

        // Normalize whitespace only — no JS cleanup here.
        // cleanJsArtifacts is called at the JS extraction site, not here,
        // because this method also receives clean queries from HTTP POST/WS.
        String body = query.replaceAll("\\s+", " ").trim();

        // Named operations: query FooBar(...) {
        Matcher named = GQL_OP_PATTERN.matcher(body);
        while (named.find()) {
            ops.add(new ParsedOp(named.group(1), named.group(2), null, body));
        }

        // Fragments: fragment Xyz on Type
        Matcher frag = GQL_FRAGMENT_PATTERN.matcher(body);
        while (frag.find()) {
            ops.add(new ParsedOp("fragment", frag.group(1), null, body));
        }

        // If no named ops found, check for anonymous operations
        if (ops.isEmpty()) {
            Matcher anon = GQL_ANON_PATTERN.matcher(body);
            if (anon.find()) {
                String name = (fallbackName != null && !fallbackName.isEmpty()) ? fallbackName : "anonymous";
                ops.add(new ParsedOp(anon.group(1), name, null, body));
            }
        }

        // Fallback: if body looks like GraphQL but no operation keyword found
        if (ops.isEmpty() && looksLikeGraphQL(body)) {
            String name = (fallbackName != null && !fallbackName.isEmpty()) ? fallbackName : "anonymous";
            ops.add(new ParsedOp("query", name, null, body));
        }

        return ops;
    }

    private static boolean looksLikeGraphQL(String s) {
        // Heuristic: contains { and field-like selections
        return s.contains("{") && s.contains("}") &&
               (s.contains("__typename") || Pattern.compile("\\w+\\s*\\{").matcher(s).find());
    }

    /**
     * Clean JS artifacts from extracted GraphQL operations.
     *
     * Strategy: first strip known JS patterns (concat, interpolation, etc.),
     * then do a final character-level pass that only keeps valid GraphQL tokens.
     *
     * Valid GraphQL consists of:
     *   - Identifiers: a-z A-Z 0-9 _
     *   - Type/variable markers: $ ! @ &
     *   - Structure: { } ( ) [ ] : , ... =
     *   - String literals: "..." (preserved as-is)
     *   - Numeric literals: digits, -, .
     *   - Whitespace (collapsed later)
     *
     * Everything else (JS operators, function calls, ternaries, semicolons,
     * template syntax, property access chains not part of GQL) gets stripped.
     */

    static String cleanJsArtifacts(String s) {
        if (s == null || s.isEmpty()) return s;

        String result = s;

        // Phase 1: Remove .concat(...) calls — extract string literal content only
        if (result.contains(".concat(")) {
            result = removeConcat(result);
        }

        // Phase 2: Remove JS string concatenation operators
        //   "..." + variable + "..."  →  "..." "..."
        //   "..." + functionCall() + "..."  →  "..." "..."
        result = result.replaceAll("\"\\s*\\+\\s*[a-zA-Z_$][a-zA-Z0-9_$.]*(?:\\([^)]*\\))?\\s*\\+\\s*\"", " ");
        result = result.replaceAll("\"\\s*\\+\\s*[a-zA-Z_$][a-zA-Z0-9_$.]*(?:\\([^)]*\\))?\\s*", " ");
        result = result.replaceAll("\\s*\\+\\s*\"", " ");

        // Phase 3: Remove template literal interpolations: ${...}
        result = result.replaceAll("\\$\\{[^}]*\\}", "");

        // Phase 4: Remove JS ternary expressions: condition ? value : fallback
        //   Catches patterns like:  n.includes("STAY")?y:""
        result = result.replaceAll(
                "[a-zA-Z_$][a-zA-Z0-9_$.]*(?:\\([^)]*\\))?\\s*\\?\\s*[a-zA-Z_$][a-zA-Z0-9_$]*\\s*:\\s*(?:\"[^\"]*\"|[a-zA-Z_$][a-zA-Z0-9_$]*)",
                "");

        // Phase 5: Unescape JSON/JS string escapes
        result = result.replace("\\n", "\n");
        result = result.replace("\\r", "\r");
        result = result.replace("\\t", "\t");
        result = result.replace("\\\"", "\"");
        result = result.replace("\\'", "'");
        result = result.replace("\\\\", "\\");

        // Phase 6: Character-level GraphQL sanitizer
        // Walk the string and keep only characters that are valid in GraphQL.
        // This is the catch-all that removes anything the above phases missed.
        result = sanitizeToGraphQL(result);

        // Phase 7: Trim to the last balanced brace
        int lastBrace = findLastBalancedBrace(result);
        if (lastBrace > 0 && lastBrace < result.length() - 1) {
            result = result.substring(0, lastBrace + 1);
        }

        // Phase 8: Collapse whitespace
        return normalizeWhitespace(result);
    }

    /**
     * Character-level sanitizer that only keeps valid GraphQL tokens.
     *
     * Walks through the string preserving:
     *   - GraphQL identifiers: letters, digits, underscores
     *   - GraphQL punctuation: { } ( ) [ ] : , ! $ @ = |
     *   - Spread operator: ...
     *   - String literals: "..." including escaped content inside
     *   - Numeric signs: - . (when adjacent to digits)
     *   - Whitespace (collapsed to single spaces later)
     *   - GraphQL comments: # to end of line (preserved then stripped)
     *
     * Strips:
     *   - JS operators: + * / % ^ ~ & | && || => === !== == != < > <= >=
     *   - JS punctuation: ; ` ' (backtick, single quote outside strings)
     *   - JS keywords/calls that survived earlier phases
     *   - Any non-ASCII characters
     *   - Dangling quotes not part of balanced string literals
     */
    private static String sanitizeToGraphQL(String s) {
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        int len = s.length();

        while (i < len) {
            char c = s.charAt(i);

            // Whitespace — keep (collapsed later)
            if (Character.isWhitespace(c)) {
                out.append(' ');
                i++;
                continue;
            }

            // String literals — preserve entire "..." blocks
            if (c == '"') {
                int end = findClosingQuote(s, i);
                if (end > i) {
                    out.append(s, i, end + 1);
                    i = end + 1;
                } else {
                    // Unmatched quote — skip it
                    i++;
                }
                continue;
            }

            // Identifiers: letters, digits, underscore
            if (Character.isLetterOrDigit(c) || c == '_') {
                // Collect the full identifier/number token
                int start = i;
                while (i < len && (Character.isLetterOrDigit(s.charAt(i)) || s.charAt(i) == '_')) {
                    i++;
                }
                String token = s.substring(start, i);

                // Filter out JS-only keywords that can't appear in GraphQL
                if (isJsOnlyKeyword(token)) {
                    // Skip this token entirely
                    continue;
                }

                out.append(token);
                continue;
            }

            // GraphQL structural punctuation
            if (c == '{' || c == '}' || c == '(' || c == ')' ||
                c == '[' || c == ']' || c == ':' || c == ',' ||
                c == '!' || c == '$' || c == '@' || c == '=') {
                out.append(c);
                i++;
                continue;
            }

            // Spread operator: ...
            if (c == '.' && i + 2 < len && s.charAt(i + 1) == '.' && s.charAt(i + 2) == '.') {
                out.append("...");
                i += 3;
                continue;
            }

            // Minus sign (for negative numbers in default values)
            if (c == '-' && i + 1 < len && Character.isDigit(s.charAt(i + 1))) {
                out.append(c);
                i++;
                continue;
            }

            // Decimal point (for float values)
            if (c == '.' && i + 1 < len && Character.isDigit(s.charAt(i + 1))) {
                out.append(c);
                i++;
                continue;
            }

            // Pipe for union types
            if (c == '|') {
                out.append(c);
                i++;
                continue;
            }

            // GraphQL comment: # to end of line — strip entirely
            if (c == '#') {
                while (i < len && s.charAt(i) != '\n') i++;
                continue;
            }

            // Everything else is JS noise — skip it
            i++;
        }

        return out.toString();
    }

    /**
     * Find the closing quote for a string literal starting at position i.
     * Handles escaped quotes (\\") inside the string.
     */
    private static int findClosingQuote(String s, int openPos) {
        int i = openPos + 1;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                i += 2; // skip escaped char
                continue;
            }
            if (c == '"') return i;
            i++;
        }
        return -1; // unmatched
    }

    /**
     * Returns true for tokens that are JS-only keywords and can never
     * appear as identifiers in valid GraphQL.
     *
     * Does NOT flag GraphQL keywords (query, mutation, fragment, on, true,
     * false, null, type, input, enum, interface, union, scalar, schema,
     * extend, implements, directive, repeatable) nor common field names.
     */
    /**
     * Returns true for tokens that are JS-only and extremely unlikely to appear
     * as valid identifiers in a GraphQL executable document (query/mutation).
     *
     * CONSERVATIVE approach: In GraphQL, ANY identifier can be a field name,
     * argument name, type name, or enum value. Words like "filter", "values",
     * "keys", "delete", "error", "length" are all legitimate field names.
     *
     * We ONLY block tokens that:
     *   1. Are JS control flow / declaration keywords (var, let, const, function, etc.)
     *   2. Cannot plausibly be field/type names in a GraphQL schema
     *   3. Appear constantly in Webpack/Rollup/Vite bundler output
     *
     * Validated against GraphQL spec (draft / Oct 2021):
     *   - Built-in scalars NOT blocked: Int, Float, String, Boolean, ID
     *   - Common custom scalars NOT blocked: JSON, Date, DateTime, Object, Array, etc.
     *   - Common field names NOT blocked: filter, values, keys, length, error,
     *     delete, status, type, name, id, map, set, result, data, etc.
     */
    private static boolean isJsOnlyKeyword(String token) {
        switch (token) {
            // JS declaration / control flow — never valid GQL field names in practice
            case "var": case "let": case "const":
            case "function": case "return":
            case "for": case "while": case "do":
            case "switch": case "case": case "break": case "continue":
            case "try": case "catch": case "finally": case "throw":
            case "typeof": case "instanceof":
            case "void": case "yield": case "await": case "async":
            case "super": case "this":
            case "import": case "export": case "from":
            case "with":
            // JS runtime / bundler identifiers — never GQL content
            case "require": case "module": case "exports":
            case "define": case "webpack": case "webpackJsonp":
            case "prototype": case "constructor":
            case "__esModule": case "__webpack_require__":
            case "createElement": case "appendChild":
            case "addEventListener": case "removeEventListener":
            case "setTimeout": case "setInterval":
            case "encodeURIComponent": case "decodeURIComponent":
            case "hasOwnProperty": case "isPrototypeOf":
            case "console": case "window": case "document":
            case "localStorage": case "sessionStorage":
            case "XMLHttpRequest":
                return true;
            default:
                return false;
        }
    }

    /**
     * Remove .concat(...) calls, handling nested parentheses correctly.
     * Extracts only string literal content from within the concat args
     * and discards variable references, ternaries, and function calls.
     */
    private static String removeConcat(String s) {
        StringBuilder out = new StringBuilder();
        int i = 0;

        while (i < s.length()) {
            // Look for .concat(
            int concatStart = s.indexOf(".concat(", i);
            if (concatStart < 0) {
                out.append(s, i, s.length());
                break;
            }

            // Append everything before .concat(
            out.append(s, i, concatStart);

            // Find the matching closing paren, tracking nesting depth
            int parenStart = concatStart + 8; // length of ".concat("
            int depth = 1;
            int parenEnd = parenStart;

            while (parenEnd < s.length() && depth > 0) {
                char c = s.charAt(parenEnd);
                if (c == '(') depth++;
                else if (c == ')') depth--;
                parenEnd++;
            }

            // Extract the content inside .concat(...)
            String args = s.substring(parenStart, parenEnd - 1);

            // Pull out only string literal content from the args
            // Match "..." sequences, handling escaped quotes
            Matcher strLit = Pattern.compile("\"((?:[^\"\\\\]++|\\\\.)++)\"").matcher(args);
            while (strLit.find()) {
                String lit = strLit.group(1);
                // Skip empty strings and pure-whitespace strings
                // but keep strings that have GraphQL content (field names, braces)
                if (!lit.isEmpty()) {
                    out.append(lit);
                }
            }

            i = parenEnd;
        }

        return out.toString();
    }

    /**
     * Collapse multiple whitespace/newlines into single spaces, trim.
     */
    private static String normalizeWhitespace(String s) {
        return s.replaceAll("\\s+", " ").trim();
    }

    /**
     * Find the position of the last } that closes the outermost balanced block.
     * Returns -1 if braces are not balanced (prevents incorrect trimming).
     */
    private static int findLastBalancedBrace(String s) {
        int depth = 0;
        int lastClose = -1;
        boolean everOpened = false;

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '{') { depth++; everOpened = true; }
            else if (c == '}') {
                depth--;
                if (depth == 0) lastClose = i;
                // Depth went negative — more } than { — braces are broken
                if (depth < 0) return -1;
            }
        }

        // If we never opened a brace, or if braces aren't balanced at the end,
        // don't trim — return -1 so the caller skips the trim
        if (!everOpened || depth != 0) return -1;

        return lastClose;
    }

    /**
     * Extract a full GraphQL operation by tracking balanced braces.
     * Given a string starting with "query Foo {", walks forward until
     * all braces are balanced, returning the complete operation.
     */
    private static String extractBalancedOp(String region) {
        int depth = 0;
        boolean started = false;
        int end = region.length();

        for (int i = 0; i < region.length(); i++) {
            char c = region.charAt(i);
            if (c == '{') {
                depth++;
                started = true;
            } else if (c == '}') {
                depth--;
                if (started && depth == 0) {
                    end = i + 1;
                    break;
                }
            }
        }

        return region.substring(0, end);
    }

    private static String extractJsonOpName(String json) {
        Matcher m = JSON_OP_NAME.matcher(json);
        return m.find() ? m.group(1) : "";
    }

    private static String unescapeJson(String s) {
        return s.replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }

    private static String urlDecode(String s) {
        try {
            return java.net.URLDecoder.decode(s, "UTF-8");
        } catch (Exception e) {
            return s;
        }
    }

    /**
     * Result of parsing a single operation.
     */
    public static class ParsedOp {
        public final String type;      // query, mutation, subscription, fragment, persisted
        public final String name;
        public final String hash;      // non-null for persisted queries
        public final String snippet;

        public ParsedOp(String type, String name, String hash, String snippet) {
            this.type = type;
            this.name = (name == null || name.isEmpty()) ? "anonymous" : name;
            this.hash = hash;
            this.snippet = snippet;
        }
    }
}
