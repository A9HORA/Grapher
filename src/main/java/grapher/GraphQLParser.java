package grapher;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
    // Matches gql`...`, graphql`...`, and minified aliases like kr.J1`...`, e.Jh`...`
    private static final Pattern JS_GQL_TAG = Pattern.compile(
            "(?:gql|graphql|[a-zA-Z_$][a-zA-Z0-9_$]*\\.[A-Za-z_$][A-Za-z0-9_$]*)\\s*`([^`]{10,}+)`",
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
            "[a-zA-Z_$][a-zA-Z0-9_$.]*\\s*=\\s*\"((?:query|mutation|subscription|fragment|\\.\\.\\.)(?:[^\"\\\\]++|\\\\.)++)\"",
            Pattern.DOTALL
    );

    private static final Pattern MINIFIED_ESCAPED_GQL = Pattern.compile(
            "\"((?:query|mutation|subscription|fragment)\\s+[A-Za-z_]\\w*(?:[^\"\\\\]++|\\\\.)++)\"",
            Pattern.DOTALL
    );

    // Compact operations in minified JS — detects tightly packed operations
    // like query Foo{bar{id}}. The [^}] capture stops at the first }, but
    // we re-extract using extractBalancedOp for proper nested brace handling.
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
    private static final int MAX_JS_SIZE = 15 * 1024 * 1024;

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
            List<String> batchItems = splitJsonArray(body.trim());
            for (String item : batchItems) {
                Matcher qmBatch = JSON_QUERY_FIELD.matcher(item);
                while (qmBatch.find()) {
                    String rawQuery = unescapeJson(qmBatch.group(1));
                    String opName = extractJsonOpName(item);
                    results.addAll(parseQueryString(rawQuery, opName));
                }
                // Also check batched doc_id requests
                Matcher docIdBatch = JSON_DOC_ID.matcher(item);
                if (docIdBatch.find()) {
                    String docId = docIdBatch.group(1);
                    String opName = extractJsonOpName(item);
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

        // Tagged template literals: gql`...`, graphql`...`, or minified aliases like kr.J1`...`
        // Build position-aware map for resolving ${varName} interpolations
        // (handles Webpack module scope collisions where single-letter vars are reused)
        Map<String, java.util.List<int[]>> templatePosMap = buildStringVarMapPositioned(content);

        // Also build a map of variable assignments to tagged template literals:
        // const Ia = gql`...`  →  Ia is the query var name
        // Used to find call sites: {query: Ia, variables: {...}}
        Pattern queryVarAssign = Pattern.compile(
                "(?:var|let|const|,)\\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\\s*=\\s*" +
                "(?:gql|graphql|[a-zA-Z_$][a-zA-Z0-9_$]*\\.[A-Za-z_$][A-Za-z0-9_$]*)\\s*`");

        Matcher tagMatcher = JS_GQL_TAG.matcher(content);
        while (tagMatcher.find()) {
            String rawBody = tagMatcher.group(1);
            int matchPos = tagMatcher.start();
            // Resolve ${varName} interpolations using position-aware lookup
            String resolved = resolveTemplateInterpolationsPositioned(rawBody, matchPos, templatePosMap, content);
            String gqlBody = cleanJsArtifacts(resolved);
            // Validate: the resolved content must contain a GraphQL operation keyword
            // to avoid false positives from non-gql backtick templates (CSS, HTML, etc.)
            String trimmed = gqlBody.replaceAll("\\s+", " ").trim();
            boolean hasGqlKeyword = trimmed.matches("(?s).*\\b(query|mutation|subscription|fragment)\\s+\\w+.*");
            if (trimmed.length() > 15 && hasGqlKeyword) {
                // Try to find the variable name this template is assigned to
                // so we can locate the call site: {query: varName, variables: {...}}
                String queryVarName = null;
                // Look backwards from the match for an assignment pattern
                int searchStart = Math.max(0, matchPos - 200);
                String prefix = content.substring(searchStart, matchPos);
                Matcher assignMatcher = queryVarAssign.matcher(prefix);
                while (assignMatcher.find()) queryVarName = assignMatcher.group(1); // last match wins

                // Extract call site variables if we found an assignment
                String callSiteVars = null;
                if (queryVarName != null) {
                    callSiteVars = extractCallSiteVariables(content, queryVarName, gqlBody);
                }

                List<ParsedOp> parsed = parseQueryString(gqlBody, null);
                if (callSiteVars != null) {
                    // Attach extracted variables to each parsed op
                    final String finalCallSiteVars = callSiteVars;
                    List<ParsedOp> enriched = new ArrayList<>();
                    for (ParsedOp op : parsed) {
                        enriched.add(new ParsedOp(op.type, op.name, op.hash, op.snippet, finalCallSiteVars));
                    }
                    results.addAll(enriched);
                } else {
                    results.addAll(parsed);
                }
            }
        }

        // Raw query/mutation/subscription declarations in JS strings
        Matcher rawMatcher = JS_GQL_STRING.matcher(content);
        while (rawMatcher.find()) {
            // Cap region to 50K to prevent extractBalancedOp from walking megabytes
            int regionEnd = Math.min(content.length(), rawMatcher.start() + 50000);
            String region = content.substring(rawMatcher.start(), regionEnd);
            String fullOp = extractBalancedOp(region);
            String cleaned = cleanJsArtifacts(fullOp);

            // Try to find the variable name this query is assigned to.
            // Covers plain template literals: const Ia = `query Foo ...`
            // and string assignments: var T = "query Foo ..."
            String queryVarName = null;
            int searchStart = Math.max(0, rawMatcher.start() - 200);
            String prefix = content.substring(searchStart, rawMatcher.start());
            // Match: varName = ` or varName = " (looking backwards from the query start)
            java.util.regex.Matcher varAssign = Pattern.compile(
                    "(?:var|let|const|,)\\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\\s*=\\s*[`\"]\\s*$")
                    .matcher(prefix);
            if (varAssign.find()) {
                queryVarName = varAssign.group(1);
            }

            String callSiteVars = null;
            if (queryVarName != null) {
                callSiteVars = extractCallSiteVariables(content, queryVarName, cleaned);
            }

            List<ParsedOp> parsed = parseQueryString(cleaned, null);
            if (callSiteVars != null && !parsed.isEmpty()) {
                List<ParsedOp> enriched = new ArrayList<>();
                for (ParsedOp op : parsed) {
                    enriched.add(new ParsedOp(op.type, op.name, op.hash, op.snippet, callSiteVars));
                }
                results.addAll(enriched);
            } else {
                results.addAll(parsed);
            }
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

        // Build position-aware variable map for resolving .concat() variable references
        // Handles Webpack module scope collisions (same single-letter var reused across modules)
        Map<String, java.util.List<int[]>> posVarMap = buildStringVarMapPositioned(content);

        // 0. Query strings followed by .concat() chains (e.g. inside JSON.stringify)
        //    Matches: "query Foo(...) { ... ".concat(cond ? y : "").concat(...)
        Pattern queryConcat = Pattern.compile(
                "\"((?:[^\"\\\\]++|\\\\.)++)\"\\s*\\.concat\\s*\\(", Pattern.DOTALL);
        Matcher concatMatcher = queryConcat.matcher(content);
        while (concatMatcher.find()) {
            String baseStr = unescapeMinified(concatMatcher.group(1));
            // Only process if the base string looks like a GraphQL query start
            String baseTrimmed = baseStr.replaceAll("\\s+", " ").trim();
            if (!baseTrimmed.matches("(?s).*\\b(query|mutation|subscription)\\s+\\w+.*")) continue;

            // Walk the .concat() chain
            String fullQuery = baseStr;
            int concatPos = concatMatcher.start() + concatMatcher.group(0).indexOf(".concat(");
            int pos = concatPos;

            while (pos < content.length()) {
                // Match .concat(
                if (pos + 8 > content.length()) break;
                int scanEnd = Math.min(pos + 20, content.length());
                java.util.regex.Matcher cm = Pattern.compile("^\\.concat\\s*\\(")
                        .matcher(content.substring(pos, scanEnd));
                if (!cm.find()) break;

                pos += cm.group().length();

                // Find matching closing paren (handle nested parens and strings)
                int depth = 1;
                int argStart = pos;
                while (pos < content.length() && depth > 0) {
                    char ch = content.charAt(pos);
                    if (ch == '(') depth++;
                    else if (ch == ')') depth--;
                    else if (ch == '"') {
                        pos++;
                        while (pos < content.length() && content.charAt(pos) != '"') {
                            if (content.charAt(pos) == '\\' && pos + 1 < content.length()) pos++;
                            pos++;
                        }
                    }
                    pos++;
                }

                String concatArg = content.substring(argStart, pos - 1).trim();
                // .concat() can take multiple arguments: .concat(arg1, arg2, arg3)
                // Split by top-level commas and resolve each argument separately
                List<String> concatArgs = splitConcatArgs(concatArg);
                for (String singleArg : concatArgs) {
                    fullQuery += resolveConcatArgPositioned(singleArg.trim(), concatPos, posVarMap, content);
                }
            }

            String cleaned = fullQuery.replaceAll("\\s+", " ").trim();
            if (cleaned.length() > 20) {
                results.addAll(parseQueryString(cleaned, null));
            }
        }

        // 1. Property assignments: a.b = "query Foo { ... }"
        //    Also search for call site: {query: varName, variables: {...}}
        Pattern propAssignWithVarName = Pattern.compile(
                "([a-zA-Z_$][a-zA-Z0-9_$.]*)\\s*=\\s*\"((?:query|mutation|subscription|fragment|\\.\\.\\.)(?:[^\"\\\\]++|\\\\.)++)\"",
                Pattern.DOTALL);
        Matcher propMatcher = propAssignWithVarName.matcher(content);
        while (propMatcher.find()) {
            String assignedVarName = propMatcher.group(1);
            // Strip property access — if "a.b = ...", the variable name is just "b" (last segment)
            // But for call site search we need the full name as it appears in query: <name>
            String callSiteKey = assignedVarName.contains(".")
                    ? assignedVarName.substring(assignedVarName.lastIndexOf('.') + 1)
                    : assignedVarName;
            String raw = cleanJsArtifacts(unescapeMinified(propMatcher.group(2)));
            List<ParsedOp> parsed = parseQueryString(raw, null);
            if (!parsed.isEmpty()) {
                String callSiteVars = extractCallSiteVariables(content, callSiteKey, raw);
                if (callSiteVars != null) {
                    List<ParsedOp> enriched = new ArrayList<>();
                    for (ParsedOp op : parsed) {
                        enriched.add(new ParsedOp(op.type, op.name, op.hash, op.snippet, callSiteVars));
                    }
                    results.addAll(enriched);
                } else {
                    results.addAll(parsed);
                }
            }
        }

        // 2. Escaped GQL strings: "query GetUser {\\n  user ...}"
        Matcher escapedMatcher = MINIFIED_ESCAPED_GQL.matcher(content);
        while (escapedMatcher.find()) {
            String raw = cleanJsArtifacts(unescapeMinified(escapedMatcher.group(1)));
            if (raw.length() > 15) {
                results.addAll(parseQueryString(raw, null));
            }
        }

        // 3. Compact operations in minified JS: query Foo{bar{baz{id}}}
        //    Uses MINIFIED_COMPACT_OP for initial detection (ensures the operation
        //    keyword is immediately followed by name and opening brace — filters out
        //    JS variables named "query" that aren't GraphQL operations).
        //    Then uses extractBalancedOp for proper nested brace handling.
        Matcher compactMatcher = MINIFIED_COMPACT_OP.matcher(content);
        while (compactMatcher.find()) {
            String opType = compactMatcher.group(1);
            String opName = compactMatcher.group(2);
            // Re-extract from the match start with balanced braces for full nesting
            int regionEnd = Math.min(content.length(), compactMatcher.start() + 50000);
            String region = content.substring(compactMatcher.start(), regionEnd);
            String fullOp = extractBalancedOp(region);
            if (fullOp.length() > 15) {
                String cleaned = cleanJsArtifacts(fullOp);
                if (cleaned.length() > 15) {
                    results.add(new ParsedOp(opType, opName, null, cleaned));
                }
            }
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

        // Inline fragments: ... on TypeName { ... }
        // These appear as standalone variable values in minified JS bundles
        // when queries are dynamically assembled via .concat()
        if (ops.isEmpty() && body.startsWith("...")) {
            Matcher inlineFrag = Pattern.compile(
                    "\\.\\.\\.\\s+on\\s+([A-Za-z_]\\w*)").matcher(body);
            if (inlineFrag.find()) {
                ops.add(new ParsedOp("fragment", inlineFrag.group(1), null, body));
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
     * Returns true for tokens that are JS-only and extremely unlikely to appear
     * as valid identifiers in a GraphQL executable document.
     *
     * CONSERVATIVE approach validated against GraphQL spec (draft / Oct 2021):
     *   - Built-in scalars NOT blocked: Int, Float, String, Boolean, ID
     *   - Common custom scalars NOT blocked: JSON, Date, DateTime, Object, Array
     *   - Common field names NOT blocked: filter, values, keys, length, error,
     *     delete, status, type, name, id, map, set, result, data, etc.
     *   - Only JS control flow / bundler identifiers are blocked.
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

    /**
     * Extract a balanced { ... } or [ ... ] block starting at position pos.
     * String-aware — skips quoted content to avoid false brace matching.
     */
    private static String extractBalancedBlock(String s, int pos) {
        if (pos >= s.length()) return null;
        char open = s.charAt(pos);
        if (open != '{' && open != '[') return null;
        char close = open == '{' ? '}' : ']';

        int depth = 0;
        boolean inString = false;
        int start = pos;

        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (inString) {
                if (c == '\\' && pos + 1 < s.length()) { pos += 2; continue; }
                if (c == '"' || c == '\'') inString = false;
                pos++;
                continue;
            }
            if (c == '"' || c == '\'') { inString = true; pos++; continue; }
            if (c == open) depth++;
            else if (c == close) {
                depth--;
                if (depth == 0) return s.substring(start, pos + 1);
            }
            pos++;
        }
        return null; // unbalanced
    }

    private static String extractJsonOpName(String json) {
        Matcher m = JSON_OP_NAME.matcher(json);
        return m.find() ? m.group(1) : "";
    }

    /**
     * Split a JSON array string into its top-level elements.
     * Uses brace/bracket depth tracking and string awareness to correctly
     * handle elements that contain }, { inside string values.
     *
     * Input:  [{"query":"..."}, {"query":"..."}]
     * Output: ["{"query":"..."}", "{"query":"..."}"]
     */
    private static List<String> splitJsonArray(String json) {
        List<String> items = new ArrayList<>();
        if (json == null || json.isEmpty()) return items;

        // Strip outer [ ]
        int start = json.indexOf('[');
        int end = json.lastIndexOf(']');
        if (start < 0 || end <= start) return items;

        String inner = json.substring(start + 1, end).trim();
        if (inner.isEmpty()) return items;

        int depth = 0;
        boolean inString = false;
        int itemStart = 0;

        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);

            if (inString) {
                if (c == '\\' && i + 1 < inner.length()) {
                    i++; // skip escaped char
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }

            if (c == '"') {
                inString = true;
            } else if (c == '{' || c == '[') {
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;
            } else if (c == ',' && depth == 0) {
                // Top-level comma — split point
                String item = inner.substring(itemStart, i).trim();
                if (!item.isEmpty()) {
                    items.add(item);
                }
                itemStart = i + 1;
            }
        }

        // Last item
        String lastItem = inner.substring(itemStart).trim();
        if (!lastItem.isEmpty()) {
            items.add(lastItem);
        }

        return items;
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
     * Split .concat() arguments by top-level commas.
     * Handles: .concat(ternary ? a : b, "literal", varRef)
     * String-aware and depth-tracked to avoid splitting inside nested expressions.
     */
    private static List<String> splitConcatArgs(String args) {
        List<String> result = new ArrayList<>();
        int depth = 0;
        boolean inString = false;
        char stringChar = 0;
        int start = 0;

        for (int i = 0; i < args.length(); i++) {
            char c = args.charAt(i);
            if (inString) {
                if (c == '\\' && i + 1 < args.length()) { i++; continue; }
                if (c == stringChar) inString = false;
                continue;
            }
            if (c == '"' || c == '\'') { inString = true; stringChar = c; continue; }
            if (c == '(' || c == '[' || c == '{') depth++;
            else if (c == ')' || c == ']' || c == '}') depth--;
            else if (c == ',' && depth == 0) {
                String arg = args.substring(start, i).trim();
                if (!arg.isEmpty()) result.add(arg);
                start = i + 1;
            }
        }
        String last = args.substring(start).trim();
        if (!last.isEmpty()) result.add(last);
        return result;
    }

    /**
     * Resolve a .concat() argument using position-aware variable lookups.
     * Picks the variable assignment closest to the usage site to handle
     * Webpack module scope collisions (e.g., y="fragment" in module A vs y="PARTNER_LOC" in module B).
     */
    private static String resolveConcatArgPositioned(String arg, int usagePos,
                                                      Map<String, java.util.List<int[]>> posMap,
                                                      String content) {
        String trimmed = arg.trim();

        // Case 1: String literal "..."
        java.util.regex.Matcher strMatch = Pattern.compile("^\"((?:[^\"\\\\]|\\\\.)*)\"$").matcher(trimmed);
        if (strMatch.find()) {
            return unescapeMinified(strMatch.group(1));
        }

        // Case 2: Ternary expression
        int questionPos = -1;
        int colonPos = -1;
        int depth = 0;
        for (int i = 0; i < trimmed.length(); i++) {
            char ch = trimmed.charAt(i);
            if (ch == '(' || ch == '[') depth++;
            else if (ch == ')' || ch == ']') depth--;
            else if (ch == '"') {
                i++;
                while (i < trimmed.length() && trimmed.charAt(i) != '"') {
                    if (trimmed.charAt(i) == '\\') i++;
                    i++;
                }
            } else if (ch == '?' && depth == 0 && questionPos < 0) {
                questionPos = i;
            } else if (ch == ':' && depth == 0 && questionPos >= 0) {
                colonPos = i;
                break;
            }
        }

        if (questionPos >= 0 && colonPos > questionPos) {
            String truthy = trimmed.substring(questionPos + 1, colonPos).trim();
            String falsy = trimmed.substring(colonPos + 1).trim();

            String truthyVal = resolveSimpleValuePositioned(truthy, usagePos, posMap, content);
            String falsyVal = resolveSimpleValuePositioned(falsy, usagePos, posMap, content);

            StringBuilder sb = new StringBuilder();
            if (truthyVal != null && !truthyVal.isEmpty()) sb.append(truthyVal);
            if (falsyVal != null && !falsyVal.isEmpty()) sb.append(falsyVal);
            return sb.toString();
        }

        // Case 3: Simple variable reference
        String val = resolveSimpleValuePositioned(trimmed, usagePos, posMap, content);
        return val != null ? val : "";
    }

    /**
     * Resolve a simple value using position-aware variable lookup.
     */
    private static String resolveSimpleValuePositioned(String expr, int usagePos,
                                                        Map<String, java.util.List<int[]>> posMap,
                                                        String content) {
        String trimmed = expr.trim();
        if (trimmed.isEmpty()) return "";

        // String literal
        java.util.regex.Matcher strMatch = Pattern.compile("^\"((?:[^\"\\\\]|\\\\.)*)\"$").matcher(trimmed);
        if (strMatch.find()) {
            return unescapeMinified(strMatch.group(1));
        }

        // Variable reference — use position-aware lookup
        if (trimmed.matches("[a-zA-Z_$][a-zA-Z0-9_$]*")) {
            return resolveVarAtPosition(trimmed, usagePos, posMap, content);
        }

        return "";
    }

    /**
     * Resolve a .concat() argument using a simple (non-position-aware) variable map.
     * Used by contexts where position tracking isn't available.
     *   - String literals: "..."
     *   - Variable references: varName → lookup in map
     *   - Ternary with empty fallback: cond ? varName : "" → include varName's value
     *   - Ternary with two non-empty sides: cond ? a : b → include both values
     */
    private static String resolveConcatArgJava(String arg, Map<String, String> varMap) {
        String trimmed = arg.trim();

        // Case 1: String literal "..."
        java.util.regex.Matcher strMatch = Pattern.compile("^\"((?:[^\"\\\\]|\\\\.)*)\"$").matcher(trimmed);
        if (strMatch.find()) {
            return unescapeMinified(strMatch.group(1));
        }

        // Case 2: Ternary expression — find ? and : at depth 0
        int questionPos = -1;
        int colonPos = -1;
        int depth = 0;
        for (int i = 0; i < trimmed.length(); i++) {
            char ch = trimmed.charAt(i);
            if (ch == '(' || ch == '[') depth++;
            else if (ch == ')' || ch == ']') depth--;
            else if (ch == '"') {
                i++;
                while (i < trimmed.length() && trimmed.charAt(i) != '"') {
                    if (trimmed.charAt(i) == '\\') i++;
                    i++;
                }
            } else if (ch == '?' && depth == 0 && questionPos < 0) {
                questionPos = i;
            } else if (ch == ':' && depth == 0 && questionPos >= 0) {
                colonPos = i;
                break;
            }
        }

        if (questionPos >= 0 && colonPos > questionPos) {
            String truthy = trimmed.substring(questionPos + 1, colonPos).trim();
            String falsy = trimmed.substring(colonPos + 1).trim();

            String truthyVal = resolveSimpleValue(truthy, varMap);
            String falsyVal = resolveSimpleValue(falsy, varMap);

            // Include all non-empty values (additive: both branches contribute)
            StringBuilder sb = new StringBuilder();
            if (truthyVal != null && !truthyVal.isEmpty()) sb.append(truthyVal);
            if (falsyVal != null && !falsyVal.isEmpty()) sb.append(falsyVal);
            return sb.toString();
        }

        // Case 3: Simple variable reference
        String val = resolveSimpleValue(trimmed, varMap);
        return val != null ? val : "";
    }

    /**
     * Resolve a simple value expression — either a string literal or a variable name.
     */
    private static String resolveSimpleValue(String expr, Map<String, String> varMap) {
        String trimmed = expr.trim();
        if (trimmed.isEmpty()) return "";

        // String literal
        java.util.regex.Matcher strMatch = Pattern.compile("^\"((?:[^\"\\\\]|\\\\.)*)\"$").matcher(trimmed);
        if (strMatch.find()) {
            return unescapeMinified(strMatch.group(1));
        }

        // Variable reference
        if (trimmed.matches("[a-zA-Z_$][a-zA-Z0-9_$]*") && varMap.containsKey(trimmed)) {
            return varMap.get(trimmed);
        }

        return "";
    }

    /**
     * Scan an entire JS file for a {query: varName, variables: {...}} call site
     * and extract the variables object as a normalized JSON string.
     *
     * This allows Grapher to send structurally correct variables (e.g.,
     * {"limit": 1, "upcomingOnly": true}) instead of null/placeholder guesses.
     *
     * Handles both module-level constants and function-local assignments.
     * Uses the query variable name (e.g., "Ia", "T", "GET_USER") as the search key.
     *
     * @param content  the full JS file content
     * @param queryVarName  the variable name that holds the query string (e.g., "Ia")
     * @param operationSignature  the operation body (for fallback type-based placeholders)
     * @return normalized JSON variables string, or null if no call site found
     */
    static String extractCallSiteVariables(String content, String queryVarName,
                                            String operationSignature) {
        if (queryVarName == null || queryVarName.isEmpty()) return null;

        // Match: {query: varName, ...} or {query:varName,...}
        // The variables key may appear before or after query in the object.
        // Strategy: find "query" followed by varName, then scan the enclosing object
        // for a "variables" key, then extract the balanced {...} or [...] value.
        Pattern callSitePattern = Pattern.compile(
                "\\{[^{}]{0,500}?\\bquery\\s*:\\s*" + java.util.regex.Pattern.quote(queryVarName) + "\\b");
        Matcher m = callSitePattern.matcher(content);

        while (m.find()) {
            // Find the full enclosing object starting at m.start()
            String region = content.substring(m.start());
            String fullObj = extractBalancedBlock(region, 0);
            if (fullObj == null) continue;

            // Look for "variables" key in this object
            int varPos = findKeyInObject(fullObj, "variables");
            if (varPos < 0) continue;

            // Find the value after the colon
            int colonPos = fullObj.indexOf(':', varPos);
            if (colonPos < 0) continue;

            int valueStart = colonPos + 1;
            while (valueStart < fullObj.length() &&
                   Character.isWhitespace(fullObj.charAt(valueStart))) valueStart++;
            if (valueStart >= fullObj.length()) continue;

            char firstChar = fullObj.charAt(valueStart);
            if (firstChar == '{' || firstChar == '[') {
                // Extract the balanced object/array
                String rawVars = extractBalancedBlock(fullObj, valueStart);
                if (rawVars == null) continue;

                // Normalize JS values to JSON
                String normalized = normalizeJsObjectToJson(rawVars, operationSignature);
                if (normalized != null && !normalized.isEmpty() &&
                    !normalized.equals("{}") && !normalized.equals("null")) {
                    return normalized;
                }
            }
        }
        return null;
    }

    /**
     * Find the position of a key in a JS object literal.
     * Only matches at depth 1 to avoid nested keys with the same name.
     */
    private static int findKeyInObject(String obj, String key) {
        String target1 = "\"" + key + "\"";
        String target2 = key + ":";  // unquoted key (common in minified code)
        int depth = 0;
        boolean inString = false;

        for (int i = 0; i < obj.length(); i++) {
            char c = obj.charAt(i);
            if (inString) {
                if (c == '\\' && i + 1 < obj.length()) i++;
                else if (c == '"') inString = false;
                continue;
            }
            if (c == '"') {
                if (depth == 1 && obj.startsWith(target1, i)) return i;
                inString = true;
            } else if (c == '{' || c == '[') {
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;
            } else if (depth == 1 && obj.startsWith(target2, i) &&
                       (i == 0 || !Character.isLetterOrDigit(obj.charAt(i - 1)))) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Normalize a JS object/array literal to valid JSON.
     * Handles minified JS patterns:
     *   !0       → true
     *   !1       → false
     *   void 0   → null
     *   undefined → null
     *   unquoted keys → "key"
     *   unresolvable refs → type-aware placeholder
     *
     * @param js  the raw JS object/array literal string
     * @param operationSignature  the operation body, used for type-aware fallbacks
     */
    private static String normalizeJsObjectToJson(String js, String operationSignature) {
        // Build type map from operation signature for fallback placeholders
        Map<String, String> typeMap = buildOperationTypeMap(operationSignature);

        StringBuilder out = new StringBuilder();
        int i = 0;
        int len = js.length();

        while (i < len) {
            char c = js.charAt(i);

            // Pass through structural characters
            if (c == '{' || c == '}' || c == '[' || c == ']' || c == ':' || c == ',') {
                out.append(c);
                i++;
                continue;
            }

            // Whitespace — pass through
            if (Character.isWhitespace(c)) {
                out.append(c);
                i++;
                continue;
            }

            // String literal — pass through, already valid JSON-compatible
            if (c == '"' || c == '\'') {
                char quote = c;
                StringBuilder str = new StringBuilder();
                i++;
                while (i < len) {
                    char sc = js.charAt(i);
                    if (sc == '\\' && i + 1 < len) {
                        str.append(sc).append(js.charAt(i + 1));
                        i += 2;
                    } else if (sc == quote) {
                        i++;
                        break;
                    } else {
                        str.append(sc);
                        i++;
                    }
                }
                // Always output double-quoted
                out.append('"').append(str).append('"');
                continue;
            }

            // Numeric literal
            if (Character.isDigit(c) || (c == '-' && i + 1 < len && Character.isDigit(js.charAt(i + 1)))) {
                int start = i;
                if (c == '-') i++;
                while (i < len && (Character.isDigit(js.charAt(i)) || js.charAt(i) == '.')) i++;
                out.append(js, start, i);
                continue;
            }

            // Boolean/null/undefined patterns
            if (js.startsWith("!0", i)) { out.append("true"); i += 2; continue; }
            if (js.startsWith("!1", i)) { out.append("false"); i += 2; continue; }
            if (js.startsWith("void 0", i)) { out.append("null"); i += 6; continue; }
            if (js.startsWith("void(0)", i)) { out.append("null"); i += 7; continue; }
            if (js.startsWith("undefined", i)) { out.append("null"); i += 9; continue; }
            if (js.startsWith("null", i) && (i + 4 >= len || !Character.isLetterOrDigit(js.charAt(i + 4)))) {
                out.append("null"); i += 4; continue;
            }
            if (js.startsWith("true", i) && (i + 4 >= len || !Character.isLetterOrDigit(js.charAt(i + 4)))) {
                out.append("true"); i += 4; continue;
            }
            if (js.startsWith("false", i) && (i + 5 >= len || !Character.isLetterOrDigit(js.charAt(i + 5)))) {
                out.append("false"); i += 5; continue;
            }

            // Identifier — could be unquoted key or unresolvable variable reference
            if (Character.isLetter(c) || c == '_' || c == '$') {
                int start = i;
                while (i < len && (Character.isLetterOrDigit(js.charAt(i)) ||
                       js.charAt(i) == '_' || js.charAt(i) == '$')) i++;
                String ident = js.substring(start, i);

                // Skip whitespace after identifier
                int j = i;
                while (j < len && Character.isWhitespace(js.charAt(j))) j++;

                if (j < len && js.charAt(j) == ':') {
                    // Unquoted key — quote it
                    out.append('"').append(ident).append('"');
                } else {
                    // Unresolvable value reference — use type-aware placeholder
                    String placeholder = typeMap.getOrDefault(ident.toLowerCase(), "null");
                    out.append(placeholder);
                }
                continue;
            }

            // Skip anything else (operators, etc.)
            i++;
        }

        String result = out.toString().replaceAll(",\\s*}", "}").replaceAll(",\\s*]", "]");
        // Validate it's a real object
        result = result.trim();
        if (!result.startsWith("{") && !result.startsWith("[")) return null;
        return result;
    }

    /**
     * Build a map of variable names (lowercase) to their type-based placeholders
     * from the operation signature. Used as fallback for unresolvable call site values.
     */
    private static Map<String, String> buildOperationTypeMap(String operationSignature) {
        Map<String, String> map = new java.util.HashMap<>();
        if (operationSignature == null) return map;

        Pattern varDecl = Pattern.compile("\\$([A-Za-z_]\\w*)\\s*:\\s*([^$,)]+)");
        Matcher m = varDecl.matcher(operationSignature);
        while (m.find()) {
            String name = m.group(1).toLowerCase();
            String type = m.group(2).trim().replaceAll("[,\\s]+$", "");
            // Use the type system from getPlaceholderForType logic
            String base = type.replace("!", "").replace("[", "").replace("]", "").trim();
            String placeholder;
            switch (base) {
                case "Int": placeholder = "0"; break;
                case "Float": placeholder = "0.0"; break;
                case "Boolean": placeholder = "false"; break;
                case "String": case "ID": placeholder = "\"\""; break;
                default: placeholder = "null"; break;
            }
            map.put(name, placeholder);
        }
        return map;
    }

    /**
     * Build a position-aware map of variable names to their string literal values.
     * Stores ALL assignments with positions so the resolver can pick the one
     * closest to the usage site (handles Webpack module scope collisions where
     * single-letter variables like y are reused across different modules).
     */
    private static Map<String, java.util.List<int[]>> buildStringVarMapPositioned(String content) {
        // Map: varName -> list of [position, startOfValue, endOfValue]
        // We store the raw Match positions and retrieve values on demand
        Map<String, java.util.List<int[]>> posMap = new java.util.HashMap<>();

        Pattern assignPattern = Pattern.compile(
                "(?:var|let|const|,)\\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\\s*=\\s*\"((?:[^\"\\\\]++|\\\\.)++)\"");
        Matcher m = assignPattern.matcher(content);
        while (m.find()) {
            String name = m.group(1);
            if (m.group(2).length() > 3) {
                posMap.computeIfAbsent(name, k -> new java.util.ArrayList<>())
                      .add(new int[]{m.start(), m.start(2), m.end(2)});
            }
        }

        return posMap;
    }

    /**
     * Resolve a variable name at a given position in the source file.
     * Picks the assignment closest to (and before) the usage position.
     */
    private static String resolveVarAtPosition(String varName, int usagePos,
                                                Map<String, java.util.List<int[]>> posMap,
                                                String content) {
        java.util.List<int[]> assignments = posMap.get(varName);
        if (assignments == null || assignments.isEmpty()) return "";

        // Find the closest preceding assignment
        int[] best = null;
        for (int[] a : assignments) {
            if (a[0] < usagePos) {
                if (best == null || a[0] > best[0]) {
                    best = a;
                }
            }
        }

        // If no preceding assignment, use the first one
        if (best == null) best = assignments.get(0);

        String raw = content.substring(best[1], best[2]);
        return unescapeJson(raw);
    }

    /**
     * Simple global variable map (non-position-aware) for use in template literal
     * resolution and other contexts where position isn't available.
     */
    private static Map<String, String> buildStringVarMap(String content) {
        Map<String, String> varMap = new java.util.HashMap<>();

        Pattern assignPattern = Pattern.compile(
                "(?:var|let|const|,)\\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\\s*=\\s*\"((?:[^\"\\\\]++|\\\\.)++)\"");
        Matcher m = assignPattern.matcher(content);
        while (m.find()) {
            String name = m.group(1);
            String value = unescapeJson(m.group(2));
            if (value.length() > 3) {
                varMap.put(name, value);
            }
        }

        return varMap;
    }

    /**
     * Resolve ${varName} interpolations using position-aware variable lookup.
     * Picks the variable assignment closest to the template's position in the file
     * to handle Webpack module scope collisions.
     */
    private static String resolveTemplateInterpolationsPositioned(String body, int templatePos,
                                                                    Map<String, java.util.List<int[]>> posMap,
                                                                    String content) {
        if (!body.contains("${")) return body;

        StringBuilder result = new StringBuilder(body.length());
        int i = 0;
        int len = body.length();

        while (i < len) {
            if (i + 1 < len && body.charAt(i) == '$' && body.charAt(i + 1) == '{') {
                int start = i + 2;
                int end = body.indexOf('}', start);
                if (end < 0) {
                    result.append(body.substring(i));
                    break;
                }
                String varName = body.substring(start, end).trim();
                // Use position-aware lookup
                String value = resolveVarAtPosition(varName, templatePos, posMap, content);
                if (!value.isEmpty()) {
                    result.append(value);
                }
                i = end + 1;
            } else {
                result.append(body.charAt(i));
                i++;
            }
        }

        return result.toString();
    }

    /**
     * Resolve ${varName} interpolations in a template literal body.
     * Uses global (non-position-aware) variable map.
     * Kept for contexts where position tracking isn't available.
     */
    private static String resolveTemplateInterpolations(String body, Map<String, String> varMap) {
        if (!body.contains("${")) return body;

        StringBuilder result = new StringBuilder(body.length());
        int i = 0;
        int len = body.length();

        while (i < len) {
            if (i + 1 < len && body.charAt(i) == '$' && body.charAt(i + 1) == '{') {
                // Find the closing }
                int start = i + 2;
                int end = body.indexOf('}', start);
                if (end < 0) {
                    // No closing brace — keep the rest as-is
                    result.append(body.substring(i));
                    break;
                }
                String varName = body.substring(start, end).trim();
                // Look up the variable
                String value = varMap.get(varName);
                if (value != null) {
                    result.append(value);
                }
                // If not found, skip the interpolation (remove it)
                i = end + 1;
            } else {
                result.append(body.charAt(i));
                i++;
            }
        }

        return result.toString();
    }

    /**
     * Result of parsing a single operation.
     */
    public static class ParsedOp {
        public final String type;      // query, mutation, subscription, fragment, persisted
        public final String name;
        public final String hash;      // non-null for persisted queries
        public final String snippet;
        public final String extractedVariables; // JSON variables extracted from call site, or null

        public ParsedOp(String type, String name, String hash, String snippet) {
            this(type, name, hash, snippet, null);
        }

        public ParsedOp(String type, String name, String hash, String snippet, String extractedVariables) {
            this.type = type;
            this.name = (name == null || name.isEmpty()) ? "anonymous" : name;
            this.hash = hash;
            this.snippet = snippet;
            this.extractedVariables = extractedVariables;
        }
    }
}
