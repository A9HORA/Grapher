package grapher;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.BinaryMessageAction;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.MessageHandler;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.TextMessageAction;
import burp.api.montoya.websocket.WebSocket;
import burp.api.montoya.websocket.WebSocketCreated;
import burp.api.montoya.websocket.WebSocketCreatedHandler;

import javax.swing.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * Grapher — Burp Suite extension (Montoya API 2026.2)
 *
 * BApp Store compliant:
 *   - Registers ExtensionUnloadingHandler for clean unload
 *   - JS parsing runs in background thread (not in HttpHandler)
 *   - Thread-safe data structures with synchronization
 *   - HttpRequestResponse stored via copyToTempFile for large projects
 *   - GUI dialogs parented to SwingUtils.suiteFrame()
 *
 * @author Aghora
 */
public class GrapherExtension implements BurpExtension, ExtensionUnloadingHandler {

    private MontoyaApi api;
    private Logging logging;
    private GraphQLTableModel tableModel;
    private GraphQLPanel panel;

    /** Background thread pool for JS parsing — avoids blocking HttpHandler. */
    private ExecutorService jsParserPool;

    /** Stores real GraphQL POST requests as templates for request construction. */
    private final CopyOnWriteArrayList<HttpRequest> discoveredGqlRequests = new CopyOnWriteArrayList<>();

    private static final Pattern JS_CONTENT_TYPE = Pattern.compile(
            "(?i)(application/javascript|text/javascript|application/x-javascript|text/ecmascript)"
    );

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        api.extension().setName("Grapher");

        // Background thread pool for JS parsing (single thread to avoid overload)
        jsParserPool = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "Grapher-JSParser");
            t.setDaemon(true);
            return t;
        });

        tableModel = new GraphQLTableModel();
        panel = new GraphQLPanel(tableModel, api, this);

        api.userInterface().registerSuiteTab("Grapher", panel);
        api.http().registerHttpHandler(new GqlHttpHandler());
        api.websockets().registerWebSocketCreatedHandler(new GqlWebSocketCreatedHandler());

        // Register unload handler for clean shutdown
        api.extension().registerUnloadingHandler(this);

        logging.logToOutput("[+] Grapher loaded — listening for GraphQL operations");
        logging.logToOutput("[+] Right-click findings to Send to Repeater / Intruder");
    }

    /**
     * Clean unload: terminate background threads, clear data, release resources.
     */
    @Override
    public void extensionUnloaded() {
        if (jsParserPool != null) {
            jsParserPool.shutdownNow();
        }
        discoveredGqlRequests.clear();
        logging.logToOutput("[+] Grapher unloaded — all resources released");
    }

    // =========================================================================
    // HTTP Handler — lightweight, no slow operations
    // =========================================================================

    private class GqlHttpHandler implements HttpHandler {

        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            // Parse request at send-time — fast JSON field matching only
            try {
                String url = request.url();
                String path = request.path();
                String method = request.method();

                if ("POST".equalsIgnoreCase(method)) {
                    String body = request.bodyToString();
                    if (body != null && !body.isEmpty() && looksLikeGraphQLBody(body)) {
                        List<GraphQLParser.ParsedOp> ops = GraphQLParser.parseJsonBody(body);
                        for (GraphQLParser.ParsedOp op : ops) {
                            addFinding(url, path, method,
                                    op.hash != null ? GraphQLEntry.Source.PERSISTED_QUERY : GraphQLEntry.Source.HTTP_POST,
                                    op.type, op.name, op.hash, op.snippet, null);
                        }
                    }
                }

                if ("GET".equalsIgnoreCase(method) && url.contains("query=")) {
                    List<GraphQLParser.ParsedOp> ops = GraphQLParser.parseUrlParams(url);
                    for (GraphQLParser.ParsedOp op : ops) {
                        addFinding(url, path, method,
                                op.hash != null ? GraphQLEntry.Source.PERSISTED_QUERY : GraphQLEntry.Source.HTTP_POST,
                                op.type, op.name, op.hash, op.snippet, null);
                    }
                }

                if ("GET".equalsIgnoreCase(method) && url.contains("extensions=")) {
                    List<GraphQLParser.ParsedOp> ops = GraphQLParser.parseUrlParams(url);
                    for (GraphQLParser.ParsedOp op : ops) {
                        addFinding(url, path, method, GraphQLEntry.Source.PERSISTED_QUERY,
                                op.type, op.name, op.hash, op.snippet, null);
                    }
                }
            } catch (Exception e) {
                logging.logToError("Error processing request: " + e.getMessage());
            }
            return RequestToBeSentAction.continueWith(request);
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
            try {
                HttpRequest initiatingRequest = response.initiatingRequest();

                // Build HttpRequestResponse — store as temp file to avoid memory bloat
                HttpRequestResponse reqResp = null;
                try {
                    HttpRequestResponse raw = HttpRequestResponse.httpRequestResponse(initiatingRequest, response);
                    reqResp = raw.copyToTempFile();
                } catch (Exception ex) {
                    try {
                        HttpRequestResponse raw = HttpRequestResponse.httpRequestResponse(initiatingRequest, null);
                        reqResp = raw.copyToTempFile();
                    } catch (Exception ex2) {
                        // findings will have null reqResp
                    }
                }

                // Update existing entries with the HttpRequestResponse pair
                processRequestFromResponse(initiatingRequest, reqResp);

                // JS parsing — offload to background thread
                final HttpResponseReceived resp = response;
                final HttpRequestResponse finalReqResp = reqResp;
                if (jsParserPool != null && !jsParserPool.isShutdown()) {
                    jsParserPool.submit(() -> {
                        try {
                            processJsResponse(resp, finalReqResp);
                        } catch (Exception ex) {
                            logging.logToError("JS parse error: " + ex.getMessage());
                        }
                    });
                }

            } catch (Exception e) {
                logging.logToError("Error processing response: " + e.getMessage());
            }
            return ResponseReceivedAction.continueWith(response);
        }
    }

    private void processRequestFromResponse(HttpRequest request, HttpRequestResponse reqResp) {
        String url = request.url();
        String path = request.path();
        String method = request.method();

        if ("POST".equalsIgnoreCase(method)) {
            String body = request.bodyToString();
            if (body != null && !body.isEmpty() && looksLikeGraphQLBody(body)) {
                rememberGqlRequest(request);

                List<GraphQLParser.ParsedOp> ops = GraphQLParser.parseJsonBody(body);
                for (GraphQLParser.ParsedOp op : ops) {
                    addFinding(url, path, method,
                            op.hash != null ? GraphQLEntry.Source.PERSISTED_QUERY : GraphQLEntry.Source.HTTP_POST,
                            op.type, op.name, op.hash, op.snippet, reqResp);
                }
            }
        }

        if ("GET".equalsIgnoreCase(method) && url.contains("query=")) {
            List<GraphQLParser.ParsedOp> ops = GraphQLParser.parseUrlParams(url);
            for (GraphQLParser.ParsedOp op : ops) {
                addFinding(url, path, method,
                        op.hash != null ? GraphQLEntry.Source.PERSISTED_QUERY : GraphQLEntry.Source.HTTP_POST,
                        op.type, op.name, op.hash, op.snippet, reqResp);
            }
        }

        if ("GET".equalsIgnoreCase(method) && url.contains("extensions=")) {
            List<GraphQLParser.ParsedOp> ops = GraphQLParser.parseUrlParams(url);
            for (GraphQLParser.ParsedOp op : ops) {
                addFinding(url, path, method, GraphQLEntry.Source.PERSISTED_QUERY,
                        op.type, op.name, op.hash, op.snippet, reqResp);
            }
        }
    }

    private void processJsResponse(HttpResponseReceived response, HttpRequestResponse reqResp) {
        String contentType = "";
        var headers = response.headers();
        for (var h : headers) {
            if ("Content-Type".equalsIgnoreCase(h.name())) {
                contentType = h.value();
                break;
            }
        }

        if (!JS_CONTENT_TYPE.matcher(contentType).find()) return;

        String body = response.bodyToString();
        if (body == null || body.length() < 20) return;

        if (!body.contains("query") && !body.contains("mutation") &&
            !body.contains("subscription") && !body.contains("gql") &&
            !body.contains("graphql") && !body.contains("sha256Hash") &&
            !body.contains("doc_id") && !body.contains("queryID") &&
            !body.contains("queryId") && !body.contains("\"Request\"")) {
            return;
        }

        String url = response.initiatingRequest().url();
        String path = response.initiatingRequest().path();

        List<GraphQLParser.ParsedOp> ops = GraphQLParser.parseJsContent(body);
        for (GraphQLParser.ParsedOp op : ops) {
            addFinding(url, path, "GET", GraphQLEntry.Source.JS_FILE,
                    op.type, op.name, op.hash, op.snippet, reqResp);
        }

        List<GraphQLParser.ParsedOp> minifiedOps = GraphQLParser.parseMinifiedJsContent(body);
        for (GraphQLParser.ParsedOp op : minifiedOps) {
            addFinding(url, path, "GET", GraphQLEntry.Source.MINIFIED_JS,
                    op.type, op.name, op.hash, op.snippet, reqResp);
        }
    }

    // =========================================================================
    // WebSocket Handler
    // =========================================================================

    private class GqlWebSocketCreatedHandler implements WebSocketCreatedHandler {
        @Override
        public void handleWebSocketCreated(WebSocketCreated webSocketCreated) {
            WebSocket webSocket = webSocketCreated.webSocket();
            HttpRequest upgradeRequest = webSocketCreated.upgradeRequest();

            String url = upgradeRequest.url();
            String path = upgradeRequest.path();

            HttpRequestResponse upgradeReqResp = null;
            try {
                upgradeReqResp = HttpRequestResponse.httpRequestResponse(upgradeRequest, null)
                        .copyToTempFile();
            } catch (Exception e) {
                // proceed without reqResp
            }
            final HttpRequestResponse finalUpgradeReqResp = upgradeReqResp;

            webSocket.registerMessageHandler(new MessageHandler() {
                @Override
                public TextMessageAction handleTextMessage(TextMessage textMessage) {
                    try {
                        if (textMessage.direction() == Direction.CLIENT_TO_SERVER) {
                            String payload = textMessage.payload();
                            if (payload != null && (payload.contains("\"query\"") ||
                                    payload.contains("\"sha256Hash\""))) {
                                List<GraphQLParser.ParsedOp> ops = GraphQLParser.parseWebSocketMessage(payload);
                                for (GraphQLParser.ParsedOp op : ops) {
                                    addFinding(url, path, "WS",
                                            GraphQLEntry.Source.WEBSOCKET,
                                            op.type, op.name, op.hash, op.snippet,
                                            finalUpgradeReqResp);
                                }
                            }
                        }
                    } catch (Exception e) {
                        logging.logToError("WS parse error: " + e.getMessage());
                    }
                    return TextMessageAction.continueWith(textMessage);
                }

                @Override
                public BinaryMessageAction handleBinaryMessage(BinaryMessage binaryMessage) {
                    return BinaryMessageAction.continueWith(binaryMessage);
                }
            });
        }
    }

    // =========================================================================
    // GraphQL endpoint tracking + request construction
    // =========================================================================

    private void rememberGqlRequest(HttpRequest request) {
        String key = request.httpService().host() + request.path();
        for (HttpRequest existing : discoveredGqlRequests) {
            String existingKey = existing.httpService().host() + existing.path();
            if (existingKey.equals(key)) return;
        }
        discoveredGqlRequests.add(request);
        logging.logToOutput("[+] Discovered GraphQL endpoint: " +
                request.httpService().host() + request.path());
    }

    public HttpRequest buildGqlRequest(String operationBody, String operationName,
                                       String operationType, String persistedHash) {
        if (discoveredGqlRequests.isEmpty()) {
            logging.logToOutput("[!] No GraphQL endpoint discovered yet — browse the target first");
            return null;
        }

        HttpRequest template = discoveredGqlRequests.get(0);
        String jsonBody;

        if ("doc_id".equals(operationType) && persistedHash != null && !persistedHash.isEmpty()) {
            jsonBody = buildDocIdBody(persistedHash, operationName);
        } else {
            String escapedBody = operationBody
                    .replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");

            // Extract variable placeholders from the operation signature
            String variablesJson = buildVariablePlaceholders(operationBody);

            if (operationName != null && !operationName.isEmpty() && !operationName.equals("anonymous")) {
                jsonBody = "{\"query\":\"" + escapedBody + "\",\"operationName\":\"" + operationName + "\",\"variables\":" + variablesJson + "}";
            } else {
                jsonBody = "{\"query\":\"" + escapedBody + "\",\"variables\":" + variablesJson + "}";
            }
        }

        return HttpRequest.httpRequest(template.httpService(),
                buildRawRequest(template, jsonBody, operationName));
    }

    /**
     * Extract variable names and types from the operation signature and build
     * a JSON variables object with placeholder values.
     *
     * Input:  "query Foo($id: ID!, $name: String, $count: Int)"
     * Output: {"id":"<ID>","name":"<String>","count":"<Int>"}
     *
     * This gives the tester a ready-to-fill template in Repeater instead of
     * an empty {} that requires reading the query to know what variables exist.
     */
    private String buildVariablePlaceholders(String operationBody) {
        // Find the variable declaration block: (...) before the first {
        int bracePos = operationBody.indexOf('{');
        if (bracePos < 0) return "{}";

        String header = operationBody.substring(0, bracePos);
        int parenStart = header.indexOf('(');
        int parenEnd = header.lastIndexOf(')');
        if (parenStart < 0 || parenEnd < 0 || parenEnd <= parenStart) return "{}";

        String varBlock = header.substring(parenStart + 1, parenEnd);

        // Parse $varName: Type pairs
        StringBuilder vars = new StringBuilder("{");
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "\\$([A-Za-z_]\\w*)\\s*:\\s*([^$,)]+)").matcher(varBlock);
        boolean first = true;
        while (m.find()) {
            String varName = m.group(1);
            String varType = m.group(2).trim().replaceAll("[,\\s]+$", "");

            if (!first) vars.append(",");
            first = false;

            // Generate appropriate placeholder based on type
            String placeholder = getPlaceholderForType(varType);
            vars.append("\"").append(varName).append("\":").append(placeholder);
        }
        vars.append("}");

        return vars.toString();
    }

    /**
     * Return a JSON placeholder value appropriate for the GraphQL type.
     */
    private String getPlaceholderForType(String type) {
        // Strip non-null marker and list brackets for base type check
        String base = type.replace("!", "").replace("[", "").replace("]", "").trim();

        switch (base) {
            case "Int":
                return "0";
            case "Float":
                return "0.0";
            case "Boolean":
                return "false";
            case "String":
                return "\"\"";
            case "ID":
                return "\"\"";
            default:
                // Complex input types get an empty object placeholder
                // The tester will need to fill in the fields
                return "{}";
        }
    }

    private String buildDocIdBody(String docId, String operationName) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"doc_id\":\"").append(docId).append("\"");
        if (operationName != null && !operationName.isEmpty() && !operationName.equals("anonymous")) {
            sb.append(",\"operationName\":\"").append(operationName).append("\"");
        }
        sb.append(",\"variables\":{}}");
        return sb.toString();
    }

    /**
     * Build a raw HTTP request using the template's headers and the new body.
     * Updates the gqlOp query parameter in the URL to match the operation being sent.
     */
    private String buildRawRequest(HttpRequest template, String jsonBody, String operationName) {
        // Get the template path and update gqlOp parameter if present
        String path = template.path();
        if (operationName != null && !operationName.isEmpty() && !operationName.equals("anonymous")) {
            // Replace existing gqlOp parameter value
            if (path.contains("gqlOp=")) {
                path = path.replaceFirst("gqlOp=[^&]*", "gqlOp=" + operationName);
            }
        }

        StringBuilder raw = new StringBuilder();
        raw.append("POST ").append(path).append(" HTTP/1.1\r\n");

        var headers = template.headers();
        boolean hasContentType = false;
        for (var h : headers) {
            String name = h.name();
            if (name.startsWith(":")) continue;
            if ("Content-Length".equalsIgnoreCase(name)) continue;
            if ("Content-Type".equalsIgnoreCase(name)) {
                hasContentType = true;
                raw.append("Content-Type: application/json\r\n");
                continue;
            }
            raw.append(h.name()).append(": ").append(h.value()).append("\r\n");
        }

        if (!hasContentType) {
            raw.append("Content-Type: application/json\r\n");
        }

        raw.append("Content-Length: ").append(jsonBody.length()).append("\r\n");
        raw.append("\r\n");
        raw.append(jsonBody);

        return raw.toString();
    }

    public List<HttpRequest> getDiscoveredGqlRequests() {
        return discoveredGqlRequests;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private boolean looksLikeGraphQLBody(String body) {
        return body.contains("\"query\"") ||
               body.contains("\"mutation\"") ||
               body.contains("\"operationName\"") ||
               body.contains("\"sha256Hash\"") ||
               body.contains("\"persistedQuery\"") ||
               body.contains("\"doc_id\"") ||
               body.contains("\"queryId\"") ||
               body.contains("\"document_id\"");
    }

    /**
     * Add a finding to the table. Thread-safe: isDuplicate and updateRequestResponse
     * are synchronized on the table model; addEntry is posted to the Swing EDT.
     */
    private void addFinding(String url, String endpoint, String method,
                            GraphQLEntry.Source source, String opType,
                            String opName, String hash, String snippet,
                            HttpRequestResponse reqResp) {

        // Synchronized dedup check + update
        if (tableModel.isDuplicate(endpoint, opName, opType, hash)) {
            // Try to upgrade an existing entry that has null reqResp
            if (reqResp != null) {
                tableModel.updateRequestResponse(endpoint, opName, opType, reqResp);
            }
            return;
        }

        GraphQLEntry entry = new GraphQLEntry.Builder()
                .url(url)
                .endpoint(endpoint)
                .method(method)
                .source(source)
                .operationType(opType)
                .operationName(opName)
                .persistedHash(hash)
                .operationBody(snippet)
                .requestResponse(reqResp)
                .build();

        SwingUtilities.invokeLater(() -> {
            tableModel.addEntry(entry);
            panel.updateStatus();
        });

        logging.logToOutput(String.format("[GQL] %s %s | %s %s | %s",
                source.label(), endpoint, opType, opName,
                hash != null ? "hash=" + hash : ""));
    }
}
