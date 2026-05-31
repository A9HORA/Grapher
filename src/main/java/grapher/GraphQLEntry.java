package grapher;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Represents a single captured GraphQL operation.
 */
public class GraphQLEntry {

    public enum Source {
        HTTP_POST("HTTP POST Body"),
        JS_FILE("JS/Static File"),
        WEBSOCKET("WebSocket Message"),
        PERSISTED_QUERY("Persisted Query Hash"),
        MINIFIED_JS("Minified/Obfuscated JS"),
        JS_EXECUTED("JS Executed (Node.js)");

        private final String label;

        Source(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    private final String url;
    private final String method;
    private final String operationType;
    private final String operationName;
    private final String operationBody;
    private final Source source;
    private final String endpoint;
    private final String persistedHash;
    private final long timestamp;
    private final HttpRequestResponse requestResponse;
    private final java.util.Set<String> tags;
    private final String extractedVariablesJson; // from JS call site, or null

    private GraphQLEntry(Builder b) {
        this.url = b.url;
        this.method = b.method;
        this.operationType = b.operationType;
        this.operationName = b.operationName;
        this.operationBody = b.operationBody;
        this.source = b.source;
        this.endpoint = b.endpoint;
        this.persistedHash = b.persistedHash;
        this.requestResponse = b.requestResponse;
        this.timestamp = System.currentTimeMillis();
        this.tags = b.tags != null ? new java.util.LinkedHashSet<>(b.tags) : new java.util.LinkedHashSet<>();
        this.extractedVariablesJson = b.extractedVariablesJson;
    }

    // --- Getters ---

    public String url() { return url; }
    public String method() { return method; }
    public String operationType() { return operationType; }
    public String operationName() { return operationName; }
    public String operationBody() { return operationBody; }
    public Source source() { return source; }
    public String endpoint() { return endpoint; }
    public String persistedHash() { return persistedHash; }
    public long timestamp() { return timestamp; }
    public HttpRequestResponse requestResponse() { return requestResponse; }

    public boolean hasSendableRequest() {
        return requestResponse != null && requestResponse.request() != null;
    }

    public java.util.Set<String> tags() { return tags; }
    public boolean hasTag(String tag) { return tags.contains(tag); }
    public String extractedVariablesJson() { return extractedVariablesJson; }

    // --- Builder ---

    public static class Builder {
        private String url = "";
        private String method = "";
        private String operationType = "";
        private String operationName = "";
        private String operationBody = "";
        private Source source = Source.HTTP_POST;
        private String endpoint = "";
        private String persistedHash = "";
        private HttpRequestResponse requestResponse = null;
        private java.util.Set<String> tags = null;
        private String extractedVariablesJson = null;

        public Builder url(String v) { this.url = v; return this; }
        public Builder method(String v) { this.method = v; return this; }
        public Builder operationType(String v) { this.operationType = v; return this; }
        public Builder operationName(String v) { this.operationName = v; return this; }
        public Builder operationBody(String v) { this.operationBody = v; return this; }
        public Builder source(Source v) { this.source = v; return this; }
        public Builder endpoint(String v) { this.endpoint = v; return this; }
        public Builder persistedHash(String v) { this.persistedHash = v; return this; }
        public Builder requestResponse(HttpRequestResponse v) { this.requestResponse = v; return this; }
        public Builder tags(java.util.Set<String> v) { this.tags = v; return this; }
        public Builder extractedVariablesJson(String v) { this.extractedVariablesJson = v; return this; }

        public GraphQLEntry build() {
            return new GraphQLEntry(this);
        }
    }
}
