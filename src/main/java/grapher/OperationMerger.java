package grapher;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Merges multiple captured versions of the same GraphQL operation into a
 * single combined operation containing all fields, arguments, variables,
 * and inline fragments discovered across every source.
 *
 * Used by CSV export and schema export to produce the most complete
 * representation of each operation.
 */
public class OperationMerger {

    // Variable declaration pattern — stops at next $, comma, or closing paren
    private static final Pattern VAR_DECL = Pattern.compile(
            "\\$([A-Za-z_]\\w*)\\s*:\\s*([^$,)]+)");

    /**
     * A merged operation ready for export.
     */
    public static class MergedOp {
        public final String operationType;
        public final String operationName;
        public final String mergedBody;
        public final String endpoint;      // from the best source
        public final String method;
        public final String source;
        public final String persistedHash;
        public final String url;

        MergedOp(String operationType, String operationName, String mergedBody,
                 String endpoint, String method, String source, String persistedHash, String url) {
            this.operationType = operationType;
            this.operationName = operationName;
            this.mergedBody = mergedBody;
            this.endpoint = endpoint;
            this.method = method;
            this.source = source;
            this.persistedHash = persistedHash;
            this.url = url;
        }
    }

    /**
     * Take all captured entries, group by (operationName, operationType),
     * merge each group into a single complete operation.
     * Returns one MergedOp per unique operation.
     */
    public static List<MergedOp> mergeAll(List<GraphQLEntry> entries) {
        // Group by operationName + operationType
        Map<String, List<GraphQLEntry>> groups = new LinkedHashMap<>();
        for (GraphQLEntry e : entries) {
            String key = e.operationName() + "|" + e.operationType();
            groups.computeIfAbsent(key, k -> new ArrayList<>()).add(e);
        }

        List<MergedOp> results = new ArrayList<>();
        for (Map.Entry<String, List<GraphQLEntry>> group : groups.entrySet()) {
            List<GraphQLEntry> versions = group.getValue();
            MergedOp merged = mergeGroup(versions);
            if (merged != null) {
                results.add(merged);
            }
        }
        return results;
    }

    /**
     * Merge all versions of a single operation into one.
     */
    private static MergedOp mergeGroup(List<GraphQLEntry> versions) {
        if (versions.isEmpty()) return null;

        GraphQLEntry first = versions.get(0);
        String opType = first.operationType();
        String opName = first.operationName();

        // For doc_id/persisted types, just pick the one with the longest body
        if ("doc_id".equals(opType) || "persisted".equals(opType)) {
            GraphQLEntry best = versions.stream()
                    .max(Comparator.comparingInt(e -> e.operationBody() != null ? e.operationBody().length() : 0))
                    .orElse(first);
            return new MergedOp(opType, opName, best.operationBody(),
                    best.endpoint(), best.method(), best.source().label(),
                    best.persistedHash(), best.url());
        }

        // Collect all variable declarations across versions
        Map<String, String> mergedVars = new LinkedHashMap<>();
        // Collect all root-level fields across versions
        Map<String, ParsedField> mergedRootFields = new LinkedHashMap<>();

        for (GraphQLEntry e : versions) {
            String body = e.operationBody();
            if (body == null || body.isEmpty()) continue;

            // Extract variables from this version's header
            Map<String, String> vars = extractVariables(body);
            for (Map.Entry<String, String> v : vars.entrySet()) {
                // Keep the variable — if already exists, keep the more specific type
                mergedVars.putIfAbsent(v.getKey(), v.getValue());
            }

            // Extract the selection set body
            int braceStart = findSelectionSetStart(body);
            if (braceStart < 0) continue;

            String selectionBody = extractBalancedBlock(body, braceStart);
            if (selectionBody == null) continue;

            // Parse fields from this version
            List<ParsedField> fields = parseFields(selectionBody);

            // Merge into the combined root field map
            for (ParsedField field : fields) {
                mergeField(mergedRootFields, field);
            }
        }

        // Rebuild the merged operation body
        String mergedBody = buildOperationBody(opType, opName, mergedVars, mergedRootFields);

        // Pick the best entry for metadata (prefer HTTP POST, then JS_EXECUTED, then JS)
        GraphQLEntry best = versions.stream()
                .max(Comparator.comparingInt(OperationMerger::sourceRank))
                .orElse(first);

        return new MergedOp(opType, opName, mergedBody,
                best.endpoint(), best.method(), "Merged (" + versions.size() + " sources)",
                best.persistedHash(), best.url());
    }

    private static int sourceRank(GraphQLEntry e) {
        switch (e.source()) {
            case HTTP_POST: return 3;
            case JS_EXECUTED: return 2;
            case JS_FILE: case MINIFIED_JS: return 1;
            default: return 0;
        }
    }

    // =========================================================================
    // Field parsing and merging
    // =========================================================================

    /**
     * A parsed field with its name, arguments, inline fragment type, and children.
     */
    private static class ParsedField {
        String name;                    // field name, or "..." for inline fragments
        String fragmentType;            // for inline fragments: the type name (e.g., "Hotel")
        Map<String, String> args;       // argument name -> "$varName" or literal
        Map<String, ParsedField> children; // nested fields

        ParsedField(String name, String fragmentType) {
            this.name = name;
            this.fragmentType = fragmentType;
            this.args = new LinkedHashMap<>();
            this.children = new LinkedHashMap<>();
        }
    }

    /**
     * Parse a selection set string (content between { and }) into fields.
     */
    private static List<ParsedField> parseFields(String content) {
        List<ParsedField> fields = new ArrayList<>();
        content = content.trim();
        if (content.startsWith("{")) content = content.substring(1);
        if (content.endsWith("}")) content = content.substring(0, content.length() - 1);
        content = content.trim();

        int i = 0;
        int len = content.length();

        while (i < len) {
            // Skip whitespace and commas
            while (i < len && (Character.isWhitespace(content.charAt(i)) || content.charAt(i) == ',')) i++;
            if (i >= len) break;

            // Inline fragment: ... on TypeName { ... }
            if (i + 2 < len && content.charAt(i) == '.' && content.charAt(i+1) == '.' && content.charAt(i+2) == '.') {
                i += 3;
                while (i < len && Character.isWhitespace(content.charAt(i))) i++;
                // Skip "on" keyword
                if (i + 2 < len && content.charAt(i) == 'o' && content.charAt(i+1) == 'n' &&
                    (i + 2 >= len || !Character.isLetterOrDigit(content.charAt(i+2)))) {
                    i += 2;
                    while (i < len && Character.isWhitespace(content.charAt(i))) i++;
                }
                // Read type name
                int ts = i;
                while (i < len && (Character.isLetterOrDigit(content.charAt(i)) || content.charAt(i) == '_')) i++;
                String typeName = content.substring(ts, i);
                while (i < len && Character.isWhitespace(content.charAt(i))) i++;

                // Parse nested selection set
                ParsedField fragment = new ParsedField("...", typeName);
                if (i < len && content.charAt(i) == '{') {
                    String nested = extractBalancedBlock(content, i);
                    if (nested != null) {
                        i += nested.length();
                        List<ParsedField> nestedFields = parseFields(nested);
                        for (ParsedField nf : nestedFields) {
                            mergeField(fragment.children, nf);
                        }
                    }
                }
                fields.add(fragment);
                continue;
            }

            // Skip @directives
            if (content.charAt(i) == '@') {
                while (i < len && !Character.isWhitespace(content.charAt(i)) && content.charAt(i) != '{' && content.charAt(i) != '}') {
                    if (content.charAt(i) == '(') {
                        int depth = 1; i++;
                        while (i < len && depth > 0) {
                            if (content.charAt(i) == '(') depth++;
                            else if (content.charAt(i) == ')') depth--;
                            i++;
                        }
                    } else {
                        i++;
                    }
                }
                continue;
            }

            // Regular field: fieldName or alias: fieldName
            if (!Character.isLetter(content.charAt(i)) && content.charAt(i) != '_') { i++; continue; }

            int ns = i;
            while (i < len && (Character.isLetterOrDigit(content.charAt(i)) || content.charAt(i) == '_')) i++;
            String ident = content.substring(ns, i);
            while (i < len && Character.isWhitespace(content.charAt(i))) i++;

            String fieldName;
            // Check for alias
            if (i < len && content.charAt(i) == ':') {
                i++;
                while (i < len && Character.isWhitespace(content.charAt(i))) i++;
                int fn = i;
                while (i < len && (Character.isLetterOrDigit(content.charAt(i)) || content.charAt(i) == '_')) i++;
                fieldName = i > fn ? content.substring(fn, i) : ident;
                while (i < len && Character.isWhitespace(content.charAt(i))) i++;
            } else {
                fieldName = ident;
            }

            ParsedField field = new ParsedField(fieldName, null);

            // Parse arguments
            if (i < len && content.charAt(i) == '(') {
                int argStart = i + 1;
                int depth = 1; i++;
                while (i < len && depth > 0) {
                    if (content.charAt(i) == '(') depth++;
                    else if (content.charAt(i) == ')') depth--;
                    i++;
                }
                String argStr = content.substring(argStart, i - 1);
                parseArgs(argStr, field.args);
                while (i < len && Character.isWhitespace(content.charAt(i))) i++;
            }

            // Skip directives after args
            while (i < len && content.charAt(i) == '@') {
                while (i < len && !Character.isWhitespace(content.charAt(i)) && content.charAt(i) != '{' && content.charAt(i) != '}') {
                    if (content.charAt(i) == '(') {
                        int depth = 1; i++;
                        while (i < len && depth > 0) {
                            if (content.charAt(i) == '(') depth++;
                            else if (content.charAt(i) == ')') depth--;
                            i++;
                        }
                    } else {
                        i++;
                    }
                }
                while (i < len && Character.isWhitespace(content.charAt(i))) i++;
            }

            // Parse nested selection set
            if (i < len && content.charAt(i) == '{') {
                String nested = extractBalancedBlock(content, i);
                if (nested != null) {
                    i += nested.length();
                    List<ParsedField> nestedFields = parseFields(nested);
                    for (ParsedField nf : nestedFields) {
                        mergeField(field.children, nf);
                    }
                }
            }

            fields.add(field);
        }

        return fields;
    }

    /**
     * Parse argument string "arg1: $var1, arg2: value" into the map.
     */
    private static void parseArgs(String argStr, Map<String, String> args) {
        int depth = 0;
        int start = 0;
        for (int i = 0; i <= argStr.length(); i++) {
            char c = i < argStr.length() ? argStr.charAt(i) : ',';
            if (c == '{' || c == '(' || c == '[') depth++;
            else if (c == '}' || c == ')' || c == ']') depth--;
            else if ((c == ',' || i == argStr.length()) && depth == 0) {
                String part = argStr.substring(start, i).trim();
                start = i + 1;
                int colon = part.indexOf(':');
                if (colon > 0) {
                    String name = part.substring(0, colon).trim();
                    String value = part.substring(colon + 1).trim();
                    args.putIfAbsent(name, value);
                }
            }
        }
    }

    /**
     * Merge a field into an existing field map. If the field already exists,
     * merge its children and arguments recursively.
     */
    private static void mergeField(Map<String, ParsedField> target, ParsedField incoming) {
        // Key: for inline fragments use "...TypeName", for fields use the field name
        String key = "...".equals(incoming.name) ? "..." + incoming.fragmentType : incoming.name;

        ParsedField existing = target.get(key);
        if (existing == null) {
            target.put(key, incoming);
        } else {
            // Merge arguments — add any new ones
            for (Map.Entry<String, String> arg : incoming.args.entrySet()) {
                existing.args.putIfAbsent(arg.getKey(), arg.getValue());
            }
            // Merge children recursively
            for (Map.Entry<String, ParsedField> child : incoming.children.entrySet()) {
                mergeField(existing.children, child.getValue());
            }
        }
    }

    // =========================================================================
    // Operation body reconstruction
    // =========================================================================

    /**
     * Build the complete operation body string from merged components.
     */
    private static String buildOperationBody(String opType, String opName,
                                              Map<String, String> vars,
                                              Map<String, ParsedField> rootFields) {
        StringBuilder sb = new StringBuilder();
        sb.append(opType).append(' ').append(opName);

        // Variable declarations
        if (!vars.isEmpty()) {
            sb.append('(');
            boolean first = true;
            for (Map.Entry<String, String> v : vars.entrySet()) {
                if (!first) sb.append(", ");
                sb.append('$').append(v.getKey()).append(": ").append(v.getValue());
                first = false;
            }
            sb.append(')');
        }

        sb.append(" { ");
        appendFields(sb, rootFields, 1);
        sb.append("}");

        return sb.toString();
    }

    /**
     * Recursively append fields to the output, with indentation.
     */
    private static void appendFields(StringBuilder sb, Map<String, ParsedField> fields, int depth) {
        for (ParsedField field : fields.values()) {
            if ("...".equals(field.name)) {
                // Inline fragment
                sb.append("... on ").append(field.fragmentType);
                if (!field.children.isEmpty()) {
                    sb.append(" { ");
                    appendFields(sb, field.children, depth + 1);
                    sb.append("} ");
                } else {
                    sb.append(' ');
                }
            } else {
                // Regular field
                sb.append(field.name);
                if (!field.args.isEmpty()) {
                    sb.append('(');
                    boolean first = true;
                    for (Map.Entry<String, String> arg : field.args.entrySet()) {
                        if (!first) sb.append(", ");
                        sb.append(arg.getKey()).append(": ").append(arg.getValue());
                        first = false;
                    }
                    sb.append(')');
                }
                if (!field.children.isEmpty()) {
                    sb.append(" { ");
                    appendFields(sb, field.children, depth + 1);
                    sb.append("} ");
                } else {
                    sb.append(' ');
                }
            }
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Extract variable declarations from the operation header.
     */
    private static Map<String, String> extractVariables(String body) {
        Map<String, String> vars = new LinkedHashMap<>();
        int bracePos = body.indexOf('{');
        if (bracePos < 0) return vars;

        String header = body.substring(0, bracePos);
        int parenStart = header.indexOf('(');
        int parenEnd = header.lastIndexOf(')');
        if (parenStart < 0 || parenEnd <= parenStart) return vars;

        String varBlock = header.substring(parenStart + 1, parenEnd);
        Matcher m = VAR_DECL.matcher(varBlock);
        while (m.find()) {
            String name = m.group(1);
            String type = m.group(2).trim().replaceAll("[,\\s]+$", "");
            vars.put(name, type);
        }
        return vars;
    }

    /**
     * Find where the root selection set starts (first { after the operation header).
     */
    private static int findSelectionSetStart(String body) {
        // Skip past the operation keyword, name, and variable declarations
        int i = 0;
        int len = body.length();

        // Skip operation keyword
        while (i < len && Character.isLetter(body.charAt(i))) i++;
        while (i < len && Character.isWhitespace(body.charAt(i))) i++;
        // Skip operation name
        while (i < len && (Character.isLetterOrDigit(body.charAt(i)) || body.charAt(i) == '_')) i++;
        while (i < len && Character.isWhitespace(body.charAt(i))) i++;
        // Skip variable declarations (...) if present
        if (i < len && body.charAt(i) == '(') {
            int depth = 1; i++;
            while (i < len && depth > 0) {
                if (body.charAt(i) == '(') depth++;
                else if (body.charAt(i) == ')') depth--;
                i++;
            }
            while (i < len && Character.isWhitespace(body.charAt(i))) i++;
        }

        if (i < len && body.charAt(i) == '{') return i;
        return -1;
    }

    /**
     * Extract a balanced { ... } block starting at position pos.
     */
    private static String extractBalancedBlock(String s, int pos) {
        if (pos >= s.length() || s.charAt(pos) != '{') return null;
        int depth = 0;
        int start = pos;
        while (pos < s.length()) {
            if (s.charAt(pos) == '{') depth++;
            else if (s.charAt(pos) == '}') {
                depth--;
                if (depth == 0) return s.substring(start, pos + 1);
            }
            pos++;
        }
        return null; // unbalanced
    }
}
