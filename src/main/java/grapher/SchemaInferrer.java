package grapher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Infers a partial GraphQL SDL schema from captured operations.
 *
 * Walks through all operation bodies, parses their selection sets and
 * argument definitions, and builds a merged type map. The output is a
 * valid .graphql SDL file that can be imported into GraphQL Voyager,
 * GraphiQL, Apollo Studio, or any SDL-compatible tool.
 *
 * Limitations (by design — documented in the output):
 *   - Field return types are inferred as "Unknown" unless they have
 *     sub-selections (in which case a named object type is created)
 *   - Only fields observed in captured operations appear; the real
 *     schema likely has more
 *   - Input types are inferred from variable declarations but inner
 *     fields of input objects are not known
 */
public class SchemaInferrer {

    // Parsed representation of a field in a selection set
    private static class FieldInfo {
        final String name;
        final String alias;           // null if no alias
        final List<ArgInfo> args;
        final List<FieldInfo> children; // nested selection set

        FieldInfo(String name, String alias, List<ArgInfo> args, List<FieldInfo> children) {
            this.name = name;
            this.alias = alias;
            this.args = args;
            this.children = children;
        }
    }

    private static class ArgInfo {
        final String name;
        final String type; // from variable declaration or "Unknown"

        ArgInfo(String name, String type) {
            this.name = name;
            this.type = type;
        }
    }

    // Accumulated type definitions
    private final Map<String, Map<String, FieldDef>> types = new LinkedHashMap<>();
    private final Map<String, Map<String, String>> rootQueryFields = new LinkedHashMap<>();
    private final Map<String, Map<String, String>> rootMutationFields = new LinkedHashMap<>();
    private final Map<String, Map<String, String>> rootSubscriptionFields = new LinkedHashMap<>();
    private final Set<String> inputTypeNames = new LinkedHashSet<>();
    private final Set<String> enumValues = new LinkedHashSet<>();

    private static class FieldDef {
        String returnType;
        final Map<String, String> args = new LinkedHashMap<>();

        FieldDef(String returnType) {
            this.returnType = returnType;
        }
    }

    /**
     * Process all captured entries and build the inferred schema.
     */
    public String inferSchema(List<GraphQLEntry> entries) {
        // Reset state
        types.clear();
        rootQueryFields.clear();
        rootMutationFields.clear();
        rootSubscriptionFields.clear();
        inputTypeNames.clear();

        for (GraphQLEntry entry : entries) {
            String opType = entry.operationType();
            String opBody = entry.operationBody();

            // Skip doc_id / persisted entries without a query body
            if (opBody == null || opBody.isEmpty()) continue;
            if ("doc_id".equals(opType) || "persisted".equals(opType)) continue;

            try {
                processOperation(opType, opBody);
            } catch (Exception e) {
                // Skip malformed operations silently
            }
        }

        return buildSdl();
    }

    /**
     * Parse a single operation body and merge its types into the accumulator.
     */
    private void processOperation(String opType, String opBody) {
        // Extract variable declarations for type info: ($id: ID!, $input: CreateInput!)
        Map<String, String> varTypes = extractVariableTypes(opBody);

        // Record input types discovered from variable declarations
        for (String varType : varTypes.values()) {
            String clean = varType.replace("!", "").replace("[", "").replace("]", "").trim();
            if (!isBuiltinScalar(clean) && !clean.isEmpty()) {
                inputTypeNames.add(clean);
            }
        }

        // Find the root selection set (after the opening {)
        int braceStart = opBody.indexOf('{');
        if (braceStart < 0) return;

        String selectionBody = opBody.substring(braceStart);
        List<FieldInfo> rootFields = parseSelectionSet(selectionBody, varTypes);

        // Determine which root type to add fields to
        Map<String, Map<String, String>> rootType;
        if ("mutation".equals(opType)) {
            rootType = rootMutationFields;
        } else if ("subscription".equals(opType)) {
            rootType = rootSubscriptionFields;
        } else {
            rootType = rootQueryFields;
        }

        // Process root-level fields
        for (FieldInfo field : rootFields) {
            String fieldName = field.name;
            if (fieldName.startsWith("__")) continue; // skip introspection meta-fields

            // Build the return type name
            String returnTypeName;
            if (field.children.isEmpty()) {
                returnTypeName = "Unknown";
            } else {
                returnTypeName = capitalize(fieldName) + "_Response";
                mergeFieldsIntoType(returnTypeName, field.children, varTypes);
            }

            // Add to root type
            Map<String, String> argsMap = rootType.computeIfAbsent(fieldName, k -> new LinkedHashMap<>());
            for (ArgInfo arg : field.args) {
                argsMap.putIfAbsent(arg.name, arg.type);
            }

            // Store the return type mapping
            ensureType(returnTypeName);
        }
    }

    /**
     * Recursively merge fields into a named type.
     */
    private void mergeFieldsIntoType(String typeName, List<FieldInfo> fields, Map<String, String> varTypes) {
        Map<String, FieldDef> typeFields = types.computeIfAbsent(typeName, k -> new LinkedHashMap<>());

        for (FieldInfo field : fields) {
            if (field.name.startsWith("__")) continue;

            String returnType;
            if (!field.children.isEmpty()) {
                // Has nested selection — create a child type
                returnType = typeName + "_" + capitalize(field.name);
                mergeFieldsIntoType(returnType, field.children, varTypes);
            } else {
                returnType = "Unknown";
            }

            FieldDef existing = typeFields.get(field.name);
            if (existing == null) {
                FieldDef fd = new FieldDef(returnType);
                for (ArgInfo arg : field.args) {
                    fd.args.putIfAbsent(arg.name, arg.type);
                }
                typeFields.put(field.name, fd);
            } else {
                // Merge: if existing is Unknown but new has children, upgrade
                if ("Unknown".equals(existing.returnType) && !"Unknown".equals(returnType)) {
                    existing.returnType = returnType;
                }
                for (ArgInfo arg : field.args) {
                    existing.args.putIfAbsent(arg.name, arg.type);
                }
            }
        }
    }

    private void ensureType(String name) {
        types.computeIfAbsent(name, k -> new LinkedHashMap<>());
    }

    // =========================================================================
    // Selection set parser — walks balanced braces to extract fields
    // =========================================================================

    private static final Pattern FIELD_PATTERN = Pattern.compile(
            "([A-Za-z_]\\w*)\\s*(?::\\s*([A-Za-z_]\\w*))?\\s*(\\([^)]*\\))?\\s*"
    );

    /**
     * Parse a selection set string starting with { and ending with }.
     * Returns a list of FieldInfo objects.
     */
    private List<FieldInfo> parseSelectionSet(String s, Map<String, String> varTypes) {
        List<FieldInfo> fields = new ArrayList<>();
        if (s == null || s.isEmpty()) return fields;

        // Strip outer braces
        s = s.trim();
        if (s.startsWith("{")) s = s.substring(1);
        if (s.endsWith("}")) s = s.substring(0, s.length() - 1);
        s = s.trim();

        int i = 0;
        int len = s.length();

        while (i < len) {
            // Skip whitespace and commas
            while (i < len && (Character.isWhitespace(s.charAt(i)) || s.charAt(i) == ',')) i++;
            if (i >= len) break;

            // Skip fragment spreads: ... on TypeName or ...FragmentName
            if (i + 2 < len && s.charAt(i) == '.' && s.charAt(i + 1) == '.' && s.charAt(i + 2) == '.') {
                i += 3;
                while (i < len && Character.isWhitespace(s.charAt(i))) i++;
                // Skip "on" keyword if present
                if (i + 2 < len && s.charAt(i) == 'o' && s.charAt(i + 1) == 'n' &&
                    (i + 2 >= len || !Character.isLetterOrDigit(s.charAt(i + 2)))) {
                    i += 2;
                    while (i < len && Character.isWhitespace(s.charAt(i))) i++;
                }
                // Skip the type/fragment name
                while (i < len && (Character.isLetterOrDigit(s.charAt(i)) || s.charAt(i) == '_')) i++;
                // If followed by a selection set, skip it
                while (i < len && Character.isWhitespace(s.charAt(i))) i++;
                if (i < len && s.charAt(i) == '{') {
                    int depth = 0;
                    while (i < len) {
                        if (s.charAt(i) == '{') depth++;
                        else if (s.charAt(i) == '}') { depth--; if (depth == 0) { i++; break; } }
                        i++;
                    }
                }
                continue;
            }

            // Skip @directives
            if (s.charAt(i) == '@') {
                while (i < len && !Character.isWhitespace(s.charAt(i)) && s.charAt(i) != '{' && s.charAt(i) != '}') {
                    if (s.charAt(i) == '(') {
                        int depth = 1; i++;
                        while (i < len && depth > 0) {
                            if (s.charAt(i) == '(') depth++;
                            else if (s.charAt(i) == ')') depth--;
                            i++;
                        }
                    } else {
                        i++;
                    }
                }
                continue;
            }

            // Parse field name (with optional alias: alias: fieldName)
            if (!Character.isLetter(s.charAt(i)) && s.charAt(i) != '_') { i++; continue; }

            int nameStart = i;
            while (i < len && (Character.isLetterOrDigit(s.charAt(i)) || s.charAt(i) == '_')) i++;
            String firstIdent = s.substring(nameStart, i);

            while (i < len && Character.isWhitespace(s.charAt(i))) i++;

            String fieldName;
            String alias = null;

            // Check for alias: alias: fieldName
            if (i < len && s.charAt(i) == ':') {
                alias = firstIdent;
                i++; // skip :
                while (i < len && Character.isWhitespace(s.charAt(i))) i++;
                int fn = i;
                while (i < len && (Character.isLetterOrDigit(s.charAt(i)) || s.charAt(i) == '_')) i++;
                fieldName = i > fn ? s.substring(fn, i) : firstIdent;
                while (i < len && Character.isWhitespace(s.charAt(i))) i++;
            } else {
                fieldName = firstIdent;
            }

            // Parse arguments: (arg1: $var1, arg2: value)
            List<ArgInfo> args = new ArrayList<>();
            if (i < len && s.charAt(i) == '(') {
                int argStart = i + 1;
                int depth = 1; i++;
                while (i < len && depth > 0) {
                    if (s.charAt(i) == '(') depth++;
                    else if (s.charAt(i) == ')') depth--;
                    i++;
                }
                String argStr = s.substring(argStart, i - 1);
                args = parseArguments(argStr, varTypes);
                while (i < len && Character.isWhitespace(s.charAt(i))) i++;
            }

            // Skip directives after arguments
            while (i < len && s.charAt(i) == '@') {
                while (i < len && !Character.isWhitespace(s.charAt(i)) && s.charAt(i) != '{' && s.charAt(i) != '}') {
                    if (s.charAt(i) == '(') {
                        int depth = 1; i++;
                        while (i < len && depth > 0) {
                            if (s.charAt(i) == '(') depth++;
                            else if (s.charAt(i) == ')') depth--;
                            i++;
                        }
                    } else {
                        i++;
                    }
                }
                while (i < len && Character.isWhitespace(s.charAt(i))) i++;
            }

            // Parse nested selection set
            List<FieldInfo> children = new ArrayList<>();
            if (i < len && s.charAt(i) == '{') {
                int braceStart = i;
                int depth = 0;
                while (i < len) {
                    if (s.charAt(i) == '{') depth++;
                    else if (s.charAt(i) == '}') { depth--; if (depth == 0) { i++; break; } }
                    i++;
                }
                String nested = s.substring(braceStart, i);
                children = parseSelectionSet(nested, varTypes);
            }

            fields.add(new FieldInfo(fieldName, alias, args, children));
        }

        return fields;
    }

    /**
     * Parse argument string like "id: $id, name: $name, limit: 10"
     * and resolve $variable types from the variable declarations.
     */
    private List<ArgInfo> parseArguments(String argStr, Map<String, String> varTypes) {
        List<ArgInfo> args = new ArrayList<>();
        if (argStr == null || argStr.trim().isEmpty()) return args;

        // Split on commas, handling nested objects/lists
        List<String> parts = splitArgs(argStr);

        for (String part : parts) {
            part = part.trim();
            if (part.isEmpty()) continue;

            int colonPos = part.indexOf(':');
            if (colonPos < 0) continue;

            String argName = part.substring(0, colonPos).trim();
            String argValue = part.substring(colonPos + 1).trim();

            // Resolve type from variable reference ($varName -> look up declared type)
            String argType = "Unknown";
            if (argValue.startsWith("$")) {
                String varName = argValue.substring(1).trim();
                if (varTypes.containsKey(varName)) {
                    argType = varTypes.get(varName);
                }
            } else if (argValue.matches("-?\\d+")) {
                argType = "Int";
            } else if (argValue.matches("-?\\d+\\.\\d+")) {
                argType = "Float";
            } else if ("true".equals(argValue) || "false".equals(argValue)) {
                argType = "Boolean";
            } else if (argValue.startsWith("\"")) {
                argType = "String";
            } else if (argValue.matches("[A-Z_][A-Z0-9_]*")) {
                // Looks like an enum value
                argType = "String"; // enums show as String in inferred schema
            }

            args.add(new ArgInfo(argName, argType));
        }

        return args;
    }

    /**
     * Split argument string by commas, respecting nested { } and ( ).
     */
    private List<String> splitArgs(String s) {
        List<String> parts = new ArrayList<>();
        int depth = 0;
        int start = 0;

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '{' || c == '(' || c == '[') depth++;
            else if (c == '}' || c == ')' || c == ']') depth--;
            else if (c == ',' && depth == 0) {
                parts.add(s.substring(start, i));
                start = i + 1;
            }
        }
        if (start < s.length()) {
            parts.add(s.substring(start));
        }

        return parts;
    }

    // =========================================================================
    // Variable type extraction
    // =========================================================================

    private static final Pattern VAR_DECL = Pattern.compile(
            "\\$([A-Za-z_]\\w*)\\s*:\\s*([^,)]+)"
    );

    /**
     * Extract variable declarations from the operation signature.
     * e.g., "query Foo($id: ID!, $input: CreateInput!)" -> {id: "ID!", input: "CreateInput!"}
     */
    private Map<String, String> extractVariableTypes(String opBody) {
        Map<String, String> vars = new LinkedHashMap<>();

        // Find the variable declaration block: (...)  before the first {
        int bracePos = opBody.indexOf('{');
        if (bracePos < 0) return vars;

        String header = opBody.substring(0, bracePos);
        int parenStart = header.indexOf('(');
        int parenEnd = header.lastIndexOf(')');
        if (parenStart < 0 || parenEnd < 0 || parenEnd <= parenStart) return vars;

        String varBlock = header.substring(parenStart + 1, parenEnd);
        Matcher m = VAR_DECL.matcher(varBlock);
        while (m.find()) {
            String name = m.group(1);
            String type = m.group(2).trim();
            // Clean trailing whitespace/commas
            type = type.replaceAll("[,\\s]+$", "");
            vars.put(name, type);
        }

        return vars;
    }

    // =========================================================================
    // SDL output builder
    // =========================================================================

    private String buildSdl() {
        StringBuilder sdl = new StringBuilder();

        sdl.append("# =============================================================\n");
        sdl.append("# Inferred GraphQL Schema — Generated by Grapher\n");
        sdl.append("# =============================================================\n");
        sdl.append("# This schema was inferred from observed operations (HTTP traffic\n");
        sdl.append("# and JS bundles). It is PARTIAL — only fields seen in captured\n");
        sdl.append("# operations are included. The actual schema likely has more.\n");
        sdl.append("# \n");
        sdl.append("# Field return types marked as 'Unknown' are leaf fields whose\n");
        sdl.append("# concrete scalar type could not be determined from the query.\n");
        sdl.append("# \n");
        sdl.append("# Import this file into GraphQL Voyager, GraphiQL, or Apollo\n");
        sdl.append("# Studio to visualize the API surface.\n");
        sdl.append("# =============================================================\n\n");

        // Declare Unknown scalar so the SDL is valid
        sdl.append("scalar Unknown\n\n");

        // Schema definition
        boolean hasQuery = !rootQueryFields.isEmpty();
        boolean hasMutation = !rootMutationFields.isEmpty();
        boolean hasSubscription = !rootSubscriptionFields.isEmpty();

        if (hasQuery || hasMutation || hasSubscription) {
            sdl.append("schema {\n");
            if (hasQuery) sdl.append("  query: Query\n");
            if (hasMutation) sdl.append("  mutation: Mutation\n");
            if (hasSubscription) sdl.append("  subscription: Subscription\n");
            sdl.append("}\n\n");
        }

        // Root Query type
        if (hasQuery) {
            sdl.append("type Query {\n");
            for (Map.Entry<String, Map<String, String>> field : rootQueryFields.entrySet()) {
                String returnType = inferRootFieldReturnType(field.getKey());
                sdl.append("  ").append(field.getKey());
                appendArgs(sdl, field.getValue());
                sdl.append(": ").append(returnType).append("\n");
            }
            sdl.append("}\n\n");
        }

        // Root Mutation type
        if (hasMutation) {
            sdl.append("type Mutation {\n");
            for (Map.Entry<String, Map<String, String>> field : rootMutationFields.entrySet()) {
                String returnType = inferRootFieldReturnType(field.getKey());
                sdl.append("  ").append(field.getKey());
                appendArgs(sdl, field.getValue());
                sdl.append(": ").append(returnType).append("\n");
            }
            sdl.append("}\n\n");
        }

        // Root Subscription type
        if (hasSubscription) {
            sdl.append("type Subscription {\n");
            for (Map.Entry<String, Map<String, String>> field : rootSubscriptionFields.entrySet()) {
                String returnType = inferRootFieldReturnType(field.getKey());
                sdl.append("  ").append(field.getKey());
                appendArgs(sdl, field.getValue());
                sdl.append(": ").append(returnType).append("\n");
            }
            sdl.append("}\n\n");
        }

        // Object types inferred from selection sets
        for (Map.Entry<String, Map<String, FieldDef>> type : types.entrySet()) {
            String typeName = type.getKey();
            Map<String, FieldDef> fields = type.getValue();

            if (fields.isEmpty()) continue;

            sdl.append("type ").append(typeName).append(" {\n");
            for (Map.Entry<String, FieldDef> field : fields.entrySet()) {
                sdl.append("  ").append(field.getKey());
                if (!field.getValue().args.isEmpty()) {
                    appendArgs(sdl, field.getValue().args);
                }
                sdl.append(": ").append(field.getValue().returnType).append("\n");
            }
            sdl.append("}\n\n");
        }

        // Input types (declared in variable types but structure unknown)
        for (String inputName : inputTypeNames) {
            // Only emit if not already defined as an object type
            if (!types.containsKey(inputName)) {
                sdl.append("# Input type observed in variable declarations — fields unknown\n");
                sdl.append("input ").append(inputName).append(" {\n");
                sdl.append("  _placeholder: Unknown\n");
                sdl.append("}\n\n");
            }
        }

        return sdl.toString();
    }

    private String inferRootFieldReturnType(String fieldName) {
        String candidate = capitalize(fieldName) + "_Response";
        if (types.containsKey(candidate) && !types.get(candidate).isEmpty()) {
            return candidate;
        }
        return "Unknown";
    }

    private void appendArgs(StringBuilder sdl, Map<String, String> args) {
        if (args == null || args.isEmpty()) return;
        sdl.append("(");
        boolean first = true;
        for (Map.Entry<String, String> arg : args.entrySet()) {
            if (!first) sdl.append(", ");
            sdl.append(arg.getKey()).append(": ").append(arg.getValue());
            first = false;
        }
        sdl.append(")");
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    private static String capitalize(String s) {
        if (s == null || s.isEmpty()) return s;
        return s.substring(0, 1).toUpperCase() + s.substring(1);
    }

    private static boolean isBuiltinScalar(String type) {
        switch (type) {
            case "Int": case "Float": case "String": case "Boolean": case "ID":
                return true;
            default:
                return false;
        }
    }
}
