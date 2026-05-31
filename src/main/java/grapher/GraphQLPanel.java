package grapher;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.table.TableRowSorter;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The Swing panel displayed as a custom tab in Burp Suite.
 *
 * BApp compliance:
 *   - All popup dialogs (JOptionPane, JFileChooser) are parented to
 *     SwingUtils.suiteFrame() for correct multi-monitor behavior.
 */
public class GraphQLPanel extends JPanel {

    private final GraphQLTableModel tableModel;
    private final MontoyaApi api;
    private final GrapherExtension extension;
    private final JTable table;
    private final TableRowSorter<GraphQLTableModel> sorter;
    private final JTextArea detailArea;
    private final JLabel statusLabel;
    private final JComboBox<String> sourceFilter;
    private final JComboBox<String> typeFilter;
    private final JTextField searchField;
    private JButton executeJsBtn;

    /**
     * Get the Burp Suite main frame for parenting dialogs.
     * Falls back to null (default screen) if unavailable.
     */
    private Frame getBurpFrame() {
        try {
            return api.userInterface().swingUtils().suiteFrame();
        } catch (Exception e) {
            return null;
        }
    }

    public GraphQLPanel(GraphQLTableModel model, MontoyaApi api, GrapherExtension extension) {
        this.tableModel = model;
        this.api = api;
        this.extension = extension;
        setLayout(new BorderLayout());

        // Initialize detail area early so toolbar lambdas can reference it
        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);

        // --- Top toolbar ---
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));

        toolbar.add(new JLabel("Source:"));
        sourceFilter = new JComboBox<>(new String[]{"All", "HTTP POST Body", "JS/Static File", "Minified/Obfuscated JS", "WebSocket Message", "Persisted Query Hash", "JS Executed (Node.js)"});
        sourceFilter.addActionListener(e -> applyFilters());
        toolbar.add(sourceFilter);

        toolbar.add(new JLabel("Type:"));
        typeFilter = new JComboBox<>(new String[]{"All", "query", "mutation", "subscription", "fragment", "persisted", "doc_id"});
        typeFilter.addActionListener(e -> applyFilters());
        toolbar.add(typeFilter);

        toolbar.add(Box.createHorizontalStrut(8));
        toolbar.add(new JLabel("Search:"));
        searchField = new JTextField(15);
        searchField.setToolTipText("Filter by operation name (case-insensitive)");
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
        });
        toolbar.add(searchField);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            tableModel.clear();
            detailArea.setText("");
            updateStatus();
        });
        toolbar.add(clearBtn);

        JButton exportBtn = new JButton("Export CSV");
        exportBtn.addActionListener(e -> exportCsv());
        toolbar.add(exportBtn);

        JButton importBtn = new JButton("Import CSV");
        importBtn.setToolTipText("Import a previously exported Grapher CSV");
        importBtn.addActionListener(e -> importCsv());
        toolbar.add(importBtn);

        JButton exportSchemaBtn = new JButton("Export .graphql");
        exportSchemaBtn.setToolTipText("Export inferred schema for GraphQL Voyager");
        exportSchemaBtn.addActionListener(e -> exportGraphqlSchema());
        toolbar.add(exportSchemaBtn);

        executeJsBtn = new JButton("Execute JS Bundles");
        executeJsBtn.setToolTipText("Run JS bundles in Node.js sandbox to capture dynamically assembled queries (requires Node.js)");
        executeJsBtn.addActionListener(e -> executeJsBundles());
        toolbar.add(executeJsBtn);

        JButton copyBtn = new JButton("Copy Selected");
        copyBtn.addActionListener(e -> copySelected());
        toolbar.add(copyBtn);

        statusLabel = new JLabel("0 operations captured");
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(statusLabel);

        add(toolbar, BorderLayout.NORTH);

        // --- Main split pane ---
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.7);

        // Table
        table = new JTable(tableModel);
        sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Column widths
        table.getColumnModel().getColumn(0).setPreferredWidth(40);
        table.getColumnModel().getColumn(1).setPreferredWidth(80);
        table.getColumnModel().getColumn(2).setPreferredWidth(200);
        table.getColumnModel().getColumn(3).setPreferredWidth(50);
        table.getColumnModel().getColumn(4).setPreferredWidth(120);
        table.getColumnModel().getColumn(5).setPreferredWidth(100);
        table.getColumnModel().getColumn(6).setPreferredWidth(150);
        table.getColumnModel().getColumn(7).setPreferredWidth(150);
        table.getColumnModel().getColumn(8).setPreferredWidth(300);

        // Color-code operation types
        table.getColumnModel().getColumn(5).setCellRenderer(new OperationTypeRenderer());

        // Selection listener -> update detail view
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow >= 0) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    GraphQLEntry entry = tableModel.getEntry(modelRow);
                    if (entry != null) {
                        showDetail(entry);
                    }
                }
            }
        });

        // ---------------------------------------------------------------
        // Right-click context menu
        // ---------------------------------------------------------------
        JPopupMenu contextMenu = new JPopupMenu();

        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> sendSelectedToRepeater());
        contextMenu.add(sendToRepeater);

        JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
        sendToIntruder.addActionListener(e -> sendSelectedToIntruder());
        contextMenu.add(sendToIntruder);

        contextMenu.addSeparator();

        JMenuItem copyMenuItem = new JMenuItem("Copy Operation");
        copyMenuItem.addActionListener(e -> copySelected());
        contextMenu.add(copyMenuItem);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                handlePopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                handlePopup(e);
            }

            private void handlePopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        table.setRowSelectionInterval(row, row);
                        int modelRow = table.convertRowIndexToModel(row);
                        GraphQLEntry entry = tableModel.getEntry(modelRow);

                        boolean canSend = canSendEntry(entry);
                        sendToRepeater.setEnabled(canSend);
                        sendToIntruder.setEnabled(canSend);

                        if (!canSend) {
                            String reason = getCannotSendReason(entry);
                            sendToRepeater.setToolTipText(reason);
                            sendToIntruder.setToolTipText(reason);
                        } else {
                            if (isJsSource(entry)) {
                                sendToRepeater.setToolTipText("Constructs a GraphQL POST using discovered endpoint");
                                sendToIntruder.setToolTipText("Constructs a GraphQL POST using discovered endpoint");
                            } else {
                                sendToRepeater.setToolTipText("Sends the original HTTP request");
                                sendToIntruder.setToolTipText("Sends the original HTTP request");
                            }
                        }

                        contextMenu.show(table, e.getX(), e.getY());
                    }
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(table);
        splitPane.setTopComponent(tableScroll);

        // Detail area (already initialized above)
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Operation Detail"));
        splitPane.setBottomComponent(detailScroll);

        add(splitPane, BorderLayout.CENTER);
    }

    // =========================================================================
    // Send to Repeater / Intruder
    // =========================================================================

    private void sendSelectedToRepeater() {
        GraphQLEntry entry = getSelectedEntry();
        if (entry == null) return;

        HttpRequest request = resolveRequest(entry);
        if (request == null) return;

        String tabName = entry.operationType() + " " + entry.operationName();
        api.repeater().sendToRepeater(request, tabName);
        api.logging().logToOutput("[+] Sent to Repeater (merged): " + tabName);
    }

    private void sendSelectedToIntruder() {
        GraphQLEntry entry = getSelectedEntry();
        if (entry == null) return;

        HttpRequest request = resolveRequest(entry);
        if (request == null) return;

        api.intruder().sendToIntruder(request);
        api.logging().logToOutput("[+] Sent to Intruder (merged): " +
                entry.operationType() + " " + entry.operationName());
    }

    /**
     * Get the merged operation body for an entry by combining all versions
     * of the same operation across all sources.
     */
    private String getMergedBody(GraphQLEntry entry) {
        // Find all entries with the same operation name and type
        List<GraphQLEntry> allVersions = new ArrayList<>();
        for (GraphQLEntry e : tableModel.getAllEntries()) {
            if (e.operationName().equals(entry.operationName()) &&
                e.operationType().equals(entry.operationType())) {
                allVersions.add(e);
            }
        }

        if (allVersions.size() <= 1) {
            // No other versions — use the entry's own body
            return entry.operationBody();
        }

        // Merge all versions
        List<OperationMerger.MergedOp> merged = OperationMerger.mergeAll(allVersions);
        if (!merged.isEmpty()) {
            return merged.get(0).mergedBody;
        }
        return entry.operationBody();
    }

    private HttpRequest resolveRequest(GraphQLEntry entry) {
        // Get the merged body from all sources
        String mergedBody = getMergedBody(entry);

        if (isJsSource(entry) || entry.source() == GraphQLEntry.Source.JS_EXECUTED) {
            // For JS source entries, pick the best extractedVariablesJson from all
            // sibling entries (prefer the one with the most keys)
            String bestVars = getMergedExtractedVariables(entry);
            HttpRequest constructed = extension.buildGqlRequest(
                    mergedBody, entry.operationName(),
                    entry.operationType(), entry.persistedHash(),
                    bestVars);
            if (constructed == null) {
                JOptionPane.showMessageDialog(getBurpFrame(),
                        "No GraphQL endpoint discovered yet.\n" +
                        "Browse the target to trigger at least one GraphQL POST request first,\n" +
                        "then try again.",
                        "No Endpoint Template", JOptionPane.WARNING_MESSAGE);
                return null;
            }
            return constructed;
        }

        if (entry.hasSendableRequest()) {
            // For HTTP POST entries, replace the query in the original request
            // with the merged version (which may have more fields from JS sources)
            HttpRequest original = entry.requestResponse().request();
            if (mergedBody != null && !mergedBody.equals(entry.operationBody())) {
                String originalBody = original.bodyToString();
                try {
                    String escapedMerged = escapeJsonString(mergedBody);

                    // Find the top-level "query" key by tracking brace depth.
                    // Only match "query" at depth 1 (inside the root JSON object)
                    // to avoid matching a "query" key nested inside "variables".
                    int qPos = findTopLevelJsonKey(originalBody, "query");
                    if (qPos >= 0) {
                        int colonPos = originalBody.indexOf(':', qPos + 7);
                        if (colonPos >= 0) {
                            int valStart = originalBody.indexOf('"', colonPos + 1);
                            if (valStart >= 0) {
                                int valEnd = valStart + 1;
                                while (valEnd < originalBody.length()) {
                                    char c = originalBody.charAt(valEnd);
                                    if (c == '\\' && valEnd + 1 < originalBody.length()) {
                                        valEnd += 2;
                                    } else if (c == '"') {
                                        break;
                                    } else {
                                        valEnd++;
                                    }
                                }
                                String newBody = originalBody.substring(0, valStart + 1) +
                                        escapedMerged +
                                        originalBody.substring(valEnd);

                                // Merge variables: the merged query body may reference
                                // variables that weren't in the original HTTP request
                                // (e.g. $authToken from a JS-discovered authenticated variant).
                                // Add missing variables with placeholders from JS extraction
                                // or type-based inference from the merged body signature.
                                newBody = mergeVariablesIntoRequest(newBody, mergedBody, entry);

                                return original.withBody(newBody);
                            }
                        }
                    }
                } catch (Exception ex) {
                    api.logging().logToError("Failed to merge body into request: " + ex.getMessage());
                }
            }
            return original;
        }

        return null;
    }

    /**
     * Merge variables into an HTTP request body. When the merged query body
     * references variables that the original HTTP request doesn't have
     * (e.g. $authToken from a JS-discovered authenticated variant), this method
     * adds them with values from JS-extracted call sites or type-based placeholders.
     *
     * Strategy:
     *   1. Parse variable names declared in the merged query body header
     *   2. Find the "variables" JSON object in the request body
     *   3. For each declared variable not already present in the request's variables:
     *      a. Check sibling entries' extractedVariablesJson for a value
     *      b. Fall back to type-based placeholder from the operation signature
     *   4. Inject the missing variables into the request's variables object
     */
    private String mergeVariablesIntoRequest(String requestBody, String mergedOpBody,
                                              GraphQLEntry entry) {
        try {
            // Step 1: Parse declared variables from the merged operation header
            Map<String, String> declaredVars = parseDeclaredVariables(mergedOpBody);
            if (declaredVars.isEmpty()) return requestBody;

            // Step 2: Find the "variables" object in the request body
            int varKeyPos = findTopLevelJsonKey(requestBody, "variables");
            if (varKeyPos < 0) return requestBody;

            String varKey = "\"variables\"";
            int colonPos = requestBody.indexOf(':', varKeyPos + varKey.length());
            if (colonPos < 0) return requestBody;

            int objStart = colonPos + 1;
            while (objStart < requestBody.length() && Character.isWhitespace(requestBody.charAt(objStart)))
                objStart++;
            if (objStart >= requestBody.length() || requestBody.charAt(objStart) != '{')
                return requestBody;

            // Find the balanced closing brace for the variables object
            int depth = 0;
            boolean inStr = false;
            int objEnd = objStart;
            while (objEnd < requestBody.length()) {
                char c = requestBody.charAt(objEnd);
                if (inStr) {
                    if (c == '\\' && objEnd + 1 < requestBody.length()) { objEnd += 2; continue; }
                    if (c == '"') inStr = false;
                    objEnd++;
                    continue;
                }
                if (c == '"') { inStr = true; objEnd++; continue; }
                if (c == '{') depth++;
                else if (c == '}') {
                    depth--;
                    if (depth == 0) { objEnd++; break; }
                }
                objEnd++;
            }

            String existingVarsJson = requestBody.substring(objStart, objEnd);

            // Step 3: Find which declared variables are missing from the existing JSON
            Map<String, String> missingVars = new LinkedHashMap<>();
            for (Map.Entry<String, String> dv : declaredVars.entrySet()) {
                String varName = dv.getKey();
                // Check if variable is already in the existing JSON
                if (existingVarsJson.contains("\"" + varName + "\"")) continue;
                // Not present — need to add it
                missingVars.put(varName, dv.getValue());
            }

            if (missingVars.isEmpty()) return requestBody;

            // Step 3a: Try to get values from sibling entries' extractedVariablesJson
            Map<String, String> jsExtractedValues = collectExtractedVariableValues(entry);

            // Step 4: Build the additions and inject
            StringBuilder additions = new StringBuilder();
            for (Map.Entry<String, String> mv : missingVars.entrySet()) {
                String varName = mv.getKey();
                String varType = mv.getValue();

                // Check JS-extracted values first
                String value = jsExtractedValues.get(varName);
                if (value == null) {
                    // Fall back to type-based placeholder
                    value = extension.getPlaceholderForType(varType);
                }

                additions.append(",\"").append(varName).append("\":").append(value);
            }

            // Insert before the closing } of the variables object
            String newVarsJson = existingVarsJson.substring(0, existingVarsJson.length() - 1) +
                    additions.toString() + "}";

            return requestBody.substring(0, objStart) + newVarsJson +
                    requestBody.substring(objEnd);

        } catch (Exception ex) {
            api.logging().logToError("Failed to merge variables: " + ex.getMessage());
            return requestBody;
        }
    }

    /**
     * Parse $varName: Type declarations from a GraphQL operation header.
     * Returns map of varName -> Type (e.g., "authToken" -> "String!").
     */
    private Map<String, String> parseDeclaredVariables(String operationBody) {
        Map<String, String> vars = new LinkedHashMap<>();
        int bracePos = operationBody.indexOf('{');
        if (bracePos < 0) return vars;

        String header = operationBody.substring(0, bracePos);
        int parenStart = header.indexOf('(');
        int parenEnd = header.lastIndexOf(')');
        if (parenStart < 0 || parenEnd <= parenStart) return vars;

        String varBlock = header.substring(parenStart + 1, parenEnd);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "\\$([A-Za-z_]\\w*)\\s*:\\s*([^$,)]+)").matcher(varBlock);
        while (m.find()) {
            vars.put(m.group(1), m.group(2).trim().replaceAll("[,\\s]+$", ""));
        }
        return vars;
    }

    /**
     * Collect extracted variable values from all sibling entries (same op name/type).
     * Parses each entry's extractedVariablesJson and merges key-value pairs.
     * Returns map of varName -> JSON value string (e.g., "authToken" -> "\"\"").
     */
    private Map<String, String> collectExtractedVariableValues(GraphQLEntry entry) {
        Map<String, String> values = new LinkedHashMap<>();
        for (GraphQLEntry e : tableModel.getAllEntries()) {
            if (!e.operationName().equals(entry.operationName()) ||
                !e.operationType().equals(entry.operationType())) continue;
            String json = e.extractedVariablesJson();
            if (json == null || json.isEmpty() || json.equals("{}")) continue;

            // Simple JSON key extraction — find "key": value pairs at depth 1
            parseJsonKeysAtDepth1(json, values);
        }
        return values;
    }

    /**
     * Extract key-value pairs at depth 1 from a JSON object string.
     * Values are kept as raw JSON fragments (e.g., "\"test\"", "null", "42", "{...}").
     */
    private void parseJsonKeysAtDepth1(String json, Map<String, String> out) {
        int depth = 0;
        boolean inStr = false;
        int i = 0;
        int len = json.length();

        while (i < len) {
            char c = json.charAt(i);
            if (inStr) {
                if (c == '\\' && i + 1 < len) { i += 2; continue; }
                if (c == '"') inStr = false;
                i++;
                continue;
            }
            if (c == '{' || c == '[') { depth++; i++; continue; }
            if (c == '}' || c == ']') { depth--; i++; continue; }
            if (c == '"' && depth == 1) {
                // Read key
                int keyStart = i + 1;
                int keyEnd = json.indexOf('"', keyStart);
                if (keyEnd < 0) break;
                String key = json.substring(keyStart, keyEnd);
                i = keyEnd + 1;
                // Skip to colon
                while (i < len && json.charAt(i) != ':') i++;
                if (i >= len) break;
                i++; // skip colon
                while (i < len && Character.isWhitespace(json.charAt(i))) i++;
                if (i >= len) break;
                // Read value — track balanced braces/brackets/strings
                int valStart = i;
                char vc = json.charAt(i);
                if (vc == '{' || vc == '[') {
                    // Balanced block
                    int d = 0;
                    boolean vs = false;
                    while (i < len) {
                        char cc = json.charAt(i);
                        if (vs) {
                            if (cc == '\\' && i + 1 < len) { i += 2; continue; }
                            if (cc == '"') vs = false;
                            i++; continue;
                        }
                        if (cc == '"') { vs = true; i++; continue; }
                        if (cc == '{' || cc == '[') d++;
                        else if (cc == '}' || cc == ']') {
                            d--;
                            if (d == 0) { i++; break; }
                        }
                        i++;
                    }
                } else if (vc == '"') {
                    // String value
                    i++;
                    while (i < len) {
                        if (json.charAt(i) == '\\' && i + 1 < len) { i += 2; continue; }
                        if (json.charAt(i) == '"') { i++; break; }
                        i++;
                    }
                } else {
                    // Number, boolean, null
                    while (i < len && json.charAt(i) != ',' && json.charAt(i) != '}' &&
                           json.charAt(i) != ']') i++;
                }
                String value = json.substring(valStart, i).trim();
                // Remove trailing comma if present
                if (value.endsWith(",")) value = value.substring(0, value.length() - 1).trim();
                out.putIfAbsent(key, value);
                continue;
            }
            i++;
        }
    }

    /**
     * Get the best extractedVariablesJson from all sibling entries.
     * Picks the longest non-null value (most complete extraction).
     */
    private String getMergedExtractedVariables(GraphQLEntry entry) {
        String best = entry.extractedVariablesJson();
        int bestLen = best != null ? best.length() : 0;

        for (GraphQLEntry e : tableModel.getAllEntries()) {
            if (!e.operationName().equals(entry.operationName()) ||
                !e.operationType().equals(entry.operationType())) continue;
            String vars = e.extractedVariablesJson();
            if (vars != null && vars.length() > bestLen) {
                best = vars;
                bestLen = vars.length();
            }
        }
        return best;
    }

    /**
     * Find the position of a top-level JSON key by tracking brace depth.
     * Only matches keys at depth 1 (directly inside the root { }).
     * Returns the position of the opening quote of the key, or -1 if not found.
     */
    private int findTopLevelJsonKey(String json, String keyName) {
        String target = "\"" + keyName + "\"";
        int depth = 0;
        boolean inString = false;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            if (inString) {
                if (c == '\\' && i + 1 < json.length()) {
                    i++; // skip escaped char
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }

            if (c == '"') {
                // Check if this is our target key at depth 1
                if (depth == 1 && i + target.length() <= json.length() &&
                    json.substring(i, i + target.length()).equals(target)) {
                    return i;
                }
                inString = true;
            } else if (c == '{' || c == '[') {
                depth++;
            } else if (c == '}' || c == ']') {
                depth--;
            }
        }
        return -1;
    }

    /**
     * Escape a string for embedding inside a JSON string value.
     * Must be called on already-unescaped content. Backslash-first ordering
     * ensures correct output without double-escaping.
     */
    private static String escapeJsonString(String s) {
        return s.replace("\\", "\\\\")  // must be first
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private boolean canSendEntry(GraphQLEntry entry) {
        if (entry == null) return false;
        if (isJsSource(entry) || entry.source() == GraphQLEntry.Source.JS_EXECUTED) {
            return entry.operationBody() != null && !entry.operationBody().isEmpty();
        }
        return entry.hasSendableRequest();
    }

    private String getCannotSendReason(GraphQLEntry entry) {
        if (entry == null) return "No entry selected";
        if ((isJsSource(entry) || entry.source() == GraphQLEntry.Source.JS_EXECUTED) &&
            (entry.operationBody() == null || entry.operationBody().isEmpty())) {
            return "No operation body extracted";
        }
        if (!entry.hasSendableRequest()) {
            return "No HTTP request available";
        }
        return "";
    }

    private boolean isJsSource(GraphQLEntry entry) {
        return entry != null &&
               (entry.source() == GraphQLEntry.Source.JS_FILE ||
                entry.source() == GraphQLEntry.Source.MINIFIED_JS ||
                entry.source() == GraphQLEntry.Source.JS_EXECUTED);
    }

    private GraphQLEntry getSelectedEntry() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = table.convertRowIndexToModel(viewRow);
        return tableModel.getEntry(modelRow);
    }

    // =========================================================================
    // UI helpers
    // =========================================================================

    public void updateStatus() {
        int total = tableModel.getRowCount();
        int visible = table.getRowCount();
        String searchText = searchField.getText().trim();

        if (total == visible) {
            statusLabel.setText(total + " operations captured");
        } else if (!searchText.isEmpty()) {
            statusLabel.setText(visible + " entries matching \"" + searchText + "\" (from " + total + " total)");
        } else {
            statusLabel.setText(visible + " / " + total + " operations shown");
        }
    }

    private void applyFilters() {
        List<RowFilter<GraphQLTableModel, Integer>> filters = new ArrayList<>();

        String sourceSel = (String) sourceFilter.getSelectedItem();
        if (sourceSel != null && !sourceSel.equals("All")) {
            filters.add(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(sourceSel) + "$", 4));
        }

        String typeSel = (String) typeFilter.getSelectedItem();
        if (typeSel != null && !typeSel.equals("All")) {
            filters.add(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(typeSel) + "$", 5));
        }

        String searchText = searchField.getText().trim();
        if (!searchText.isEmpty()) {
            // Case-insensitive match on operation name column (index 6)
            filters.add(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(searchText), 6));
        }

        if (filters.size() > 1) {
            sorter.setRowFilter(RowFilter.andFilter(filters));
        } else if (filters.size() == 1) {
            sorter.setRowFilter(filters.get(0));
        } else {
            sorter.setRowFilter(null);
        }
        updateStatus();
    }

    private void showDetail(GraphQLEntry entry) {
        StringBuilder sb = new StringBuilder();
        sb.append("URL:            ").append(entry.url()).append("\n");
        sb.append("Endpoint:       ").append(entry.endpoint()).append("\n");
        sb.append("Method:         ").append(entry.method()).append("\n");
        sb.append("Source:         ").append(entry.source().label()).append("\n");
        sb.append("Operation Type: ").append(entry.operationType()).append("\n");
        sb.append("Operation Name: ").append(entry.operationName()).append("\n");
        if (entry.persistedHash() != null && !entry.persistedHash().isEmpty()) {
            sb.append("Persisted Hash: ").append(entry.persistedHash()).append("\n");
        }
        if (isJsSource(entry)) {
            sb.append("Send Action:    Constructs GraphQL POST from discovered endpoint\n");
        } else if (entry.hasSendableRequest()) {
            sb.append("Send Action:    Sends original HTTP request\n");
        }
        if (!entry.tags().isEmpty()) {
            sb.append("Tags:           ").append(String.join(", ", entry.tags())).append("\n");
        }
        if (entry.extractedVariablesJson() != null) {
            sb.append("Extracted Vars: ").append(entry.extractedVariablesJson()).append("\n");
        }
        sb.append("\n--- Operation / Selection Body ---\n");
        sb.append(entry.operationBody());
        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    // =========================================================================
    // Export / Import — all dialogs parented to getBurpFrame()
    // =========================================================================

    private void exportCsv() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("graphql_operations.csv"));
        if (fc.showSaveDialog(getBurpFrame()) == JFileChooser.APPROVE_OPTION) {
            try (FileWriter fw = new FileWriter(fc.getSelectedFile())) {
                fw.write("Endpoint,Method,Source,OperationType,OperationName,PersistedHash,URL,OperationSelectionBody\n");

                // Merge all versions of each operation into one complete entry
                List<OperationMerger.MergedOp> merged = OperationMerger.mergeAll(tableModel.getAllEntries());

                for (OperationMerger.MergedOp op : merged) {
                    fw.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                            csvEscape(op.endpoint), csvEscape(op.method),
                            csvEscape(op.source), csvEscape(op.operationType),
                            csvEscape(op.operationName), csvEscape(op.persistedHash != null ? op.persistedHash : ""),
                            csvEscape(op.url), csvEscape(op.mergedBody)));
                }

                int total = tableModel.getRowCount();
                int exported = merged.size();
                JOptionPane.showMessageDialog(getBurpFrame(),
                        "Exported " + exported + " merged operations (from " + total + " total entries).",
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(getBurpFrame(), "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void exportGraphqlSchema() {
        List<GraphQLEntry> entries = tableModel.getAllEntries();
        if (entries.isEmpty()) {
            JOptionPane.showMessageDialog(getBurpFrame(), "No operations captured yet.",
                    "Nothing to Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Merge operations before schema inference — combines fields from all sources
        List<OperationMerger.MergedOp> merged = OperationMerger.mergeAll(entries);
        List<GraphQLEntry> mergedEntries = new ArrayList<>();
        for (OperationMerger.MergedOp op : merged) {
            mergedEntries.add(new GraphQLEntry.Builder()
                    .url(op.url)
                    .endpoint(op.endpoint)
                    .method(op.method)
                    .source(GraphQLEntry.Source.HTTP_POST) // source doesn't matter for schema inference
                    .operationType(op.operationType)
                    .operationName(op.operationName)
                    .persistedHash(op.persistedHash)
                    .operationBody(op.mergedBody)
                    .requestResponse(null)
                    .build());
        }

        SchemaInferrer inferrer = new SchemaInferrer();
        String sdl = inferrer.inferSchema(mergedEntries);

        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("inferred_schema.graphql"));
        if (fc.showSaveDialog(getBurpFrame()) == JFileChooser.APPROVE_OPTION) {
            try (FileWriter fw = new FileWriter(fc.getSelectedFile())) {
                fw.write(sdl);
                JOptionPane.showMessageDialog(getBurpFrame(),
                        "Inferred schema exported.\n" +
                        "Import into GraphQL Voyager to visualize.",
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(getBurpFrame(), "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importCsv() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Import Grapher CSV");
        if (fc.showOpenDialog(getBurpFrame()) != JFileChooser.APPROVE_OPTION) return;

        File file = fc.getSelectedFile();
        int imported = 0;
        int skipped = 0;

        try (java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(file))) {
            String headerLine = br.readLine();
            if (headerLine == null) {
                JOptionPane.showMessageDialog(getBurpFrame(), "Empty file.",
                        "Import Failed", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (!headerLine.contains("OperationType") || !headerLine.contains("OperationName")) {
                JOptionPane.showMessageDialog(getBurpFrame(),
                        "Invalid CSV format. Expected a Grapher export with columns:\n" +
                        "Endpoint, Method, Source, OperationType, OperationName, PersistedHash, URL, OperationSelectionBody",
                        "Import Failed", JOptionPane.ERROR_MESSAGE);
                return;
            }

            String line;
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty()) continue;

                String[] fields = parseCsvLine(line);
                if (fields.length < 8) { skipped++; continue; }

                String endpoint = fields[0];
                String method = fields[1];
                String sourceLabel = fields[2];
                String opType = fields[3];
                String opName = fields[4];
                String hash = fields[5].isEmpty() ? null : fields[5];
                String url = fields[6];
                String opBody = fields[7];

                GraphQLEntry.Source source = labelToSource(sourceLabel);

                if (tableModel.isDuplicate(endpoint, opName, opType, hash)) {
                    skipped++;
                    continue;
                }

                GraphQLEntry entry = new GraphQLEntry.Builder()
                        .url(url)
                        .endpoint(endpoint)
                        .method(method)
                        .source(source)
                        .operationType(opType)
                        .operationName(opName)
                        .persistedHash(hash)
                        .operationBody(opBody)
                        .requestResponse(null)
                        .build();

                tableModel.addEntry(entry);
                imported++;
            }

            updateStatus();
            JOptionPane.showMessageDialog(getBurpFrame(),
                    "Imported " + imported + " operations" +
                    (skipped > 0 ? " (" + skipped + " duplicates/invalid skipped)" : "") + ".",
                    "Import Complete", JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(getBurpFrame(), "Import failed: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Execute captured JS bundle URLs through Node.js to capture dynamically
     * assembled GraphQL operations that regex-based parsing can't reconstruct.
     *
     * Flow:
     *   1. Extract the companion Node.js script from the JAR resources
     *   2. For each JS_FILE / MINIFIED_JS entry, save the response body to a temp file
     *   3. Run: node grapher-executor.js <temp_js_file>
     *   4. Parse stdout JSON lines as captured GraphQL operations
     *   5. Add results to the table with source "JS Executed (Node.js)"
     */
    private void executeJsBundles() {
        // Find Node.js binary — searches common paths since Burp may not inherit shell PATH
        String nodePath = findNodePath();
        if (nodePath == null) {
            // Auto-discovery failed — let the user provide the path
            int choice = JOptionPane.showOptionDialog(getBurpFrame(),
                    "Node.js was not found automatically.\n\n" +
                    "Searched PATH, /usr/local/bin, /opt/homebrew/bin, ~/.nvm, and common locations.\n\n" +
                    "Would you like to locate the Node.js binary manually?",
                    "Node.js Not Found",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                    null,
                    new String[]{"Browse...", "Cancel"},
                    "Browse...");

            if (choice != 0) return;

            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select Node.js binary");
            fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
            // Start in a sensible location
            String os = System.getProperty("os.name", "").toLowerCase();
            if (os.contains("mac")) {
                fc.setCurrentDirectory(new java.io.File("/usr/local/bin"));
            } else if (os.contains("win")) {
                fc.setCurrentDirectory(new java.io.File("C:\\Program Files\\nodejs"));
            } else {
                fc.setCurrentDirectory(new java.io.File("/usr/bin"));
            }

            if (fc.showOpenDialog(getBurpFrame()) != JFileChooser.APPROVE_OPTION) return;

            nodePath = fc.getSelectedFile().getAbsolutePath();

            // Validate the selected binary
            try {
                ProcessBuilder pb = new ProcessBuilder(nodePath, "--version");
                pb.redirectErrorStream(true);
                Process p = pb.start();
                java.io.BufferedReader r = new java.io.BufferedReader(
                        new java.io.InputStreamReader(p.getInputStream()));
                String version = r.readLine();
                boolean finished = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                if (!finished || p.exitValue() != 0) {
                    JOptionPane.showMessageDialog(getBurpFrame(),
                            "The selected file is not a valid Node.js binary.",
                            "Invalid Selection", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                api.logging().logToOutput("[+] User-provided Node.js: " + nodePath + " (" + version + ")");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(getBurpFrame(),
                        "Failed to run the selected file: " + ex.getMessage(),
                        "Invalid Selection", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }

        // Collect JS file entries that have response bodies
        List<GraphQLEntry> jsEntries = new ArrayList<>();
        for (GraphQLEntry e : tableModel.getAllEntries()) {
            if ((e.source() == GraphQLEntry.Source.JS_FILE ||
                 e.source() == GraphQLEntry.Source.MINIFIED_JS) &&
                e.hasSendableRequest() && e.requestResponse().response() != null) {
                jsEntries.add(e);
            }
        }

        if (jsEntries.isEmpty()) {
            JOptionPane.showMessageDialog(getBurpFrame(),
                    "No JS files with response bodies found.\n" +
                    "Browse the target first so Grapher captures JS responses.",
                    "Nothing to Execute", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Extract the executor script from JAR resources
        java.io.File scriptFile;
        try {
            scriptFile = extractExecutorScript();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(getBurpFrame(),
                    "Failed to extract executor script: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Deduplicate by URL — don't execute the same JS file twice

        // Fix 8: Warning dialog about sandbox limitations
        int confirm = JOptionPane.showConfirmDialog(getBurpFrame(),
                "Execute JS Bundles runs untrusted JavaScript from the target\n" +
                "in a sandboxed Node.js environment.\n\n" +
                "While the sandbox restricts file and network access and uses\n" +
                "security flags to block common escape vectors, it is not a\n" +
                "complete security boundary.\n\n" +
                "Only execute JS from targets you trust.\n\n" +
                "Proceed?",
                "Security Notice", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        // Fix 5: Disable button while running
        executeJsBtn.setEnabled(false);

        // Run in background thread to avoid blocking UI
        final java.io.File finalScriptFile = scriptFile;
        final String finalNodePath = nodePath;
        Thread executorThread = new Thread(() -> {
            int captured = 0;
            int processed = 0;
            java.util.Set<String> seen = new java.util.HashSet<>();

            for (GraphQLEntry entry : jsEntries) {
                // Check for interrupt (extension unload)
                if (Thread.currentThread().isInterrupted()) break;

                if (seen.contains(entry.url())) continue;
                seen.add(entry.url());

                try {
                    // Save JS response body to a temp file
                    String jsBody = entry.requestResponse().response().bodyToString();
                    if (jsBody == null || jsBody.length() < 100) continue;

                    java.io.File tempJs = java.io.File.createTempFile("grapher_js_", ".js");
                    tempJs.deleteOnExit();
                    try (java.io.FileWriter fw = new java.io.FileWriter(tempJs)) {
                        fw.write(jsBody);
                    }

                    // Fix 7: Execute with security flags to block common VM escape vectors
                    ProcessBuilder pb = new ProcessBuilder(finalNodePath,
                            "--disable-proto=throw",
                            "--disallow-code-generation-from-strings",
                            finalScriptFile.getAbsolutePath(),
                            tempJs.getAbsolutePath());
                    pb.redirectErrorStream(false);
                    Process proc = pb.start();

                    // Read stdout for captured operations
                    java.io.BufferedReader reader = new java.io.BufferedReader(
                            new java.io.InputStreamReader(proc.getInputStream()));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (line.isEmpty() || !line.startsWith("{")) continue;

                        try {
                            // Parse JSON line — extract query/doc_id and operationName
                            String query = extractJsonField(line, "query");
                            String docId = extractJsonField(line, "doc_id");
                            String opName = extractJsonField(line, "operationName");

                            if (query != null && !query.isEmpty()) {
                                // Parse the query string for operation type and name
                                List<GraphQLParser.ParsedOp> ops = GraphQLParser.parseQueryString(query, opName);
                                for (GraphQLParser.ParsedOp op : ops) {
                                    final String url = entry.url();
                                    final String endpoint = entry.endpoint();
                                    SwingUtilities.invokeLater(() -> {
                                        if (!tableModel.isDuplicate(endpoint, op.name, op.type, op.hash)) {
                                            GraphQLEntry newEntry = new GraphQLEntry.Builder()
                                                    .url(url)
                                                    .endpoint(endpoint)
                                                    .method("GET")
                                                    .source(GraphQLEntry.Source.JS_EXECUTED)
                                                    .operationType(op.type)
                                                    .operationName(op.name)
                                                    .persistedHash(op.hash)
                                                    .operationBody(op.snippet)
                                                    .requestResponse(null)
                                                    .build();
                                            tableModel.addEntry(newEntry);
                                            updateStatus();
                                        }
                                    });
                                    captured++;
                                }
                            } else if (docId != null && !docId.isEmpty()) {
                                final String url = entry.url();
                                final String endpoint = entry.endpoint();
                                final String fDocId = docId;
                                final String fOpName = (opName != null && !opName.isEmpty()) ? opName : "anonymous";
                                SwingUtilities.invokeLater(() -> {
                                    if (!tableModel.isDuplicate(endpoint, fOpName, "doc_id", fDocId)) {
                                        GraphQLEntry newEntry = new GraphQLEntry.Builder()
                                                .url(url)
                                                .endpoint(endpoint)
                                                .method("GET")
                                                .source(GraphQLEntry.Source.JS_EXECUTED)
                                                .operationType("doc_id")
                                                .operationName(fOpName)
                                                .persistedHash(fDocId)
                                                .operationBody("doc_id: " + fDocId + " (" + fOpName + ")")
                                                .requestResponse(null)
                                                .build();
                                        tableModel.addEntry(newEntry);
                                        updateStatus();
                                    }
                                });
                                captured++;
                            }
                        } catch (Exception parseEx) {
                            // Skip malformed JSON lines
                        }
                    }

                    // Wait for process with timeout
                    boolean finished = proc.waitFor(15, java.util.concurrent.TimeUnit.SECONDS);
                    if (!finished) {
                        proc.destroyForcibly();
                    }

                    // Clean up temp JS file
                    tempJs.delete();
                    processed++;

                } catch (Exception ex) {
                    api.logging().logToError("JS execution error for " + entry.url() + ": " + ex.getMessage());
                }
            }

            final int fCaptured = captured;
            final int fProcessed = processed;
            SwingUtilities.invokeLater(() -> {
                executeJsBtn.setEnabled(true);
                updateStatus();
                JOptionPane.showMessageDialog(getBurpFrame(),
                        "Executed " + fProcessed + " JS bundles.\n" +
                        "Captured " + fCaptured + " additional operations.",
                        "JS Execution Complete", JOptionPane.INFORMATION_MESSAGE);
            });

        }, "Grapher-JSExecutor");
        // Fix 6: Register thread with extension for clean shutdown
        extension.setJsExecutorThread(executorThread);
        executorThread.start();
    }

    /**
     * Find the Node.js binary path. Burp's JRE may not inherit the user's
     * shell PATH, so we search common installation locations.
     * Returns the full path to node, or null if not found.
     */
    private String findNodePath() {
        // Try bare "node" first (works if Burp inherits PATH)
        String[] candidates;
        String os = System.getProperty("os.name", "").toLowerCase();

        if (os.contains("mac")) {
            candidates = new String[]{
                "node",
                "/usr/local/bin/node",
                "/opt/homebrew/bin/node",
                System.getProperty("user.home") + "/.nvm/current/bin/node",
                "/usr/local/opt/node/bin/node",
            };
        } else if (os.contains("win")) {
            candidates = new String[]{
                "node",
                "node.exe",
                "C:\\Program Files\\nodejs\\node.exe",
                System.getenv("APPDATA") + "\\nvm\\current\\node.exe",
            };
        } else {
            // Linux
            candidates = new String[]{
                "node",
                "/usr/bin/node",
                "/usr/local/bin/node",
                System.getProperty("user.home") + "/.nvm/current/bin/node",
                "/snap/bin/node",
            };
        }

        // Also check NVM_DIR if set
        String nvmDir = System.getenv("NVM_DIR");
        List<String> allCandidates = new ArrayList<>(java.util.Arrays.asList(candidates));
        if (nvmDir != null && !nvmDir.isEmpty()) {
            allCandidates.add(nvmDir + "/current/bin/node");
            // Try to find the default version
            java.io.File nvmVersions = new java.io.File(nvmDir, "versions/node");
            if (nvmVersions.isDirectory()) {
                java.io.File[] versions = nvmVersions.listFiles();
                if (versions != null) {
                    for (java.io.File v : versions) {
                        allCandidates.add(v.getAbsolutePath() + "/bin/node");
                    }
                }
            }
        }

        for (String candidate : allCandidates) {
            try {
                ProcessBuilder pb = new ProcessBuilder(candidate, "--version");
                pb.redirectErrorStream(true);
                Process p = pb.start();
                boolean finished = p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
                if (finished && p.exitValue() == 0) {
                    // Read version for logging
                    java.io.BufferedReader r = new java.io.BufferedReader(
                            new java.io.InputStreamReader(p.getInputStream()));
                    String version = r.readLine();
                    api.logging().logToOutput("[+] Found Node.js: " + candidate + " (" + version + ")");
                    return candidate;
                }
            } catch (Exception e) {
                // Try next candidate
            }
        }

        return null;
    }

    /**
     * Extract the grapher-executor.js script from JAR resources to a temp file.
     */
    private java.io.File extractExecutorScript() throws Exception {
        java.io.File scriptFile = java.io.File.createTempFile("grapher-executor-", ".js");
        scriptFile.deleteOnExit();

        try (java.io.InputStream is = getClass().getResourceAsStream("/grapher-executor.js");
             java.io.FileOutputStream fos = new java.io.FileOutputStream(scriptFile)) {
            if (is == null) {
                throw new RuntimeException("grapher-executor.js not found in JAR resources");
            }
            byte[] buffer = new byte[4096];
            int len;
            while ((len = is.read(buffer)) != -1) {
                fos.write(buffer, 0, len);
            }
        }

        return scriptFile;
    }

    /**
     * Extract the string value of a top-level JSON field.
     * Uses depth tracking to avoid matching nested keys with the same name.
     * Unescapes the value with backslash-last ordering (reverse of escapeJsonString).
     */
    private String extractJsonField(String json, String fieldName) {
        // Find the key at top level (depth 1)
        int keyPos = findTopLevelJsonKey(json, fieldName);
        if (keyPos < 0) return null;

        String key = "\"" + fieldName + "\"";
        int colonPos = json.indexOf(':', keyPos + key.length());
        if (colonPos < 0) return null;

        // Skip whitespace after colon
        int i = colonPos + 1;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        if (i >= json.length()) return null;

        if (json.charAt(i) == '"') {
            // String value — walk to closing quote, handling escapes
            int start = i + 1;
            int end = start;
            while (end < json.length()) {
                if (json.charAt(end) == '\\' && end + 1 < json.length()) {
                    end += 2; // skip escaped char
                } else if (json.charAt(end) == '"') {
                    break;
                } else {
                    end++;
                }
            }
            // Unescape: backslash-last ordering (reverse of escape)
            return json.substring(start, end)
                    .replace("\\n", "\n").replace("\\r", "\r")
                    .replace("\\t", "\t").replace("\\\"", "\"")
                    .replace("\\\\", "\\");
        }

        return null;
    }

    private String[] parseCsvLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        int i = 0;

        while (i < line.length()) {
            char c = line.charAt(i);

            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        current.append('"');
                        i += 2;
                    } else {
                        inQuotes = false;
                        i++;
                    }
                } else {
                    current.append(c);
                    i++;
                }
            } else {
                if (c == '"') {
                    inQuotes = true;
                    i++;
                } else if (c == ',') {
                    fields.add(current.toString());
                    current = new StringBuilder();
                    i++;
                } else {
                    current.append(c);
                    i++;
                }
            }
        }
        fields.add(current.toString());

        return fields.toArray(new String[0]);
    }

    private GraphQLEntry.Source labelToSource(String label) {
        for (GraphQLEntry.Source s : GraphQLEntry.Source.values()) {
            if (s.label().equals(label)) return s;
        }
        return GraphQLEntry.Source.HTTP_POST;
    }

    private void copySelected() {
        GraphQLEntry entry = getSelectedEntry();
        if (entry == null) return;

        String text = entry.operationType() + " " + entry.operationName() +
                " | " + entry.endpoint() + " | " + entry.source().label();
        if (entry.persistedHash() != null && !entry.persistedHash().isEmpty()) {
            text += " | hash=" + entry.persistedHash();
        }

        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                new StringSelection(text), null);
    }

    private static String csvEscape(String s) {
        if (s == null) return "";
        return s.replace("\"", "\"\"").replace("\n", " ").replace("\r", "");
    }

    private static class OperationTypeRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected && value instanceof String) {
                switch ((String) value) {
                    case "mutation":
                        c.setForeground(new Color(204, 0, 0));
                        break;
                    case "subscription":
                        c.setForeground(new Color(0, 128, 0));
                        break;
                    case "query":
                        c.setForeground(new Color(0, 0, 180));
                        break;
                    case "persisted":
                        c.setForeground(new Color(180, 100, 0));
                        break;
                    case "fragment":
                        c.setForeground(new Color(128, 0, 128));
                        break;
                    case "doc_id":
                        c.setForeground(new Color(0, 100, 180));
                        break;
                    default:
                        c.setForeground(Color.BLACK);
                }
            } else if (!isSelected) {
                c.setForeground(Color.BLACK);
            }
            return c;
        }
    }
}
