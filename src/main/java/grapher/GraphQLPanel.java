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
import java.util.List;

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

        JButton executeJsBtn = new JButton("Execute JS Bundles");
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
        api.logging().logToOutput("[+] Sent to Repeater: " + tabName);
    }

    private void sendSelectedToIntruder() {
        GraphQLEntry entry = getSelectedEntry();
        if (entry == null) return;

        HttpRequest request = resolveRequest(entry);
        if (request == null) return;

        api.intruder().sendToIntruder(request);
        api.logging().logToOutput("[+] Sent to Intruder: " +
                entry.operationType() + " " + entry.operationName());
    }

    private HttpRequest resolveRequest(GraphQLEntry entry) {
        if (isJsSource(entry)) {
            HttpRequest constructed = extension.buildGqlRequest(
                    entry.operationBody(), entry.operationName(),
                    entry.operationType(), entry.persistedHash());
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
            return entry.requestResponse().request();
        }

        return null;
    }

    private boolean canSendEntry(GraphQLEntry entry) {
        if (entry == null) return false;
        if (isJsSource(entry)) {
            return entry.operationBody() != null && !entry.operationBody().isEmpty();
        }
        return entry.hasSendableRequest();
    }

    private String getCannotSendReason(GraphQLEntry entry) {
        if (entry == null) return "No entry selected";
        if (isJsSource(entry) && (entry.operationBody() == null || entry.operationBody().isEmpty())) {
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
                entry.source() == GraphQLEntry.Source.MINIFIED_JS);
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
        if (total == visible) {
            statusLabel.setText(total + " operations captured");
        } else {
            statusLabel.setText(visible + " / " + total + " operations shown");
        }
    }

    private void applyFilters() {
        RowFilter<GraphQLTableModel, Integer> sourceRowFilter = null;
        RowFilter<GraphQLTableModel, Integer> typeRowFilter = null;

        String sourceSel = (String) sourceFilter.getSelectedItem();
        if (sourceSel != null && !sourceSel.equals("All")) {
            sourceRowFilter = RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(sourceSel) + "$", 4);
        }

        String typeSel = (String) typeFilter.getSelectedItem();
        if (typeSel != null && !typeSel.equals("All")) {
            typeRowFilter = RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(typeSel) + "$", 5);
        }

        if (sourceRowFilter != null && typeRowFilter != null) {
            sorter.setRowFilter(RowFilter.andFilter(java.util.List.of(sourceRowFilter, typeRowFilter)));
        } else if (sourceRowFilter != null) {
            sorter.setRowFilter(sourceRowFilter);
        } else if (typeRowFilter != null) {
            sorter.setRowFilter(typeRowFilter);
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
                for (GraphQLEntry e : tableModel.getAllEntries()) {
                    fw.write(String.format("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                            csvEscape(e.endpoint()), csvEscape(e.method()),
                            csvEscape(e.source().label()), csvEscape(e.operationType()),
                            csvEscape(e.operationName()), csvEscape(e.persistedHash() != null ? e.persistedHash() : ""),
                            csvEscape(e.url()), csvEscape(e.operationBody())));
                }
                JOptionPane.showMessageDialog(getBurpFrame(), "Exported " + tableModel.getRowCount() + " entries.",
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

        SchemaInferrer inferrer = new SchemaInferrer();
        String sdl = inferrer.inferSchema(entries);

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
        java.util.Set<String> processedUrls = new java.util.HashSet<>();
        int totalCaptured = 0;
        int filesProcessed = 0;

        // Run in background thread to avoid blocking UI
        final java.io.File finalScriptFile = scriptFile;
        final String finalNodePath = nodePath;
        new Thread(() -> {
            int captured = 0;
            int processed = 0;
            java.util.Set<String> seen = new java.util.HashSet<>();

            for (GraphQLEntry entry : jsEntries) {
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

                    // Execute: node grapher-executor.js <temp_js_file>
                    ProcessBuilder pb = new ProcessBuilder(finalNodePath, finalScriptFile.getAbsolutePath(), tempJs.getAbsolutePath());
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
                updateStatus();
                JOptionPane.showMessageDialog(getBurpFrame(),
                        "Executed " + fProcessed + " JS bundles.\n" +
                        "Captured " + fCaptured + " additional operations.",
                        "JS Execution Complete", JOptionPane.INFORMATION_MESSAGE);
            });

        }, "Grapher-JSExecutor").start();
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
     * Simple JSON field extractor — avoids adding a JSON library dependency.
     * Extracts the string value of a top-level field from a JSON object.
     */
    private String extractJsonField(String json, String fieldName) {
        String key = "\"" + fieldName + "\"";
        int keyPos = json.indexOf(key);
        if (keyPos < 0) return null;

        int colonPos = json.indexOf(':', keyPos + key.length());
        if (colonPos < 0) return null;

        // Skip whitespace after colon
        int i = colonPos + 1;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        if (i >= json.length()) return null;

        if (json.charAt(i) == '"') {
            // String value
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
            return json.substring(start, end)
                    .replace("\\n", "\n").replace("\\t", "\t")
                    .replace("\\\"", "\"").replace("\\\\", "\\");
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
