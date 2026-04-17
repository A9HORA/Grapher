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
        sourceFilter = new JComboBox<>(new String[]{"All", "HTTP POST Body", "JS/Static File", "Minified/Obfuscated JS", "WebSocket Message", "Persisted Query Hash"});
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
