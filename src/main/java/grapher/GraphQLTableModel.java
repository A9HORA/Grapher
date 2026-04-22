package grapher;

import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Table model for displaying captured GraphQL operations.
 *
 * Thread safety:
 *   - isDuplicate() and updateRequestResponse() are called from HTTP handler
 *     threads and the background JS parser thread
 *   - addEntry(), clear(), getEntry(), getValueAt() are called from the Swing EDT
 *   - All access to the entries list is synchronized on the list object
 */
public class GraphQLTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
            "#", "Timestamp", "Endpoint", "Method", "Source",
            "Operation Type", "Operation Name", "Persisted Hash", "Operation / Selection Body"
    };

    private final List<GraphQLEntry> entries = new ArrayList<>();
    private final Object lock = new Object();
    private final SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");

    @Override
    public int getRowCount() {
        synchronized (lock) {
            return entries.size();
        }
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) return Integer.class;
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        synchronized (lock) {
            if (rowIndex < 0 || rowIndex >= entries.size()) return "";
            GraphQLEntry entry = entries.get(rowIndex);

            switch (columnIndex) {
                case 0: return rowIndex + 1;
                case 1: return dateFormat.format(new Date(entry.timestamp()));
                case 2: return entry.endpoint();
                case 3: return entry.method();
                case 4: return entry.source().label();
                case 5: return entry.operationType();
                case 6: return entry.operationName();
                case 7: return entry.persistedHash() != null ? entry.persistedHash() : "";
                case 8: return entry.operationBody();
                default: return "";
            }
        }
    }

    /**
     * Add a new entry. Must be called from the Swing EDT.
     */
    public void addEntry(GraphQLEntry entry) {
        int row;
        synchronized (lock) {
            row = entries.size();
            entries.add(entry);
        }
        fireTableRowsInserted(row, row);
    }

    /**
     * Clear all entries. Must be called from the Swing EDT.
     */
    public void clear() {
        int size;
        synchronized (lock) {
            size = entries.size();
            if (size > 0) {
                entries.clear();
            }
        }
        if (size > 0) {
            fireTableRowsDeleted(0, size - 1);
        }
    }

    /**
     * Get entry at a specific row.
     */
    public GraphQLEntry getEntry(int row) {
        synchronized (lock) {
            if (row >= 0 && row < entries.size()) {
                return entries.get(row);
            }
            return null;
        }
    }

    /**
     * Get all entries (for export). Returns a snapshot copy.
     */
    public List<GraphQLEntry> getAllEntries() {
        synchronized (lock) {
            return new ArrayList<>(entries);
        }
    }

    /**
     * Check if an operation was already captured.
     * Thread-safe — called from handler threads.
     */
    public boolean isDuplicate(String endpoint, String opName, String opType, String hash) {
        synchronized (lock) {
            for (GraphQLEntry e : entries) {
                if (e.endpoint().equals(endpoint) &&
                    e.operationName().equals(opName) &&
                    e.operationType().equals(opType)) {
                    if (hash != null && hash.equals(e.persistedHash())) return true;
                    if (hash == null && e.persistedHash() == null) return true;
                    if (hash == null && (e.persistedHash() == null || e.persistedHash().isEmpty())) return true;
                }
            }
            return false;
        }
    }

    /**
     * Update the HttpRequestResponse and operationBody on an existing entry.
     * Keeps the longer operationBody (the more complete version).
     * Thread-safe — called from handler threads.
     */
    public void updateRequestResponse(String endpoint, String opName, String opType,
                                      HttpRequestResponse reqResp, String newBody) {
        synchronized (lock) {
            for (int i = 0; i < entries.size(); i++) {
                GraphQLEntry e = entries.get(i);
                if (e.endpoint().equals(endpoint) &&
                    e.operationName().equals(opName) &&
                    e.operationType().equals(opType)) {
                    // Only update if we have something better
                    boolean needsReqResp = !e.hasSendableRequest() && reqResp != null;
                    boolean needsBody = newBody != null && newBody.length() > e.operationBody().length();
                    
                    if (!needsReqResp && !needsBody) return;
                    
                    GraphQLEntry updated = new GraphQLEntry.Builder()
                            .url(e.url())
                            .endpoint(e.endpoint())
                            .method(e.method())
                            .source(e.source())
                            .operationType(e.operationType())
                            .operationName(e.operationName())
                            .persistedHash(e.persistedHash())
                            .operationBody(needsBody ? newBody : e.operationBody())
                            .requestResponse(needsReqResp ? reqResp : e.requestResponse())
                            .build();
                    entries.set(i, updated);
                    final int row = i;
                    SwingUtilities.invokeLater(() -> fireTableRowsUpdated(row, row));
                    return;
                }
            }
        }
    }
}
