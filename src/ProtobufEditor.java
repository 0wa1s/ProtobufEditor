package burp;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.regex.*;

/**
 * ProtobufEditor – Burp Suite Extension
 *
 * Features:
 *  1. Standalone editor tab: right-click → Send to Protobuf Editor,
 *     edit JSON, click Send.
 *  2. Intruder integration: mark fuzz positions inside the JSON with
 *     the § character (e.g. §originalValue§), click "Send to Intruder".
 *     In Intruder → Payloads → Payload Processing add rule:
 *       Invoke Burp extension → Protobuf Re-encoder
 *     The processor substitutes each payload into the §marks§ and
 *     re-encodes to protobuf before Intruder sends the request.
 *
 * Install: Extender → Add → Java → ProtobufEditor.jar
 */
public class ProtobufEditor implements IBurpExtender, ITab, IContextMenuFactory,
        IIntruderPayloadProcessor {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers      helpers;
    private EditorPanel            editorPanel;

    // Shared state written by UI thread, read by Intruder processor threads
    volatile String  intruderJsonTemplate = null;
    volatile boolean intruderHasGrpcFrame = false;
    volatile byte    intruderGrpcFlag     = 0;
    volatile String  intruderMsgName      = "";
    volatile boolean intruderApplyNames   = true;
    // protoMappings is only modified on EDT, read by processor threads (safe for reads)
    final Map<String, Map<String, String>> protoMappings = new LinkedHashMap<>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
        this.callbacks = cb;
        this.helpers   = cb.getHelpers();
        cb.setExtensionName("Protobuf Editor");
        cb.registerContextMenuFactory(this);
        cb.registerIntruderPayloadProcessor(this);
        editorPanel = new EditorPanel(cb, helpers, this);
        cb.addSuiteTab(this);
        cb.printOutput("[ProtobufEditor] Loaded. Intruder processor: 'Protobuf Re-encoder'");
    }

    @Override public String    getTabCaption()     { return "Protobuf Editor"; }
    @Override public Component getUiComponent()    { return editorPanel; }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation inv) {
        IHttpRequestResponse[] msgs = inv.getSelectedMessages();
        if (msgs == null || msgs.length == 0) return null;
        JMenuItem item = new JMenuItem("Send to Protobuf Editor");
        item.addActionListener(e ->
                SwingUtilities.invokeLater(() -> editorPanel.loadRequest(msgs[0])));
        return Collections.singletonList(item);
    }

    // ── IIntruderPayloadProcessor ─────────────────────────────────────────────
    // Called by Burp on Intruder threads for every payload in the attack.
    // currentPayload = the fuzz string bytes for this iteration.
    // We take the JSON template (with §marks§), substitute the payload,
    // re-encode to protobuf, and return the bytes. Burp replaces the
    // body with whatever we return.

    @Override
    public String getProcessorName() { return "Protobuf Re-encoder"; }

    @Override
    public byte[] processPayload(byte[] currentPayload,
                                 byte[] originalPayload,
                                 byte[] baseValue) {
        String template = intruderJsonTemplate;
        if (template == null || template.isEmpty()) {
            callbacks.printError("[ProtobufEditor] Processor called but no template set. " +
                    "Click 'Send to Intruder' in the editor first.");
            return currentPayload;
        }

        String payloadStr;
        try { payloadStr = new String(currentPayload, StandardCharsets.UTF_8); }
        catch (Exception e) { payloadStr = new String(currentPayload, StandardCharsets.ISO_8859_1); }

        // Substitute ALL §...§ markers with the current payload (JSON-escaped)
        String filledJson = template.replaceAll(
                "\u00a7[^\u00a7]*\u00a7",
                Matcher.quoteReplacement(escapeJsonString(payloadStr)));

        try {
            Object parsed = JsonParser.parse(filledJson);
            if (!(parsed instanceof Map)) throw new Exception("Root must be JSON object");
            @SuppressWarnings("unchecked")
            Map<Object, Object> obj = (Map<Object, Object>) parsed;

            // Reverse named fields to numbers if proto mapping active
            String msgName = intruderMsgName;
            if (intruderApplyNames && !msgName.isEmpty() && protoMappings.containsKey(msgName)) {
                Map<String, String> rev = new HashMap<>();
                for (Map.Entry<String, String> e : protoMappings.get(msgName).entrySet())
                    rev.put(e.getValue(), e.getKey());
                obj = reverseNames(obj, rev);
            }

            byte[] protoBytes = ProtoEncoder.encode(obj);
            if (intruderHasGrpcFrame)
                protoBytes = addGrpcFrame(protoBytes, intruderGrpcFlag);

            callbacks.printOutput("[ProtobufEditor] payload='" + payloadStr
                    + "' encoded to " + protoBytes.length + " bytes");
            return protoBytes;

        } catch (Exception ex) {
            callbacks.printError("[ProtobufEditor] Encode failed for payload '"
                    + payloadStr + "': " + ex.getMessage());
            return currentPayload;
        }
    }

    // ── Shared static helpers ─────────────────────────────────────────────────

    static String escapeJsonString(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    static byte[] addGrpcFrame(byte[] proto, byte flag) {
        byte[] out = new byte[5 + proto.length];
        out[0] = flag;
        ByteBuffer.wrap(out, 1, 4).putInt(proto.length);
        System.arraycopy(proto, 0, out, 5, proto.length);
        return out;
    }

    @SuppressWarnings("unchecked")
    static Map<Object, Object> reverseNames(Map<Object, Object> obj, Map<String, String> rev) {
        Map<Object, Object> out = new LinkedHashMap<>();
        for (Map.Entry<Object, Object> e : obj.entrySet()) {
            String key = String.valueOf(e.getKey());
            Object val = e.getValue();
            if (val instanceof Map) val = reverseNames((Map<Object, Object>) val, rev);
            out.put(rev.getOrDefault(key, key), val);
        }
        return out;
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Editor Panel
    // ═════════════════════════════════════════════════════════════════════════

    static class EditorPanel extends JPanel {

        private final IBurpExtenderCallbacks callbacks;
        private final IExtensionHelpers      helpers;
        private final ProtobufEditor         ext;

        private IHttpService currentService;
        private byte[]       originalRequest;
        private byte[]       originalBody;
        private boolean      hasGrpcFraming;

        private final JTextArea  headersArea;
        private final JTextArea  jsonEditor;
        private final JTextArea  responseArea;
        private final JLabel     statusLabel;
        private final JTextField msgNameField;
        private final JCheckBox  applyNamesBox;
        private final JLabel     protoInfoLabel;
        private final JButton    sendBtn;

        EditorPanel(IBurpExtenderCallbacks cb, IExtensionHelpers h, ProtobufEditor ext) {
            super(new BorderLayout(4, 4));
            this.callbacks = cb;
            this.helpers   = h;
            this.ext       = ext;
            setBorder(new EmptyBorder(8, 8, 8, 8));
            Font mono = new Font("Monospaced", Font.PLAIN, 12);

            // ── Toolbar ──────────────────────────────────────────────────────
            JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

            JButton loadProtoBtn = new JButton("Load .proto\u2026");
            loadProtoBtn.addActionListener(this::onLoadProto);
            toolbar.add(loadProtoBtn);

            toolbar.add(new JLabel("Message:"));
            msgNameField = new JTextField("(auto)", 16);
            toolbar.add(msgNameField);

            applyNamesBox = new JCheckBox("Named fields", true);
            toolbar.add(applyNamesBox);

            JButton decodeBtn = new JButton("\u27f3 Decode");
            decodeBtn.addActionListener(e -> decodeCurrentBody());
            toolbar.add(decodeBtn);

            JButton validateBtn = new JButton("\u270e Validate JSON");
            validateBtn.addActionListener(e -> validateJson());
            toolbar.add(validateBtn);

            sendBtn = new JButton("\u25b6  Send");
            sendBtn.setFont(sendBtn.getFont().deriveFont(Font.BOLD));
            sendBtn.setBackground(new Color(0x1b5e20));
            sendBtn.setForeground(Color.WHITE);
            sendBtn.setOpaque(true);
            sendBtn.addActionListener(e -> doSend());
            toolbar.add(sendBtn);

            JButton intruderBtn = new JButton("\u26a1 Send to Intruder");
            intruderBtn.setFont(intruderBtn.getFont().deriveFont(Font.BOLD));
            intruderBtn.setBackground(new Color(0xe65100));
            intruderBtn.setForeground(Color.WHITE);
            intruderBtn.setOpaque(true);
            intruderBtn.setToolTipText(
                    "<html>Mark fuzz positions as \u00a7value\u00a7 in JSON, then click this.<br>" +
                    "In Intruder \u2192 Payloads \u2192 Payload Processing \u2192 Add \u2192<br>" +
                    "Invoke Burp extension \u2192 <b>Protobuf Re-encoder</b></html>");
            intruderBtn.addActionListener(e -> doSendToIntruder());
            toolbar.add(intruderBtn);

            // Mark selection as fuzz point — wraps selected text in §§
            JButton markBtn = new JButton("§ Mark Fuzz Point");
            markBtn.setBackground(new Color(0x4a148c));
            markBtn.setForeground(Color.WHITE);
            markBtn.setOpaque(true);
            markBtn.setToolTipText("Select a value in the JSON editor, then click to wrap it with §§ markers");
            markBtn.addActionListener(e -> markFuzzPoint());
            toolbar.add(markBtn);

            // Clear all markers
            JButton clearBtn = new JButton("× Clear Markers");
            clearBtn.setToolTipText("Remove all §§ markers from the JSON");
            clearBtn.addActionListener(e -> clearFuzzMarkers());
            toolbar.add(clearBtn);

            statusLabel = new JLabel("  Right-click a request \u2192 Send to Protobuf Editor");
            statusLabel.setForeground(new Color(0x444444));
            toolbar.add(statusLabel);

            add(toolbar, BorderLayout.NORTH);

            // ── Hint bar ─────────────────────────────────────────────────────
            JLabel hint = new JLabel(
                    "  \u26a1 Intruder fuzzing: edit field values as \u00a7value\u00a7  " +
                    "\u2192  Send to Intruder  \u2192  Payloads \u2192 Payload Processing \u2192 " +
                    "Add \u2192 Invoke extension \u2192 Protobuf Re-encoder");
            hint.setForeground(new Color(0x5d4037));
            hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 11f));
            hint.setBackground(new Color(0xfff8e1));
            hint.setOpaque(true);
            hint.setBorder(new EmptyBorder(3, 6, 3, 6));

            // ── Splits ───────────────────────────────────────────────────────
            headersArea = new JTextArea(6, 0);
            headersArea.setFont(mono);
            JScrollPane hScroll = new JScrollPane(headersArea);
            hScroll.setBorder(titled("Request Headers (editable)"));

            jsonEditor = new JTextArea();
            jsonEditor.setFont(mono);
            JScrollPane jScroll = new JScrollPane(jsonEditor);
            jScroll.setBorder(titled(
                    "Protobuf Body \u2192 JSON  (edit freely \u00b7 fuzz markers: \u00a7value\u00a7)"));

            JSplitPane reqSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, hScroll, jScroll);
            reqSplit.setResizeWeight(0.25);
            reqSplit.setDividerSize(5);

            responseArea = new JTextArea();
            responseArea.setFont(mono);
            responseArea.setEditable(false);
            JScrollPane rScroll = new JScrollPane(responseArea);
            rScroll.setBorder(titled("Response"));

            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqSplit, rScroll);
            mainSplit.setResizeWeight(0.6);
            mainSplit.setDividerSize(6);

            JPanel center = new JPanel(new BorderLayout());
            center.add(hint, BorderLayout.NORTH);
            center.add(mainSplit, BorderLayout.CENTER);
            add(center, BorderLayout.CENTER);

            protoInfoLabel = new JLabel("  No .proto loaded \u2014 fields shown as numbers");
            protoInfoLabel.setForeground(Color.GRAY);
            add(protoInfoLabel, BorderLayout.SOUTH);
        }

        private static TitledBorder titled(String t) {
            return BorderFactory.createTitledBorder(
                    BorderFactory.createLineBorder(new Color(0xcccccc)), t);
        }

        // ── Load from context menu ────────────────────────────────────────────

        void loadRequest(IHttpRequestResponse msg) {
            currentService  = msg.getHttpService();
            originalRequest = msg.getRequest();
            IRequestInfo info = helpers.analyzeRequest(originalRequest);
            int off = info.getBodyOffset();
            headersArea.setText(new String(originalRequest, 0, off, StandardCharsets.ISO_8859_1));
            originalBody   = Arrays.copyOfRange(originalRequest, off, originalRequest.length);
            hasGrpcFraming = detectGrpcFraming(originalBody);
            decodeCurrentBody();
            responseArea.setText("");
            setStatus("Loaded from " + currentService.getHost(), true);
        }

        // ── Decode ────────────────────────────────────────────────────────────

        private void decodeCurrentBody() {
            if (originalBody == null) { setStatus("No request loaded", false); return; }
            byte[] proto = hasGrpcFraming ? stripGrpcFrame(originalBody) : originalBody;
            try {
                Map<Object, Object> decoded = ProtoDecoder.decode(proto);
                String name = msgNameField.getText().trim();
                if (applyNamesBox.isSelected() && ext.protoMappings.containsKey(name))
                    decoded = applyNames(decoded, ext.protoMappings.get(name));
                jsonEditor.setText(JsonPrinter.print(decoded, 0));
                setStatus("Decoded " + proto.length + " bytes", true);
            } catch (Exception ex) {
                jsonEditor.setText("// Decode error: " + ex.getMessage());
                setStatus("Decode error", false);
            }
        }

        // ── Mark / clear fuzz points ──────────────────────────────────────────

        private void clearFuzzMarkers() {
            jsonEditor.setText(jsonEditor.getText().replaceAll("\u00a7([^\u00a7]*)\u00a7", "$1"));
            setStatus("Markers cleared", true);
        }

        private void markFuzzPoint() {
            String selected = jsonEditor.getSelectedText();
            if (selected == null || selected.isEmpty()) {
                setStatus("Select a value in the JSON first, then click \u00a7 Mark Fuzz Point", false);
                return;
            }
            int start = jsonEditor.getSelectionStart();
            int end   = jsonEditor.getSelectionEnd();
            String text = jsonEditor.getText();
            jsonEditor.setText(text.substring(0, start) + "\u00a7" + selected + "\u00a7" + text.substring(end));
            jsonEditor.setSelectionStart(start);
            jsonEditor.setSelectionEnd(end + 2);
            setStatus("Marked: \u00a7" + selected + "\u00a7  \u2014 click \u26a1 Send to Intruder when ready", true);
        }

        // ── Validate ──────────────────────────────────────────────────────────

        private void validateJson() {
            // Replace §markers§ with placeholder so JSON parser doesn't choke on §
            String text = jsonEditor.getText()
                    .replaceAll("\u00a7[^\u00a7]*\u00a7", "\"__FUZZ__\"");
            try { JsonParser.parse(text); setStatus("JSON valid", true); }
            catch (Exception ex) { setStatus("JSON error: " + ex.getMessage(), false); }
        }

        // ── Send ──────────────────────────────────────────────────────────────

        private void doSend() {
            if (currentService == null) { setStatus("No request loaded", false); return; }
            if (jsonEditor.getText().contains("\u00a7")) {
                setStatus("Remove \u00a7markers\u00a7 before sending directly, or use Send to Intruder", false);
                return;
            }
            byte[] body = encodeJson(jsonEditor.getText());
            if (body == null) return;

            String headers = normaliseHeaders(headersArea.getText(), body.length);
            byte[] req = concat(headers.getBytes(StandardCharsets.ISO_8859_1), body);

            setStatus("Sending\u2026", true);
            sendBtn.setEnabled(false);
            responseArea.setText("Sending\u2026");

            final IHttpService svc = currentService;
            Thread t = new Thread(() -> {
                byte[] resp = null; String err = null;
                try {
                    callbacks.printOutput("[ProtobufEditor] Sending " + req.length + " bytes to "
                            + svc.getHost() + ":" + svc.getPort());
                    IHttpRequestResponse rrr = callbacks.makeHttpRequest(svc, req);
                    resp = (rrr != null) ? rrr.getResponse() : null;
                    callbacks.printOutput("[ProtobufEditor] Response: "
                            + (resp == null ? "null" : resp.length + " bytes"));
                } catch (Throwable ex) {
                    err = ex.getClass().getSimpleName() + ": "
                            + (ex.getMessage() != null ? ex.getMessage() : "(no message)");
                    callbacks.printError("[ProtobufEditor] Send threw: " + err);
                }
                final byte[] fr = resp; final String fe = err;
                SwingUtilities.invokeLater(() -> {
                    sendBtn.setEnabled(true);
                    if (fe != null) { setStatus("Error: " + fe, false); responseArea.setText("ERROR: " + fe); }
                    else if (fr == null || fr.length == 0) { setStatus("Empty response", false); responseArea.setText("(no response)"); }
                    else { displayResponse(fr); setStatus("Response: " + fr.length + " bytes", true); }
                });
            });
            t.setDaemon(true); t.start();
        }

        // ── Dialog helpers ────────────────────────────────────────────────────

        private static void showDialog(Component parent, String title, int type, String html) {
            JTextPane tp = new JTextPane();
            tp.setContentType("text/html");
            tp.setText("<html><body style='font-family:sans-serif;font-size:12px'>"
                    + html + "</body></html>");
            tp.setEditable(false);
            tp.setBackground(UIManager.getColor("OptionPane.background"));
            tp.setPreferredSize(new Dimension(380, tp.getPreferredSize().height));
            // Let it lay out at 380px wide, then size height to fit
            JScrollPane sp = new JScrollPane(tp,
                    JScrollPane.VERTICAL_SCROLLBAR_NEVER,
                    JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
            sp.setBorder(null);
            sp.setPreferredSize(new Dimension(380, 220));
            JOptionPane.showMessageDialog(parent, sp, title, type);
        }

        private static JComponent makeLabel(String html) {
            JTextPane tp = new JTextPane();
            tp.setContentType("text/html");
            tp.setText("<html><body style='font-family:sans-serif;font-size:12px'>"
                    + html + "</body></html>");
            tp.setEditable(false);
            tp.setBackground(UIManager.getColor("OptionPane.background"));
            tp.setPreferredSize(new Dimension(380, 140));
            JScrollPane sp = new JScrollPane(tp,
                    JScrollPane.VERTICAL_SCROLLBAR_NEVER,
                    JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
            sp.setBorder(null);
            sp.setPreferredSize(new Dimension(380, 140));
            return sp;
        }

        // ── Send to Intruder ──────────────────────────────────────────────────

        private void doSendToIntruder() {
            if (currentService == null) { setStatus("No request loaded", false); return; }

            String jsonText = jsonEditor.getText();

            if (!jsonText.contains("\u00a7")) {
                int choice = JOptionPane.showConfirmDialog(this,
                        makeLabel("No \u00a7fuzz markers\u00a7 found in JSON.<br><br>" +
                        "Select a value in the editor and click <b>\u00a7 Mark Fuzz Point</b>.<br><br>" +
                        "Send anyway with the whole body as a single insertion point?"),
                        "No fuzz markers", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                if (choice != JOptionPane.YES_OPTION) return;
            }

            // Snapshot current settings into processor state
            ext.intruderJsonTemplate = jsonText;
            ext.intruderHasGrpcFrame = hasGrpcFraming;
            ext.intruderGrpcFlag     = hasGrpcFraming ? originalBody[0] : 0;
            ext.intruderMsgName      = msgNameField.getText().trim();
            ext.intruderApplyNames   = applyNamesBox.isSelected();

            // Build a representative encoded body for the Intruder base request.
            // §markers§ sit INSIDE JSON string quotes: "§value§"
            // so we strip just the § characters, leaving the quoted string intact.
            String templateForEncode = jsonText.replace("\u00a7", "");
            byte[] body = encodeJson(templateForEncode);
            if (body == null) return;  // encode error already shown

            String headersRaw  = normaliseHeaders(headersArea.getText(), body.length);
            byte[] headersBytes = headersRaw.getBytes(StandardCharsets.ISO_8859_1);
            byte[] fullRequest  = concat(headersBytes, body);

            // The insertion point covers the entire body.
            // Intruder will call our processor for each payload; the processor
            // returns fully re-encoded protobuf bytes which replace the body.
            // The §§ markers shown in Intruder's Raw tab around the body are
            // expected - that is just how Intruder displays insertion points.
            callbacks.sendToIntruder(
                    currentService.getHost(),
                    currentService.getPort(),
                    "https".equalsIgnoreCase(currentService.getProtocol()),
                    fullRequest,
                    Collections.singletonList(new int[]{headersBytes.length, fullRequest.length})
            );

            setStatus("Sent to Intruder \u2014 add 'Protobuf Re-encoder' in Payload Processing", true);

            showDialog(this, "Intruder Ready", JOptionPane.INFORMATION_MESSAGE,
                    "<b>Request sent to Intruder!</b><br><br>" +
                    "The \u00a7\u00a7 markers around the body in Intruder's Raw tab are " +
                    "normal \u2014 that is just how Intruder shows the insertion point.<br><br>" +
                    "<b>Required: add the payload processor</b><br>" +
                    "Without this step payloads will be sent as raw text, not protobuf.<br><br>" +
                    "1. Intruder \u2192 <b>Payloads</b> tab<br>" +
                    "2. Scroll to <b>Payload Processing</b><br>" +
                    "3. <b>Add \u2192 Invoke Burp extension \u2192 Protobuf Re-encoder</b><br>" +
                    "4. Add your payload list \u2192 <b>Start Attack</b>");
        }

        // ── Response display ──────────────────────────────────────────────────

        private void displayResponse(byte[] response) {
            IResponseInfo info = helpers.analyzeResponse(response);
            int off     = info.getBodyOffset();
            String hdrs = new String(response, 0, off, StandardCharsets.ISO_8859_1);
            byte[] body = Arrays.copyOfRange(response, off, response.length);

            String ct = "";
            for (String h : info.getHeaders())
                if (h.toLowerCase().startsWith("content-type")) { ct = h.toLowerCase(); break; }

            StringBuilder sb = new StringBuilder(hdrs);
            if (ct.contains("grpc") || ct.contains("protobuf")) {
                byte[] proto = detectGrpcFraming(body) ? stripGrpcFrame(body) : body;
                try {
                    Map<Object, Object> dec = ProtoDecoder.decode(proto);
                    String name = msgNameField.getText().trim();
                    if (applyNamesBox.isSelected() && ext.protoMappings.containsKey(name))
                        dec = applyNames(dec, ext.protoMappings.get(name));
                    sb.append("\n// Protobuf decoded:\n").append(JsonPrinter.print(dec, 0));
                } catch (Exception ex) { sb.append(bytesToHex(body)); }
            } else {
                sb.append(new String(body, StandardCharsets.UTF_8));
            }
            responseArea.setText(sb.toString());
            responseArea.setCaretPosition(0);
        }

        // ── .proto loading ────────────────────────────────────────────────────

        private void onLoadProto(ActionEvent e) {
            JFileChooser fc = new JFileChooser();
            fc.setFileFilter(new FileNameExtensionFilter("Proto files (*.proto)", "proto"));
            fc.setMultiSelectionEnabled(true);
            if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
            List<String> loaded = new ArrayList<>();
            for (File f : fc.getSelectedFiles()) {
                Map<String, Map<String, String>> p = ProtoFileParser.parse(f);
                ext.protoMappings.putAll(p);
                loaded.addAll(p.keySet());
            }
            if (!loaded.isEmpty()) {
                protoInfoLabel.setText("  Loaded: " + String.join(", ", loaded));
                if (msgNameField.getText().trim().equals("(auto)")
                        || msgNameField.getText().trim().isEmpty())
                    msgNameField.setText(loaded.get(0));
                setStatus("Proto loaded: " + loaded.size() + " messages", true);
                decodeCurrentBody();
            } else {
                setStatus("No messages found in .proto", false);
            }
        }

        // ── Encode helpers ────────────────────────────────────────────────────

        private byte[] encodeJson(String jsonText) {
            try {
                Object parsed = JsonParser.parse(jsonText);
                if (!(parsed instanceof Map)) throw new Exception("Root must be JSON object");
                @SuppressWarnings("unchecked")
                Map<Object, Object> obj = (Map<Object, Object>) parsed;

                String name = msgNameField.getText().trim();
                if (applyNamesBox.isSelected() && ext.protoMappings.containsKey(name)) {
                    Map<String, String> rev = new HashMap<>();
                    for (Map.Entry<String, String> e : ext.protoMappings.get(name).entrySet())
                        rev.put(e.getValue(), e.getKey());
                    obj = reverseNames(obj, rev);
                }

                byte[] proto = ProtoEncoder.encode(obj);
                if (hasGrpcFraming) proto = addGrpcFrame(proto, originalBody[0]);
                return proto;
            } catch (Exception ex) {
                setStatus("Encode error: " + ex.getMessage(), false);
                return null;
            }
        }

        // ── Misc helpers ──────────────────────────────────────────────────────

        private void setStatus(String msg, boolean ok) {
            statusLabel.setText("  " + msg);
            statusLabel.setForeground(ok ? new Color(0x1b5e20) : new Color(0xb71c1c));
        }

        static boolean detectGrpcFraming(byte[] b) {
            if (b.length < 5) return false;
            int flag = b[0] & 0xFF;
            if (flag != 0 && flag != 1) return false;
            return ByteBuffer.wrap(b, 1, 4).getInt() == b.length - 5;
        }

        static byte[] stripGrpcFrame(byte[] b) {
            int len = ByteBuffer.wrap(b, 1, 4).getInt();
            return Arrays.copyOfRange(b, 5, 5 + len);
        }

        static String normaliseHeaders(String raw, int bodyLen) {
            raw = raw.replaceAll("\r\n|\r|\n", "\r\n").replaceAll("(\r\n)+$", "");
            raw = raw.replaceAll("(?i)content-length:\\s*\\d+", "Content-Length: " + bodyLen);
            return raw + "\r\n\r\n";
        }

        static byte[] concat(byte[] a, byte[] b) {
            byte[] out = new byte[a.length + b.length];
            System.arraycopy(a, 0, out, 0, a.length);
            System.arraycopy(b, 0, out, a.length, b.length);
            return out;
        }

        static String bytesToHex(byte[] b) {
            StringBuilder sb = new StringBuilder();
            for (byte x : b) sb.append(String.format("%02x ", x));
            return sb.toString();
        }

        @SuppressWarnings("unchecked")
        static Map<Object, Object> applyNames(Map<Object, Object> m, Map<String, String> fm) {
            Map<Object, Object> out = new LinkedHashMap<>();
            for (Map.Entry<Object, Object> e : m.entrySet()) {
                Object val = e.getValue();
                if (val instanceof Map) val = applyNames((Map<Object, Object>) val, fm);
                out.put(fm.getOrDefault(String.valueOf(e.getKey()), String.valueOf(e.getKey())), val);
            }
            return out;
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Protobuf decoder
    // ═════════════════════════════════════════════════════════════════════════

    static class ProtoDecoder {
        static Map<Object, Object> decode(byte[] data) throws IOException {
            return decode(data, 0, data.length);
        }

        @SuppressWarnings("unchecked")
        static Map<Object, Object> decode(byte[] data, int start, int end) throws IOException {
            Map<Object, Object> result = new LinkedHashMap<>();
            int pos = start;
            while (pos < end) {
                long[] t  = readVarint(data, pos); pos = (int) t[1];
                int fn    = (int) (t[0] >>> 3);
                int wt    = (int) (t[0] & 7);
                String key = String.valueOf(fn);
                Object entry;

                switch (wt) {
                    case 0: {
                        long[] v = readVarint(data, pos); pos = (int) v[1];
                        Map<Object,Object> m = new LinkedHashMap<>();
                        m.put("_type","varint"); m.put("value", v[0]); entry = m; break;
                    }
                    case 1: {
                        long v = ByteBuffer.wrap(data,pos,8).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong(); pos+=8;
                        Map<Object,Object> m = new LinkedHashMap<>();
                        m.put("_type","fixed64"); m.put("value",v); entry = m; break;
                    }
                    case 2: {
                        long[] lr = readVarint(data, pos); int len=(int)lr[0]; pos=(int)lr[1];
                        byte[] chunk = Arrays.copyOfRange(data, pos, pos+len); pos+=len;
                        try {
                            String s = new String(chunk, StandardCharsets.UTF_8);
                            boolean ok = true;
                            for (char c : s.toCharArray()) if (c < 0x20 && c!='\t' && c!='\n' && c!='\r'){ok=false;break;}
                            if (ok && s.length() > 0) {
                                Map<Object,Object> m = new LinkedHashMap<>();
                                m.put("_type","string"); m.put("value",s); entry = m; break;
                            }
                        } catch (Exception ignored) {}
                        try {
                            Map<Object,Object> nested = decode(chunk,0,chunk.length);
                            if (!nested.isEmpty()) {
                                Map<Object,Object> m = new LinkedHashMap<>();
                                m.put("_type","message"); m.put("value",nested); entry = m; break;
                            }
                        } catch (Exception ignored) {}
                        StringBuilder hex = new StringBuilder();
                        for (byte b : chunk) hex.append(String.format("%02x",b));
                        Map<Object,Object> m = new LinkedHashMap<>();
                        m.put("_type","bytes"); m.put("value",hex.toString()); entry = m; break;
                    }
                    case 5: {
                        int v = ByteBuffer.wrap(data,pos,4).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt(); pos+=4;
                        Map<Object,Object> m = new LinkedHashMap<>();
                        m.put("_type","fixed32"); m.put("value",(long)v&0xFFFFFFFFL); entry = m; break;
                    }
                    default: throw new IOException("Unknown wire type " + wt);
                }

                if (result.containsKey(key)) {
                    Object ex = result.get(key);
                    List<Object> list = (ex instanceof List) ? (List<Object>)ex : new ArrayList<>(Arrays.asList(ex));
                    if (!(ex instanceof List)) result.put(key, list);
                    list.add(entry);
                } else {
                    result.put(key, entry);
                }
            }
            return result;
        }

        static long[] readVarint(byte[] data, int pos) throws IOException {
            long r = 0; int s = 0;
            while (true) {
                if (pos >= data.length) throw new IOException("Truncated varint");
                int b = data[pos++] & 0xFF;
                r |= (long)(b & 0x7F) << s; s += 7;
                if ((b & 0x80) == 0) break;
            }
            return new long[]{r, pos};
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Protobuf encoder
    // ═════════════════════════════════════════════════════════════════════════

    static class ProtoEncoder {
        @SuppressWarnings("unchecked")
        static byte[] encode(Map<Object, Object> obj) throws Exception {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (Map.Entry<Object, Object> e : obj.entrySet()) {
                int fn;
                try { fn = Integer.parseInt(String.valueOf(e.getKey())); }
                catch (NumberFormatException ex) {
                    throw new Exception("Field key '" + e.getKey() + "' is not a number. " +
                            "Did you forget to reverse-map proto field names?");
                }
                Object val = e.getValue();
                if (val instanceof List)
                    for (Object item : (List<Object>)val) encodeField(out, fn, (Map<Object,Object>)item);
                else
                    encodeField(out, fn, (Map<Object,Object>)val);
            }
            return out.toByteArray();
        }

        @SuppressWarnings("unchecked")
        static void encodeField(ByteArrayOutputStream out, int fn, Map<Object,Object> e) throws Exception {
            String type = String.valueOf(e.get("_type"));
            Object val  = e.get("value");
            switch (type) {
                case "varint":  writeTag(out,fn,0); writeVarint(out,toLong(val)); break;
                case "string": {
                    writeTag(out,fn,2); byte[] b=String.valueOf(val).getBytes(StandardCharsets.UTF_8);
                    writeVarint(out,b.length); out.write(b); break;
                }
                case "message": {
                    writeTag(out,fn,2); byte[] n=encode((Map<Object,Object>)val);
                    writeVarint(out,n.length); out.write(n); break;
                }
                case "bytes": {
                    writeTag(out,fn,2);
                    byte[] b=hexToBytes(String.valueOf(val).replaceAll("\\s",""));
                    writeVarint(out,b.length); out.write(b); break;
                }
                case "fixed64": {
                    writeTag(out,fn,1);
                    out.write(ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN).putLong(toLong(val)).array()); break;
                }
                case "fixed32": {
                    writeTag(out,fn,5);
                    out.write(ByteBuffer.allocate(4).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt((int)toLong(val)).array()); break;
                }
                default: throw new Exception("Unknown _type: " + type);
            }
        }

        static void writeTag(ByteArrayOutputStream out, int fn, int wt) { writeVarint(out,((long)fn<<3)|wt); }
        static void writeVarint(ByteArrayOutputStream out, long v) {
            while (true) { if ((v & ~0x7FL)==0){out.write((int)v);return;} out.write((int)(v&0x7F)|0x80); v>>>=7; }
        }
        static long toLong(Object v) {
            if (v instanceof Number) return ((Number)v).longValue();
            return Long.parseLong(String.valueOf(v));
        }
        static byte[] hexToBytes(String hex) {
            byte[] out = new byte[hex.length()/2];
            for (int i=0;i<out.length;i++) out[i]=(byte)Integer.parseInt(hex.substring(i*2,i*2+2),16);
            return out;
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    // JSON printer
    // ═════════════════════════════════════════════════════════════════════════

    static class JsonPrinter {
        @SuppressWarnings("unchecked")
        static String print(Object obj, int indent) {
            String p=rep("  ",indent), p1=rep("  ",indent+1);
            if (obj instanceof Map) {
                Map<Object,Object> m=(Map<Object,Object>)obj;
                if (m.isEmpty()) return "{}";
                StringBuilder sb=new StringBuilder("{\n"); int i=0;
                for (Map.Entry<Object,Object> e : m.entrySet()) {
                    sb.append(p1).append('"').append(esc(String.valueOf(e.getKey()))).append("\": ");
                    sb.append(print(e.getValue(),indent+1));
                    if (++i<m.size()) sb.append(','); sb.append('\n');
                }
                return sb.append(p).append('}').toString();
            } else if (obj instanceof List) {
                List<Object> l=(List<Object>)obj;
                if (l.isEmpty()) return "[]";
                StringBuilder sb=new StringBuilder("[\n");
                for (int i=0;i<l.size();i++) {
                    sb.append(p1).append(print(l.get(i),indent+1));
                    if (i<l.size()-1) sb.append(','); sb.append('\n');
                }
                return sb.append(p).append(']').toString();
            } else if (obj instanceof String) { return '"'+esc((String)obj)+'"'; }
            else if (obj==null) { return "null"; }
            else { return String.valueOf(obj); }
        }
        static String esc(String s){return s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t");}
        static String rep(String s,int n){StringBuilder sb=new StringBuilder();for(int i=0;i<n;i++)sb.append(s);return sb.toString();}
    }

    // ═════════════════════════════════════════════════════════════════════════
    // JSON parser
    // ═════════════════════════════════════════════════════════════════════════

    static class JsonParser {
        String src; int pos;
        JsonParser(String s){src=s;pos=0;}
        static Object parse(String s) throws Exception {
            JsonParser p=new JsonParser(s.trim()); Object v=p.parseValue(); p.skipWs();
            if(p.pos!=p.src.length()) throw new Exception("Trailing chars at "+p.pos); return v;
        }
        void skipWs(){while(pos<src.length()&&src.charAt(pos)<=' ')pos++;}
        Object parseValue() throws Exception {
            skipWs(); if(pos>=src.length()) throw new Exception("Unexpected end");
            char c=src.charAt(pos);
            if(c=='{') return parseObject(); if(c=='[') return parseArray();
            if(c=='"') return parseString();
            if(c=='t'){pos+=4;return Boolean.TRUE;} if(c=='f'){pos+=5;return Boolean.FALSE;}
            if(c=='n'){pos+=4;return null;}
            if(c=='-'||Character.isDigit(c)) return parseNumber();
            throw new Exception("Unexpected '"+c+"' at "+pos);
        }
        Map<Object,Object> parseObject() throws Exception {
            pos++; Map<Object,Object> m=new LinkedHashMap<>(); skipWs();
            if(pos<src.length()&&src.charAt(pos)=='}'){pos++;return m;}
            while(true){
                skipWs(); String k=parseString(); skipWs();
                if(src.charAt(pos)!=':') throw new Exception("Expected ':' at "+pos); pos++;
                m.put(k,parseValue()); skipWs(); char n=src.charAt(pos);
                if(n=='}'){pos++;return m;} if(n!=',') throw new Exception("Expected ',' at "+pos); pos++;
            }
        }
        List<Object> parseArray() throws Exception {
            pos++; List<Object> l=new ArrayList<>(); skipWs();
            if(pos<src.length()&&src.charAt(pos)==']'){pos++;return l;}
            while(true){
                l.add(parseValue()); skipWs(); char n=src.charAt(pos);
                if(n==']'){pos++;return l;} if(n!=',') throw new Exception("Expected ',' at "+pos); pos++;
            }
        }
        String parseString() throws Exception {
            if(src.charAt(pos)!='"') throw new Exception("Expected '\"' at "+pos); pos++;
            StringBuilder sb=new StringBuilder();
            while(pos<src.length()){
                char c=src.charAt(pos++);
                if(c=='"') return sb.toString();
                if(c=='\\'){char e=src.charAt(pos++);
                    switch(e){case '"':sb.append('"');break;case '\\':sb.append('\\');break;
                        case 'n':sb.append('\n');break;case 'r':sb.append('\r');break;case 't':sb.append('\t');break;
                        case 'u':sb.append((char)Integer.parseInt(src.substring(pos,pos+4),16));pos+=4;break;
                        default:sb.append(e);}
                } else sb.append(c);
            }
            throw new Exception("Unterminated string");
        }
        Object parseNumber(){
            int s=pos; if(pos<src.length()&&src.charAt(pos)=='-')pos++;
            while(pos<src.length()&&Character.isDigit(src.charAt(pos)))pos++;
            boolean f=false;
            if(pos<src.length()&&src.charAt(pos)=='.'){f=true;pos++;while(pos<src.length()&&Character.isDigit(src.charAt(pos)))pos++;}
            if(pos<src.length()&&(src.charAt(pos)=='e'||src.charAt(pos)=='E')){f=true;pos++;
                if(pos<src.length()&&(src.charAt(pos)=='+'||src.charAt(pos)=='-'))pos++;
                while(pos<src.length()&&Character.isDigit(src.charAt(pos)))pos++;}
            String n=src.substring(s,pos);
            if(f) return Double.parseDouble(n);
            try{return Long.parseLong(n);}catch(NumberFormatException e){return Double.parseDouble(n);}
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    // .proto file parser
    // ═════════════════════════════════════════════════════════════════════════

    static class ProtoFileParser {
        static Map<String,Map<String,String>> parse(File f) {
            Map<String,Map<String,String>> result=new LinkedHashMap<>();
            try {
                StringBuilder sb=new StringBuilder();
                try(BufferedReader r=new BufferedReader(new FileReader(f))){String l;while((l=r.readLine())!=null)sb.append(l).append('\n');}
                String content=sb.toString().replaceAll("/\\*.*?\\*/","").replaceAll("//[^\n]*","");
                Matcher m=Pattern.compile("message\\s+(\\w+)\\s*\\{([^}]*)\\}",Pattern.DOTALL).matcher(content);
                while(m.find()){
                    Map<String,String> fields=new LinkedHashMap<>();
                    Matcher fm=Pattern.compile("(?:required|optional|repeated|)\\s*[\\w.]+\\s+(\\w+)\\s*=\\s*(\\d+)\\s*[;\\[]").matcher(m.group(2));
                    while(fm.find()) if(!fm.group(1).equals("option")&&!fm.group(1).equals("reserved")) fields.put(fm.group(2),fm.group(1));
                    result.put(m.group(1),fields);
                }
            } catch(Exception ignored){}
            return result;
        }
    }
}
