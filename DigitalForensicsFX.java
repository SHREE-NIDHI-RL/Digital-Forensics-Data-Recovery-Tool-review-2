/* Save as: DigitalForensicsFX.java
   Single-file JavaFX app with dashboard, cyber theme, progress bar, status log,
   updated Verify Hash (paste or choose file), config persistence, encryption/decryption.
   Requires Java 17+ and JavaFX SDK.
*/

import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.text.Font;
import javafx.stage.*;

import javafx.util.Pair;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.*;
import java.util.List;
import java.util.regex.Pattern;

public class DigitalForensicsFX extends Application {

    // UI controls
    private TextArea statusLog = new TextArea();
    private ProgressBar progressBar = new ProgressBar(0);
    private Label progressLabel = new Label("");
    private Properties cfg = new Properties();
    private Path cfgDir = Paths.get(System.getProperty("user.home"), ".dftool");
    private Path cfgFile = cfgDir.resolve("dftool.properties");

    // Core data / managers
    private List<String> sessionLog = new ArrayList<>();
    private final String REPORTS_DIR = "forensic_reports";
    private final String RECOVERED_DIR = "recovered_files";

    // Default password - first run
    private String defaultPassword = "admin";

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        ensureBaseDirs();
        loadConfig();

        // Authenticate first
        boolean ok = authenticateDialog(primaryStage);
        if (!ok) { showAlert("Authentication failed", "Wrong password. Exiting."); Platform.exit(); return; }

        primaryStage.setTitle("Digital Forensics Dashboard");

        BorderPane root = new BorderPane();
        root.setPadding(new Insets(12));

        // Top header
        HBox header = buildHeader();
        root.setTop(header);

        // Left sidebar (cards)
        VBox left = buildSidebar(primaryStage);
        root.setLeft(left);

        // Center - big dashboard / controls area (grid of cards)
        GridPane center = buildDashboard(primaryStage);
        root.setCenter(center);

        // Bottom - status log and progress bar
        VBox bottom = buildBottomArea();
        root.setBottom(bottom);

        Scene scene = new Scene(root, 1100, 700);
        scene.getStylesheets().add(inlineCssAsDataUri());
        primaryStage.setScene(scene);
        primaryStage.show();

        appendStatus("Ready. Dashboard loaded.");
    }

    private HBox buildHeader() {
        Label title = new Label("⚔️  DIGITAL FORENSICS TOOL");
        title.setFont(Font.font(20));
        Label subtitle = new Label(" — Dashboard (Cyber Theme)");
        subtitle.setStyle("-fx-text-fill: #bfefff; -fx-font-size: 12;");
        HBox hb = new HBox(10, title, subtitle);
        hb.setPadding(new Insets(8));
        hb.setAlignment(Pos.CENTER_LEFT);
        hb.setStyle("-fx-background-color: linear-gradient(#0f1724, #071027); -fx-padding: 8;");
        return hb;
    }

    private VBox buildSidebar(Stage stage) {
        VBox vb = new VBox(12);
        vb.setPadding(new Insets(12));
        vb.setPrefWidth(260);

        Label menu = new Label("Main Menu");
        menu.setFont(Font.font(16));

        Button btnScan = styledCard("🔎 Scan Directory", "Scan a folder and list files", e -> scanDirectoryTask(stage));
        Button btnMetadata = styledCard("📝 View Metadata", "Inspect file metadata", e -> viewMetadata(stage));
        Button btnHash = styledCard("🔐 Generate Hash", "MD5 / SHA-256", e -> generateHashDialog(stage));
        Button btnVerify = styledCard("🧾 Verify Hash", "Paste hash or choose file", e -> verifyHashDialog(stage));
        Button btnRecover = styledCard("🩺 Recover Files", "Copy deleted/sim folder", e -> recoverFilesTask(stage));
        Button btnSearch = styledCard("🔎 Keyword Search", "Search text inside files", e -> searchKeywordTask(stage));
        Button btnAttack = styledCard("🛡️ Attack Scan", "Search for known patterns", e -> attackScanTask(stage));

        vb.getChildren().addAll(menu, btnScan, btnMetadata, btnHash, btnVerify, btnRecover, btnSearch, btnAttack);
        vb.setStyle("-fx-background-color: rgba(5,10,20,0.6); -fx-border-color: #073b4c; -fx-border-width: 1;");
        return vb;
    }

    private GridPane buildDashboard(Stage stage) {
        GridPane grid = new GridPane();
        grid.setPadding(new Insets(12));
        grid.setHgap(12);
        grid.setVgap(12);

        Button btnExport = bigCard("📤 Export Results", "CSV / JSON", e -> exportResultsDialog(stage));
        Button btnEncRpt = bigCard("🔏 Generate Encrypted Report", "Encrypt session report", e -> generateEncryptedReportDialog(stage));
        Button btnDecRpt = bigCard("🔓 Decrypt Report", "Decrypt saved report file", e -> decryptReportDialog(stage));
        Button btnPlainRpt = bigCard("🗂️ Export Plain Report", "Save readable report", e -> exportPlainReport());
        Button btnTimeline = bigCard("🕘 Timeline", "List files by last-modified", e -> timelineTask(stage));
        Button btnPass = bigCard("🔑 Change Password", "Change tool password", e -> changePasswordDialog(stage));
        Button btnClear = bigCard("🧹 Clear Log", "Clear session log & UI", e -> clearSession());
        Button btnExit = bigCard("⛔ Exit", "Close app", e -> Platform.exit());

        grid.add(btnExport, 0, 0);
        grid.add(btnEncRpt, 1, 0);
        grid.add(btnDecRpt, 2, 0);
        grid.add(btnPlainRpt, 0, 1);
        grid.add(btnTimeline, 1, 1);
        grid.add(btnPass, 2, 1);
        grid.add(btnClear, 0, 2);
        grid.add(btnExit, 1, 2);

        ColumnConstraints c1 = new ColumnConstraints();
        c1.setPercentWidth(33);
        grid.getColumnConstraints().addAll(c1, c1, c1);

        return grid;
    }

    private VBox buildBottomArea() {
        statusLog.setWrapText(true);
        statusLog.setEditable(false);
        statusLog.setPrefRowCount(8);

        progressBar.setPrefWidth(Double.MAX_VALUE);
        progressBar.setProgress(0);

        HBox pbox = new HBox(8, progressBar, progressLabel);
        pbox.setAlignment(Pos.CENTER_LEFT);
        pbox.setPadding(new Insets(6));
        VBox vb = new VBox(6, new Label("Status Log:"), statusLog, pbox);
        vb.setPadding(new Insets(12));
        vb.setStyle("-fx-background-color: rgba(0,0,0,0.45); -fx-border-color: #072b2f;");
        return vb;
    }

    // ---------- Styled components ----------
    private Button styledCard(String title, String subtitle, javafx.event.EventHandler<javafx.event.ActionEvent> h) {
        Button b = new Button(title + "\n" + subtitle);
        b.setPrefWidth(220);
        b.setWrapText(true);
        b.setOnAction(h);
        b.getStyleClass().add("card-small");
        return b;
    }

    private Button bigCard(String title, String subtitle, javafx.event.EventHandler<javafx.event.ActionEvent> h) {
        Button b = new Button(title + "\n" + subtitle);
        b.setPrefSize(320, 100);
        b.setWrapText(true);
        b.setOnAction(h);
        b.getStyleClass().add("card-big");
        return b;
    }

    // ---------- Tasks / Long-running operations ----------

    private void scanDirectoryTask(Stage stage) {
        DirectoryChooser dc = new DirectoryChooser();
        dc.setTitle("Select Directory to Scan");
        File dir = dc.showDialog(stage);
        if (dir == null) return;
        final File finalDir = dir;
        Task<List<File>> task = new Task<List<File>>() {
            @Override
            protected List<File> call() {
                updateMessage("Scanning " + finalDir.getAbsolutePath());
                updateProgress(-1, 1); // indeterminate
                File[] arr = finalDir.listFiles();
                if (arr == null) {
                    updateMessage("No files / access denied.");
                    updateProgress(0, 1);
                    return Collections.emptyList();
                }
                List<File> files = Arrays.asList(arr);
                updateMessage("Scan complete. " + files.size() + " entries.");
                updateProgress(1, 1);
                return files;
            }
        };
        bindTaskToUI(task);
        task.setOnSucceeded(e -> {
            List<File> files = task.getValue();
            appendStatus("Scanned: " + finalDir.getAbsolutePath() + " (" + files.size() + " entries)");
            for (File f : files) appendStatus("  - " + f.getName());
            sessionLog.add("Scanned directory: " + finalDir.getAbsolutePath() + " (" + files.size() + " entries)");
            saveLast("lastDir", finalDir.getAbsolutePath());
        });
        new Thread(task).start();
    }
/*
    private void recoverFilesTask(Stage stage) {
        DirectoryChooser srcDc = new DirectoryChooser();
        srcDc.setTitle("Select Source (simulate deleted)");
        File src = srcDc.showDialog(stage);
        if (src == null) return;
        DirectoryChooser destDc = new DirectoryChooser();
        destDc.setTitle("Select Destination (recovered)");
        File dest = destDc.showDialog(stage);
        if (dest == null) dest = new File(RECOVERED_DIR);

        final File finalSrc = src;
        final File finalDest = dest;

        Task<Integer> task = new Task<Integer>() {
            @Override
            protected Integer call() {
                updateMessage("Recovering from " + finalSrc.getAbsolutePath());
                File[] arr = finalSrc.listFiles();
                if (arr == null) {
                    updateMessage("No files or access denied.");
                    return 0;
                }
                int total = arr.length;
                int count = 0;
                for (int i = 0; i < arr.length; i++) {
                    File f = arr[i];
                    if (!f.isFile()) {
                        updateProgress(i + 1, total);
                        continue;
                    }
                    try {
                        Files.copy(f.toPath(), Paths.get(finalDest.getAbsolutePath(), f.getName()), StandardCopyOption.REPLACE_EXISTING);
                        count++;
                        updateMessage("Recovered: " + f.getName());
                    } catch (IOException ex) {
                        updateMessage("Fail: " + f.getName());
                    }
                    updateProgress(i + 1, total);
                    try { Thread.sleep(60); } catch (InterruptedException ignored) {}
                }
                updateMessage("Recovered " + count + " / " + total);
                return count;
            }
        };

        bindTaskToUI(task);
        task.setOnSucceeded(e -> {
            appendStatus("Recovered files to: " + finalDest.getAbsolutePath() + " (" + task.getValue() + " files)");
            sessionLog.add("Recovered files from " + finalSrc.getAbsolutePath() + " to " + finalDest.getAbsolutePath() + ": " + task.getValue() + " file(s)");
            saveLast("lastRecoveredDir", finalDest.getAbsolutePath());
        });
        new Thread(task).start();
    }
    */
  private void recoverFilesTask(Stage stage) {
    DirectoryChooser srcDc = new DirectoryChooser();
    srcDc.setTitle("Select Source (simulate deleted)");
    File src = srcDc.showDialog(stage);
    if (src == null) return;

    DirectoryChooser destDc = new DirectoryChooser();
    destDc.setTitle("Select Destination (recovered)");
    File dest = destDc.showDialog(stage);
    if (dest == null) dest = new File(RECOVERED_DIR);

    final File finalSrc = src;
    final File finalDest = dest;

    Task<Integer> task = new Task<Integer>() {
        @Override
        protected Integer call() {
            updateMessage("Recovering from " + finalSrc.getAbsolutePath());
            File[] arr = finalSrc.listFiles();
            if (arr == null) {
                updateMessage("No files or access denied.");
                return 0;
            }
            int total = arr.length;
            int count = 0;
            for (int i = 0; i < arr.length; i++) {
                File f = arr[i];
                if (!f.isFile()) {
                    updateProgress(i + 1, total);
                    continue;
                }
                try {
                    Files.copy(f.toPath(), Paths.get(finalDest.getAbsolutePath(), f.getName()), StandardCopyOption.REPLACE_EXISTING);
                    count++;
                    updateMessage("Recovered: " + f.getName());

                    // ===== JDBC INSERT =====
                    DBHelper.insertRecoveredFile(f.getName(), f.getAbsolutePath(),
                            Paths.get(finalDest.getAbsolutePath(), f.getName()).toString(),
                            System.currentTimeMillis());

                } catch (IOException ex) {
                    updateMessage("Fail: " + f.getName());
                }
                updateProgress(i + 1, total);
                try { Thread.sleep(60); } catch (InterruptedException ignored) {}
            }
            updateMessage("Recovered " + count + " / " + total);
            return count;
        }
    };

    bindTaskToUI(task);
    task.setOnSucceeded(e -> {
        appendStatus("Recovered files to: " + finalDest.getAbsolutePath() + " (" + task.getValue() + " files)");
        sessionLog.add("Recovered files from " + finalSrc.getAbsolutePath() + " to " + finalDest.getAbsolutePath() + ": " + task.getValue() + " file(s)");
        saveLast("lastRecoveredDir", finalDest.getAbsolutePath());
    });
    new Thread(task).start();
}



    private void searchKeywordTask(Stage stage) {
        DirectoryChooser dc = new DirectoryChooser();
        dc.setTitle("Select Root Folder to Search");
        File root = dc.showDialog(stage);
        if (root == null) return;
        TextInputDialog tid = new TextInputDialog();
        tid.setHeaderText("Enter keyword (case-insensitive):");
        Optional<String> kwOpt = tid.showAndWait();
        if (kwOpt.isEmpty()) return;
        final String keyword = kwOpt.get().toLowerCase();

        final Path rootPath = root.toPath();

        Task<List<String>> task = new Task<List<String>>() {
            @Override
            protected List<String> call() {
                updateMessage("Searching for '" + keyword + "' ...");
                List<String> hits = new ArrayList<>();
                List<Path> all = collectFiles(rootPath);
                int total = all.size();
                for (int i = 0; i < all.size(); i++) {
                    Path p = all.get(i);
                    updateProgress(i + 1, total);
                    try {
                        String content = Files.readString(p);
                        if (content.toLowerCase().contains(keyword)) hits.add(p.toString());
                    } catch (IOException ignored) {}
                }
                updateMessage("Search complete. " + hits.size() + " matches.");
                return hits;
            }
        };

        bindTaskToUI(task);
        task.setOnSucceeded(e -> {
            List<String> hits = task.getValue();
            if (hits.isEmpty()) appendStatus("No matches found for '" + keyword + "'.");
            else {
                appendStatus(hits.size() + " matches found:");
                for (String h : hits) appendStatus("  - " + h);
            }
            sessionLog.add("Keyword search: '" + keyword + "' under " + root.getAbsolutePath() + " -> " + hits.size() + " match(es)");
            saveLast("lastSearchDir", root.getAbsolutePath());
        });
        new Thread(task).start();
    }

    private void attackScanTask(Stage stage) {
        DirectoryChooser dc = new DirectoryChooser();
        dc.setTitle("Select Directory to Scan for Attack Patterns");
        File root = dc.showDialog(stage);
        if (root == null) return;

        final Path rootPath = root.toPath();

        // load patterns from attack_patterns.txt if exists in working dir
        final List<Pattern> patterns = new ArrayList<>();
        Path pat = Paths.get("attack_patterns.txt");
        if (Files.exists(pat)) {
            try {
                List<String> lines = Files.readAllLines(pat);
                for (String line : lines) {
                    if (line.trim().isEmpty()) continue;
                    // line can be "regex,Name" or simple text
                    String[] parts = line.split(",", 2);
                    patterns.add(Pattern.compile(parts[0], Pattern.CASE_INSENSITIVE));
                }
            } catch (IOException ignored) {}
        } else {
            // fallback built-in patterns (examples)
            patterns.add(Pattern.compile("password|passwd|pwd", Pattern.CASE_INSENSITIVE));
            patterns.add(Pattern.compile("ssh-rsa|-----BEGIN RSA PRIVATE KEY-----", Pattern.CASE_INSENSITIVE));
        }

        Task<Map<Path, List<String>>> task = new Task<Map<Path, List<String>>>() {
            @Override
            protected Map<Path, List<String>> call() {
                updateMessage("Scanning for attack patterns...");
                Map<Path, List<String>> detected = new LinkedHashMap<>();
                List<Path> all = collectFiles(rootPath);
                int total = all.size();
                for (int i = 0; i < all.size(); i++) {
                    Path p = all.get(i);
                    updateProgress(i + 1, total);
                    try {
                        String content = Files.readString(p);
                        List<String> found = new ArrayList<>();
                        for (Pattern patn : patterns) {
                            if (patn.matcher(content).find()) found.add(patn.pattern());
                        }
                        if (!found.isEmpty()) detected.put(p, found);
                    } catch (IOException ignored) {}
                }
                updateMessage("Attack scan complete. " + detected.size() + " affected files.");
                return detected;
            }
        };

        bindTaskToUI(task);
        task.setOnSucceeded(e -> {
            Map<Path, List<String>> res = task.getValue();
            if (res.isEmpty()) appendStatus("No attack patterns detected.");
            else {
                appendStatus("Attack detection report:");
                for (Map.Entry<Path, List<String>> en : res.entrySet()) {
                    appendStatus("File: " + en.getKey().toString());
                    appendStatus("  Patterns: " + String.join(", ", en.getValue()));
                }
            }
            sessionLog.add("Attack scan on: " + root.getAbsolutePath() + " -> " + res.size() + " file(s)");
        });

        new Thread(task).start();
    }

    private void timelineTask(Stage stage) {
        DirectoryChooser dc = new DirectoryChooser();
        dc.setTitle("Select Directory for Timeline");
        File root = dc.showDialog(stage);
        if (root == null) return;
        final Path rootPath = root.toPath();

        Task<List<Path>> task = new Task<List<Path>>() {
            @Override
            protected List<Path> call() {
                updateMessage("Collecting files...");
                List<Path> all = collectFiles(rootPath);
                all.sort((a, b) -> {
                    try {
                        return Long.compare(Files.getLastModifiedTime(b).toMillis(), Files.getLastModifiedTime(a).toMillis());
                    } catch (IOException ex) { return 0; }
                });
                updateMessage("Timeline ready (" + all.size() + " files)");
                updateProgress(1, 1);
                return all;
            }
        };
        bindTaskToUI(task);
        task.setOnSucceeded(e -> {
            List<Path> list = task.getValue();
            appendStatus("Timeline for " + root.getAbsolutePath() + ":");
            SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
            for (Path p : list) {
                try {
                    appendStatus(" " + sdf.format(new Date(Files.getLastModifiedTime(p).toMillis())) + " | " + p.toString());
                } catch (IOException ignored) {}
            }
            sessionLog.add("Timeline generated for: " + root.getAbsolutePath() + " (" + list.size() + " files)");
        });
        new Thread(task).start();
    }

    // ---------- Utility dialogs & small actions ----------

    private void viewMetadata(Stage stage) {
        FileChooser fc = new FileChooser();
        fc.setTitle("Select File");
        File f = fc.showOpenDialog(stage);
        if (f == null) return;
        StringBuilder sb = new StringBuilder();
        sb.append("Name: ").append(f.getName()).append("\n");
        sb.append("Path: ").append(f.getAbsolutePath()).append("\n");
        sb.append("Size: ").append(f.length()).append(" bytes\n");
        sb.append("Readable: ").append(f.canRead()).append("\n");
        sb.append("Writable: ").append(f.canWrite()).append("\n");
        sb.append("Hidden: ").append(f.isHidden()).append("\n");
        sb.append("Last Modified: ").append(new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date(f.lastModified()))).append("\n");
        appendStatus(sb.toString());
        sessionLog.add("Metadata viewed for: " + f.getAbsolutePath());
        saveLast("lastFile", f.getAbsolutePath());
    }
/*
    private void generateHashDialog(Stage stage) {
        FileChooser fc = new FileChooser();
        fc.setTitle("Choose file to hash");
        File f = fc.showOpenDialog(stage);
        if (f == null) return;
        ChoiceDialog<String> cd = new ChoiceDialog<>("SHA-256", "MD5", "SHA-256");
        cd.setHeaderText("Select algorithm");
        Optional<String> opt = cd.showAndWait();
        String algo = opt.orElse("SHA-256");
        try {
            final String hash = computeHash(f.toPath(), algo);
            appendStatus(algo + " for " + f.getName() + ":\n" + hash);
            sessionLog.add("Hash " + algo + " computed for: " + f.getAbsolutePath() + " => " + hash);
        } catch (Exception ex) {
            appendStatus("Hash failed: " + ex.getMessage());
        }
    }
*/
 private void generateHashDialog(Stage stage) {
    FileChooser fc = new FileChooser();
    fc.setTitle("Choose file to hash");
    File f = fc.showOpenDialog(stage);
    if (f == null) return;

    ChoiceDialog<String> cd = new ChoiceDialog<>("SHA-256", "MD5", "SHA-256");
    cd.setHeaderText("Select algorithm");
    Optional<String> opt = cd.showAndWait();
    String algo = opt.orElse("SHA-256");

    try {
        final String hash = computeHash(f.toPath(), algo);
        appendStatus(algo + " for " + f.getName() + ":\n" + hash);
        sessionLog.add("Hash " + algo + " computed for: " + f.getAbsolutePath() + " => " + hash);

        // ===== JDBC INSERT =====
        DBHelper.insertFileHash(f.getName(), f.getAbsolutePath(), hash, System.currentTimeMillis());

    } catch (Exception ex) {
        appendStatus("Hash failed: " + ex.getMessage());
    }
}


    private void verifyHashDialog(Stage stage) {
        FileChooser fc = new FileChooser();
        fc.setTitle("Select file to verify");
        File file = fc.showOpenDialog(stage);
        if (file == null) return;
        final File finalFile = file;

        // Ask user whether to paste hash or choose second file
        Alert choice = new Alert(Alert.AlertType.CONFIRMATION);
        choice.setTitle("Verification Options");
        choice.setHeaderText("Choose verification method:");
        choice.setContentText("YES = Paste known hash value\nNO = Select another file to compare\nCANCEL = Abort");
        ButtonType yes = new ButtonType("Paste hash", ButtonBar.ButtonData.YES);
        ButtonType no = new ButtonType("Choose file", ButtonBar.ButtonData.NO);
        choice.getButtonTypes().setAll(yes, no, ButtonType.CANCEL);

        Optional<ButtonType> result = choice.showAndWait();
        if (result.isEmpty() || result.get() == ButtonType.CANCEL) return;

        try {
            final String fileHash = computeHash(finalFile.toPath(), "SHA-256");
            if (result.get() == yes) {
                TextInputDialog pasteDialog = new TextInputDialog();
                pasteDialog.setTitle("Paste Known Hash");
                pasteDialog.setHeaderText("Paste previous hash (SHA-256) for comparison:");
                Optional<String> pasteOpt = pasteDialog.showAndWait();
                if (pasteOpt.isEmpty()) return;
                String known = pasteOpt.get().trim();
                appendStatus("Computed SHA-256: " + fileHash);
                appendStatus("Provided hash:   " + known);
                if (known.equalsIgnoreCase(fileHash)) {
                    appendStatus("✅ HASH MATCH — file appears unchanged: " + finalFile.getName());
                    sessionLog.add("Verified hash (paste) matched for: " + finalFile.getAbsolutePath());
                } else {
                    appendStatus("❌ HASH MISMATCH — file may have been modified: " + finalFile.getName());
                    sessionLog.add("Verified hash (paste) mismatch for: " + finalFile.getAbsolutePath());
                }
            } else { // choose second file
                FileChooser fc2 = new FileChooser();
                fc2.setTitle("Select second file to compare");
                File file2 = fc2.showOpenDialog(stage);
                if (file2 == null) return;
                final File finalFile2 = file2;
                final String file2Hash = computeHash(finalFile2.toPath(), "SHA-256");
                appendStatus("File1 SHA-256: " + fileHash);
                appendStatus("File2 SHA-256: " + file2Hash);
                if (fileHash.equalsIgnoreCase(file2Hash)) {
                    appendStatus("✅ MATCH — files are identical.");
                    sessionLog.add("Verified files identical: " + finalFile.getAbsolutePath() + " & " + finalFile2.getAbsolutePath());
                } else {
                    appendStatus("❌ DIFFER — files differ.");
                    sessionLog.add("Verified files different: " + finalFile.getAbsolutePath() + " & " + finalFile2.getAbsolutePath());
                }
            }
        } catch (Exception ex) {
            appendStatus("Verify failed: " + ex.getMessage());
        }
    }

    private void exportResultsDialog(Stage stage) {
        DirectoryChooser dc = new DirectoryChooser(); dc.setTitle("Select directory to export results from");
        File root = dc.showDialog(stage); if (root == null) return;
        ChoiceDialog<String> cd = new ChoiceDialog<>("CSV", "CSV", "JSON"); Optional<String> opt = cd.showAndWait();
        String fmt = opt.orElse("CSV");
        try {
            List<Path> all = collectFiles(root.toPath());
            Path out;
            if ("CSV".equals(fmt)) {
                out = Paths.get(REPORTS_DIR, "scan_export_" + System.currentTimeMillis() + ".csv");
                try (BufferedWriter bw = Files.newBufferedWriter(out)) {
                    bw.write("path,size,lastModified,ext\n");
                    for (Path p : all) {
                        bw.write(p.toString() + "," + Files.size(p) + "," + Files.getLastModifiedTime(p).toMillis() + "," + getExt(p.getFileName().toString()) + "\n");
                    }
                }
            } else {
                out = Paths.get(REPORTS_DIR, "scan_export_" + System.currentTimeMillis() + ".json");
                try (BufferedWriter bw = Files.newBufferedWriter(out)) {
                    bw.write("[\n");
                    for (int i = 0; i < all.size(); i++) {
                        Path p = all.get(i);
                        bw.write("{\"path\":\"" + p.toString() + "\",\"size\":" + Files.size(p) + ",\"lastModified\":" + Files.getLastModifiedTime(p).toMillis() + ",\"ext\":\"" + getExt(p.getFileName().toString()) + "\"}");
                        if (i < all.size() - 1) bw.write(",\n");
                    }
                    bw.write("]");
                }
            }
            appendStatus(fmt + " saved: " + out.toAbsolutePath());
            sessionLog.add("Exported " + fmt + " for " + root.getAbsolutePath());
            saveLast("lastExportDir", root.getAbsolutePath());
        } catch (IOException ex) { appendStatus("Export failed: " + ex.getMessage()); }
    }
/*
    private void generateEncryptedReportDialog(Stage stage) {
        if (sessionLog.isEmpty()) { showAlert("No actions", "Nothing to report."); return; }
        TextInputDialog tid = new TextInputDialog();
        tid.setHeaderText("Enter passphrase to encrypt report:");
        Optional<String> passOpt = tid.showAndWait();
        if (passOpt.isEmpty()) return;
        String pass = passOpt.get();
        String content = buildLogContent();
        try {
            byte[] key = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(pass.getBytes(StandardCharsets.UTF_8)), 16);
            SecretKeySpec skey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skey);
            byte[] enc = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));
            Path out = Paths.get(REPORTS_DIR, "report_enc_" + System.currentTimeMillis() + ".enc");
            Files.write(out, enc);
            appendStatus("Encrypted report saved: " + out.toAbsolutePath());
            sessionLog.add("Encrypted report generated");
            saveLast("lastReportDir", out.getParent().toAbsolutePath().toString());
        } catch (Exception ex) { appendStatus("Encryption failed: " + ex.getMessage()); }
    }
    */
   private void generateEncryptedReportDialog(Stage stage) {
    if (sessionLog.isEmpty()) { showAlert("No actions", "Nothing to report."); return; }

    TextInputDialog tid = new TextInputDialog();
    tid.setHeaderText("Enter passphrase to encrypt report:");
    Optional<String> passOpt = tid.showAndWait();
    if (passOpt.isEmpty()) return;

    String pass = passOpt.get();
    String content = buildLogContent();

    try {
        byte[] key = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(pass.getBytes(StandardCharsets.UTF_8)), 16);
        SecretKeySpec skey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skey);
        byte[] enc = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));

        Path out = Paths.get(REPORTS_DIR, "report_enc_" + System.currentTimeMillis() + ".enc");
        Files.write(out, enc);

        appendStatus("Encrypted report saved: " + out.toAbsolutePath());
        sessionLog.add("Encrypted report generated");
        saveLast("lastReportDir", out.getParent().toAbsolutePath().toString());

        // ===== JDBC INSERT =====
        DBHelper.insertEncryptedReport(out.getFileName().toString(), out.toAbsolutePath().toString(), System.currentTimeMillis());

    } catch (Exception ex) {
        appendStatus("Encryption failed: " + ex.getMessage());
    }
}






    private void decryptReportDialog(Stage stage) {
        FileChooser fc = new FileChooser(); fc.setTitle("Select encrypted file (.enc)");
        File enc = fc.showOpenDialog(stage); if (enc == null) return;
        TextInputDialog tid = new TextInputDialog(); tid.setHeaderText("Enter passphrase used for encryption:");
        Optional<String> passOpt = tid.showAndWait(); if (passOpt.isEmpty()) return;
        String pass = passOpt.get();
        FileChooser fcOut = new FileChooser(); fcOut.setTitle("Save Decrypted File As");
        File out = fcOut.showSaveDialog(stage); if (out == null) return;
        try {
            byte[] encBytes = Files.readAllBytes(enc.toPath());
            byte[] key = Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(pass.getBytes(StandardCharsets.UTF_8)), 16);
            SecretKeySpec skey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skey);
            byte[] dec = cipher.doFinal(encBytes);
            Files.write(out.toPath(), dec);
            appendStatus("Decryption successful, saved: " + out.getAbsolutePath());
        } catch (Exception ex) { appendStatus("Decryption failed: " + ex.getMessage()); }
    }

    private void exportPlainReport() {
        if (sessionLog.isEmpty()) { showAlert("No actions", "Nothing to report."); return; }
        String content = buildLogContent();
        try {
            Path p = Paths.get(REPORTS_DIR, "report_" + System.currentTimeMillis() + ".txt");
            Files.writeString(p, content, StandardCharsets.UTF_8);
            appendStatus("Plain report saved: " + p.toAbsolutePath());
            sessionLog.add("Plain report generated");
        } catch (IOException ex) { appendStatus("Save failed: " + ex.getMessage()); }
    }

    private void changePasswordDialog(Stage stage) {
        Dialog<Pair<String,String>> dlg = new Dialog<Pair<String,String>>();
        dlg.setTitle("Change Tool Password");
        ButtonType okBtn = new ButtonType("Change", ButtonBar.ButtonData.OK_DONE);
        dlg.getDialogPane().getButtonTypes().addAll(okBtn, ButtonType.CANCEL);

        GridPane gp = new GridPane();
        gp.setHgap(10); gp.setVgap(10);
        PasswordField cur = new PasswordField(); cur.setPromptText("Current password");
        PasswordField np = new PasswordField(); np.setPromptText("New password");
        PasswordField cnp = new PasswordField(); cnp.setPromptText("Confirm new password");
        gp.addRow(0, new Label("Current:"), cur);
        gp.addRow(1, new Label("New:"), np);
        gp.addRow(2, new Label("Confirm:"), cnp);
        dlg.getDialogPane().setContent(gp);
        dlg.setResultConverter(bt -> {
            if (bt == okBtn) return new Pair<>(np.getText(), cur.getText());
            return null;
        });
        Optional<Pair<String,String>> res = dlg.showAndWait();
        if (res.isPresent()) {
            String newPass = res.get().getKey();
            String curPass = res.get().getValue();
            String stored = cfg.getProperty("pw.hash");
            try {
                if (stored == null) stored = hashString(defaultPassword);
                if (!hashString(curPass).equals(stored)) { showAlert("Error", "Current password incorrect."); return; }
                if (newPass == null || newPass.isEmpty()) { showAlert("Error", "New password cannot be empty."); return; }
                cfg.setProperty("pw.hash", hashString(newPass));
                saveConfig();
                appendStatus("Password changed.");
            } catch (Exception ex) { appendStatus("Password change error: " + ex.getMessage()); }
        }
    }

    private void clearSession() {
        sessionLog.clear();
        statusLog.clear();
        appendStatus("Session cleared.");
    }

    // ---------- Helpers ----------

    private boolean authenticateDialog(Stage owner) {
        String stored = cfg.getProperty("pw.hash");
        TextInputDialog tid = new TextInputDialog();
        tid.setHeaderText("Enter tool password:");
        Optional<String> opt = tid.showAndWait();
        if (opt.isEmpty()) return false;
        String input = opt.get();
        try {
            String wantHash = (stored == null) ? hashString(defaultPassword) : stored;
            if (hashString(input).equals(wantHash)) {
                // if stored absent, persist default or keep existing
                if (stored == null) { cfg.setProperty("pw.hash", wantHash); saveConfig(); }
                appendStatus("Authenticated successfully.");
                return true;
            }
            return false;
        } catch (Exception ex) { return false; }
    }

    private void bindTaskToUI(Task<?> task) {
        progressBar.progressProperty().bind(task.progressProperty());
        progressLabel.textProperty().bind(task.messageProperty());
        task.setOnFailed(e -> appendStatus("Task failed: " + task.getException()));
        task.setOnSucceeded(e -> {
            progressBar.progressProperty().unbind();
            progressBar.setProgress(0);
            progressLabel.textProperty().unbind();
            progressLabel.setText("");
        });
    }

    private void appendStatus(String s) {
        Platform.runLater(() -> {
            statusLog.appendText("[" + new SimpleDateFormat("HH:mm:ss").format(new Date()) + "] " + s + "\n");
        });
    }

    private List<Path> collectFiles(Path root) {
        List<Path> out = new ArrayList<>();
        try {
            Files.walk(root).filter(Files::isRegularFile).forEach(out::add);
        } catch (IOException ignored) {}
        return out;
    }

    private String computeHash(Path p, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        try (InputStream is = Files.newInputStream(p)) {
            byte[] buf = new byte[4096];
            int r;
            while ((r = is.read(buf)) > 0) md.update(buf, 0, r);
        }
        byte[] h = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private String buildLogContent() {
        StringBuilder sb = new StringBuilder();
        sb.append("===== FORENSIC REPORT =====\n");
        sb.append("Generated on: ").append(LocalDateTime.now()).append("\n\n");
        for (int i = 0; i < sessionLog.size(); i++) sb.append((i + 1) + ") " + sessionLog.get(i) + "\n");
        return sb.toString();
    }

    private void ensureBaseDirs() {
        try {
            Files.createDirectories(Paths.get(REPORTS_DIR));
            Files.createDirectories(Paths.get(RECOVERED_DIR));
            Files.createDirectories(cfgDir);
        } catch (IOException ignored) {}
    }

    private void loadConfig() {
        try {
            if (Files.exists(cfgFile)) {
                try (InputStream is = Files.newInputStream(cfgFile)) { cfg.load(is); }
            } else {
                cfg.setProperty("lastDir", "");
                cfg.setProperty("lastRecoveredDir", RECOVERED_DIR);
                // pw.hash left absent -> default used until changed
                saveConfig();
            }
        } catch (Exception ignored) {}
    }

    private void saveConfig() {
        try {
            Files.createDirectories(cfgDir);
            try (OutputStream os = Files.newOutputStream(cfgFile)) { cfg.store(os, "DFTool config"); }
        } catch (IOException ignored) {}
    }

    private void saveLast(String key, String value) {
        cfg.setProperty(key, value);
        saveConfig();
    }

    private String hashString(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] b = md.digest(s.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private void showAlert(String title, String msg) {
        Platform.runLater(() -> {
            Alert a = new Alert(Alert.AlertType.INFORMATION);
            a.setTitle(title);
            a.setHeaderText(null);
            a.setContentText(msg);
            a.showAndWait();
        });
    }

    private String getExt(String name) {
        int i = name.lastIndexOf('.');
        return (i > 0 && i < name.length() - 1) ? name.substring(i + 1) : "";
    }

    // ---------- Inline CSS (cyber theme) ----------
    private String inlineCssAsDataUri() {
        try {
            String css = """
                .card-small {
                    -fx-background-color: linear-gradient(#082a2e, #021019);
                    -fx-text-fill: #e6f7ff;
                    -fx-border-color: #064a57;
                    -fx-border-radius: 8;
                    -fx-background-radius: 8;
                    -fx-padding: 10;
                    -fx-font-size: 12;
                }
                .card-small:hover { -fx-background-color: linear-gradient(#0b3c43, #051121); }
                .card-big {
                    -fx-background-color: linear-gradient(#092b2f, #021019);
                    -fx-text-fill: #dff6ff;
                    -fx-border-color: #087a89;
                    -fx-border-radius: 10;
                    -fx-background-radius: 10;
                    -fx-padding: 12;
                    -fx-font-size: 14;
                    -fx-font-weight: bold;
                }
                .card-big:hover { -fx-background-color: linear-gradient(#0f5562, #03202b); }
                Label { -fx-text-fill: #caf0f8; }
                .root { -fx-font-family: 'Segoe UI', Roboto, Arial; -fx-background-color: linear-gradient(#00121a, #001825); }
                TextArea { -fx-control-inner-background: #021017; -fx-font-family: monospace; -fx-border-color: #043b45; -fx-text-fill: #bfefff; }
                Button { -fx-cursor: hand; }
                """;
            Path tmp = Files.createTempFile("df_css_", ".css");
            Files.writeString(tmp, css, StandardCharsets.UTF_8);
            return tmp.toUri().toString();
        } catch (IOException e) {
            return null;
        }
    }
}
