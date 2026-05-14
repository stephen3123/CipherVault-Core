package com.ciphervault.app;

import com.ciphervault.config.AppPaths;
import com.ciphervault.db.AuditLogRepository;
import com.ciphervault.db.DatabaseManager;
import com.ciphervault.db.UserRepository;
import com.ciphervault.db.VaultFileRepository;
import com.ciphervault.model.AuditEntry;
import com.ciphervault.model.VaultFileRecord;
import com.ciphervault.security.CryptoService;
import com.ciphervault.security.PasswordService;
import com.ciphervault.service.AppService;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Collectors;
import javafx.application.Application;
import javafx.beans.property.SimpleLongProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public final class CipherVaultApp extends Application {
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm")
                    .withZone(ZoneId.systemDefault());

    private final ObservableList<VaultFileRecord> vaultItems = FXCollections.observableArrayList();
    private final ObservableList<String> auditItems = FXCollections.observableArrayList();

    private Stage primaryStage;
    private AppService appService;
    private TableView<VaultFileRecord> vaultTable;
    private ListView<String> auditListView;
    private Label statusLabel;
    private Label totalFilesValueLabel;
    private Label vaultPathValueLabel;
    private Label latestActivityValueLabel;

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage stage) {
        this.primaryStage = stage;
        primaryStage.setTitle("CipherVault");
        primaryStage.setMinWidth(1120);
        primaryStage.setMinHeight(740);

        try {
            AppPaths appPaths = new AppPaths();
            DatabaseManager databaseManager = new DatabaseManager(appPaths);
            this.appService = new AppService(
                    appPaths,
                    databaseManager,
                    new UserRepository(databaseManager),
                    new VaultFileRepository(databaseManager),
                    new AuditLogRepository(databaseManager),
                    new PasswordService(),
                    new CryptoService()
            );
            appService.initialize();

            if (appService.isSetupComplete()) {
                showLoginView("Enter your master password to unlock the vault.");
            } else {
                showSetupView();
            }

            primaryStage.show();
        } catch (Exception exception) {
            showFatalError("CipherVault could not start.", exception);
        }
    }

    @Override
    public void stop() {
        if (appService != null) {
            appService.shutdown();
        }
    }

    private void showSetupView() {
        PasswordField passwordField = createPasswordField("Master password");
        PasswordField confirmField = createPasswordField("Confirm master password");
        Label helperLabel = createFeedbackLabel("Use at least 10 characters. This password unlocks the whole vault.");
        helperLabel.getStyleClass().setAll("feedback-label", "neutral-text");

        Button createButton = new Button("Create Secure Vault");
        createButton.getStyleClass().addAll("action-button", "primary-button");
        createButton.setMaxWidth(Double.MAX_VALUE);
        createButton.setDefaultButton(true);
        createButton.disableProperty().bind(passwordField.textProperty().isEmpty()
                .or(confirmField.textProperty().isEmpty()));

        createButton.setOnAction(event -> {
            String password = passwordField.getText();
            String confirmPassword = confirmField.getText();

            if (!password.equals(confirmPassword)) {
                setFeedback(helperLabel, "The two passwords do not match.", true);
                return;
            }

            try {
                appService.createVault(password.toCharArray());
                passwordField.clear();
                confirmField.clear();
                showDashboardView("Vault created successfully. Files will now be stored in encrypted form.");
            } catch (Exception exception) {
                setFeedback(helperLabel, exception.getMessage(), true);
            }
        });

        VBox form = createAuthCard(
                "First-time setup",
                "Create a single master password for this device.",
                helperLabel,
                createFieldGroup("Master Password", passwordField),
                createFieldGroup("Confirm Password", confirmField),
                createButton
        );

        Scene scene = buildAuthScene(
                "Local Security Project",
                "CipherVault",
                "An encrypted desktop vault built in Java with AES-GCM, PBKDF2, SQLite, and a clear audit trail.",
                form
        );
        primaryStage.setScene(scene);
    }

    private void showLoginView(String message) {
        PasswordField passwordField = createPasswordField("Master password");
        Label helperLabel = createFeedbackLabel(message);
        helperLabel.getStyleClass().setAll("feedback-label", "neutral-text");

        Button loginButton = new Button("Unlock Vault");
        loginButton.getStyleClass().addAll("action-button", "primary-button");
        loginButton.setMaxWidth(Double.MAX_VALUE);
        loginButton.setDefaultButton(true);
        loginButton.disableProperty().bind(passwordField.textProperty().isEmpty());

        loginButton.setOnAction(event -> {
            try {
                AppService.LoginResult result = appService.login(passwordField.getText().toCharArray());
                passwordField.clear();
                if (result.success()) {
                    showDashboardView(result.message());
                } else {
                    setFeedback(helperLabel, result.message(), true);
                }
            } catch (Exception exception) {
                setFeedback(helperLabel, exception.getMessage(), true);
            }
        });

        VBox form = createAuthCard(
                "Vault Access",
                "Only the master password can derive the encryption key.",
                helperLabel,
                createFieldGroup("Master Password", passwordField),
                loginButton
        );

        Scene scene = buildAuthScene(
                "Encrypted Desktop Vault",
                "Unlock CipherVault",
                "The application keeps metadata in SQLite and stores every vaulted file as AES-GCM encrypted bytes on disk.",
                form
        );
        primaryStage.setScene(scene);
    }

    private void showDashboardView(String initialStatus) {
        BorderPane root = new BorderPane();
        root.getStyleClass().add("dashboard-root");

        VBox page = new VBox(22);
        page.setPadding(new Insets(28));

        HBox header = new HBox(16);
        header.setAlignment(Pos.CENTER_LEFT);

        VBox headerText = new VBox(6);
        Label eyebrow = new Label("Secure Local Workspace");
        eyebrow.getStyleClass().add("eyebrow-label");
        Label title = new Label("CipherVault Dashboard");
        title.getStyleClass().add("page-title");
        Label subtitle = new Label("Import, encrypt, export, and audit your protected files from one place.");
        subtitle.getStyleClass().add("page-subtitle");
        headerText.getChildren().addAll(eyebrow, title, subtitle);

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button revealButton = new Button("Reveal Vault Folder");
        revealButton.getStyleClass().addAll("action-button", "secondary-button");
        revealButton.setOnAction(event ->
                getHostServices().showDocument(appService.getVaultDirectory().toUri().toString()));

        Button logoutButton = new Button("Logout");
        logoutButton.getStyleClass().addAll("action-button", "ghost-button");
        logoutButton.setOnAction(event -> {
            appService.logout();
            showLoginView("Signed out. Re-enter the master password to continue.");
        });

        header.getChildren().addAll(headerText, spacer, revealButton, logoutButton);

        HBox metricsRow = new HBox(16);
        metricsRow.getChildren().addAll(
                createMetricCard("Protected Files", totalFilesValueLabel = createMetricValue("0"), "Encrypted items currently stored in the vault."),
                createMetricCard("Vault Location", vaultPathValueLabel = createMetricValue(appService.getVaultDirectory().toString()), "Encrypted file blobs live here, separate from plaintext exports."),
                createMetricCard("Latest Activity", latestActivityValueLabel = createMetricValue("No activity yet"), "Recent security-relevant event captured in the audit stream.")
        );

        Button importButton = new Button("Import File");
        importButton.getStyleClass().addAll("action-button", "primary-button");
        importButton.setOnAction(event -> handleImport());

        Button exportButton = new Button("Export Decrypted Copy");
        exportButton.getStyleClass().addAll("action-button", "secondary-button");

        Button deleteButton = new Button("Delete From Vault");
        deleteButton.getStyleClass().addAll("action-button", "danger-button");

        Button refreshButton = new Button("Refresh");
        refreshButton.getStyleClass().addAll("action-button", "ghost-button");
        refreshButton.setOnAction(event -> refreshDashboardData("Dashboard refreshed."));

        vaultTable = createVaultTable();
        exportButton.disableProperty().bind(vaultTable.getSelectionModel().selectedItemProperty().isNull());
        deleteButton.disableProperty().bind(vaultTable.getSelectionModel().selectedItemProperty().isNull());

        exportButton.setOnAction(event -> handleExport());
        deleteButton.setOnAction(event -> handleDelete());

        HBox actionBar = new HBox(12, importButton, exportButton, deleteButton, refreshButton);
        actionBar.setAlignment(Pos.CENTER_LEFT);

        VBox vaultCard = new VBox(16);
        vaultCard.getStyleClass().add("panel-card");
        Label vaultTitle = new Label("Encrypted Vault Contents");
        vaultTitle.getStyleClass().add("section-title");
        Label vaultSubtitle = new Label("Every file listed below is stored encrypted and can be exported only after unlocking the vault.");
        vaultSubtitle.getStyleClass().add("section-subtitle");
        VBox.setVgrow(vaultTable, Priority.ALWAYS);
        vaultCard.getChildren().addAll(vaultTitle, vaultSubtitle, actionBar, vaultTable);

        auditListView = new ListView<>(auditItems);
        auditListView.getStyleClass().add("audit-list");
        auditListView.setPlaceholder(new Label("Audit entries will appear here."));
        VBox.setVgrow(auditListView, Priority.ALWAYS);

        VBox auditCard = new VBox(16);
        auditCard.getStyleClass().add("panel-card");
        auditCard.setPrefWidth(360);
        Label auditTitle = new Label("Activity Feed");
        auditTitle.getStyleClass().add("section-title");
        Label auditSubtitle = new Label("Login attempts, imports, exports, and deletes are recorded for demo-ready security visibility.");
        auditSubtitle.getStyleClass().add("section-subtitle");
        auditCard.getChildren().addAll(auditTitle, auditSubtitle, auditListView);

        HBox workspace = new HBox(18, vaultCard, auditCard);
        HBox.setHgrow(vaultCard, Priority.ALWAYS);
        VBox.setVgrow(workspace, Priority.ALWAYS);

        statusLabel = createFeedbackLabel(initialStatus);
        statusLabel.getStyleClass().setAll("feedback-label", "success-text", "status-bar");

        page.getChildren().addAll(header, metricsRow, workspace, statusLabel);
        root.setCenter(page);

        Scene scene = new Scene(root, 1240, 800);
        applyStyles(scene);
        primaryStage.setScene(scene);
        refreshDashboardData(initialStatus);
    }

    private void handleImport() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose a File to Encrypt");
        var selectedFile = chooser.showOpenDialog(primaryStage);

        if (selectedFile == null) {
            return;
        }
        Path selection = selectedFile.toPath();

        try {
            VaultFileRecord record = appService.importFile(selection);
            refreshDashboardData("Imported and encrypted " + record.originalName() + ".");
        } catch (Exception exception) {
            showError("Import failed", exception.getMessage());
        }
    }

    private void handleExport() {
        VaultFileRecord selected = vaultTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            return;
        }

        FileChooser chooser = new FileChooser();
        chooser.setTitle("Export Decrypted Copy");
        chooser.setInitialFileName(selected.originalName());
        var destinationFile = chooser.showSaveDialog(primaryStage);
        if (destinationFile == null) {
            return;
        }
        Path destination = destinationFile.toPath();

        try {
            appService.exportFile(selected.id(), destination);
            refreshDashboardData("Decrypted copy exported to " + destination.getFileName() + ".");
        } catch (Exception exception) {
            showError("Export failed", exception.getMessage());
        }
    }

    private void handleDelete() {
        VaultFileRecord selected = vaultTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            return;
        }

        Alert confirmation = new Alert(
                Alert.AlertType.CONFIRMATION,
                "Delete " + selected.originalName() + " from the encrypted vault?",
                ButtonType.CANCEL,
                ButtonType.OK
        );
        confirmation.setHeaderText("Remove encrypted file");

        if (confirmation.showAndWait().orElse(ButtonType.CANCEL) != ButtonType.OK) {
            return;
        }

        try {
            appService.deleteFile(selected.id());
            refreshDashboardData("Deleted " + selected.originalName() + " from the vault.");
        } catch (Exception exception) {
            showError("Delete failed", exception.getMessage());
        }
    }

    private void refreshDashboardData(String statusMessage) {
        try {
            List<VaultFileRecord> files = appService.getVaultFiles();
            List<AuditEntry> auditEntries = appService.getRecentAuditEntries(20);

            vaultItems.setAll(files);
            auditItems.setAll(auditEntries.stream().map(this::formatAuditEntry).toList());

            totalFilesValueLabel.setText(Integer.toString(files.size()));
            vaultPathValueLabel.setText(appService.getVaultDirectory().toString());
            latestActivityValueLabel.setText(auditEntries.isEmpty()
                    ? "No activity yet"
                    : humanizeEvent(auditEntries.get(0).eventType()));
            setStatus(statusMessage, false);
        } catch (Exception exception) {
            setStatus("Could not refresh dashboard: " + exception.getMessage(), true);
        }
    }

    private TableView<VaultFileRecord> createVaultTable() {
        TableView<VaultFileRecord> table = new TableView<>(vaultItems);
        table.getStyleClass().add("vault-table");
        table.setPlaceholder(new Label("No encrypted files yet. Import something to start."));

        TableColumn<VaultFileRecord, String> nameColumn = new TableColumn<>("File Name");
        nameColumn.setCellValueFactory(cell -> new SimpleStringProperty(cell.getValue().originalName()));
        nameColumn.setPrefWidth(280);

        TableColumn<VaultFileRecord, String> typeColumn = new TableColumn<>("Type");
        typeColumn.setCellValueFactory(cell -> new SimpleStringProperty(cell.getValue().mimeType()));
        typeColumn.setPrefWidth(180);

        TableColumn<VaultFileRecord, Number> sizeColumn = new TableColumn<>("Size");
        sizeColumn.setCellValueFactory(cell -> new SimpleLongProperty(cell.getValue().sizeBytes()));
        sizeColumn.setPrefWidth(120);
        sizeColumn.setCellFactory(column -> new javafx.scene.control.TableCell<>() {
            @Override
            protected void updateItem(Number item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? "" : formatFileSize(item.longValue()));
            }
        });

        TableColumn<VaultFileRecord, String> dateColumn = new TableColumn<>("Added");
        dateColumn.setCellValueFactory(cell -> new SimpleStringProperty(DATE_FORMATTER.format(cell.getValue().createdAt())));
        dateColumn.setPrefWidth(180);

        table.getColumns().addAll(nameColumn, typeColumn, sizeColumn, dateColumn);
        return table;
    }

    private Scene buildAuthScene(String eyebrowText, String titleText, String bodyText, VBox formCard) {
        HBox shell = new HBox(28);
        shell.getStyleClass().add("auth-shell");
        shell.setPadding(new Insets(30));

        VBox heroPanel = new VBox(18);
        heroPanel.getStyleClass().add("hero-panel");
        HBox.setHgrow(heroPanel, Priority.ALWAYS);

        Label eyebrow = new Label(eyebrowText);
        eyebrow.getStyleClass().add("eyebrow-label");
        Label title = new Label(titleText);
        title.getStyleClass().add("hero-title");
        Label body = new Label(bodyText);
        body.getStyleClass().add("hero-copy");
        body.setWrapText(true);

        heroPanel.getChildren().addAll(
                eyebrow,
                title,
                body,
                createInsightTile("AES-GCM", "Authenticated encryption protects file confidentiality and integrity."),
                createInsightTile("PBKDF2", "A master password derives the actual encryption key with a random salt."),
                createInsightTile("Audit Trail", "Login attempts and file actions are logged for project reporting.")
        );

        StackPane formPane = new StackPane(formCard);
        formPane.getStyleClass().add("form-pane");

        shell.getChildren().addAll(heroPanel, formPane);

        BorderPane root = new BorderPane(shell);
        root.getStyleClass().add("auth-root");

        Scene scene = new Scene(root, 1180, 760);
        applyStyles(scene);
        return scene;
    }

    private VBox createAuthCard(String title, String subtitle, Label helperLabel, javafx.scene.Node... content) {
        VBox card = new VBox(16);
        card.getStyleClass().addAll("panel-card", "auth-card");
        card.setPadding(new Insets(28));
        card.setMaxWidth(430);

        Label cardTitle = new Label(title);
        cardTitle.getStyleClass().add("card-title");
        Label cardSubtitle = new Label(subtitle);
        cardSubtitle.getStyleClass().add("section-subtitle");
        cardSubtitle.setWrapText(true);

        card.getChildren().addAll(cardTitle, cardSubtitle);
        card.getChildren().addAll(content);
        card.getChildren().add(helperLabel);
        return card;
    }

    private VBox createFieldGroup(String labelText, TextField field) {
        Label label = new Label(labelText);
        label.getStyleClass().add("field-label");
        VBox group = new VBox(8, label, field);
        group.getStyleClass().add("field-group");
        return group;
    }

    private PasswordField createPasswordField(String promptText) {
        PasswordField field = new PasswordField();
        field.setPromptText(promptText);
        field.getStyleClass().add("text-input");
        return field;
    }

    private VBox createMetricCard(String titleText, Label valueLabel, String bodyText) {
        VBox card = new VBox(10);
        card.getStyleClass().add("metric-card");
        Label title = new Label(titleText);
        title.getStyleClass().add("metric-title");
        Label body = new Label(bodyText);
        body.getStyleClass().add("metric-copy");
        body.setWrapText(true);
        card.getChildren().addAll(title, valueLabel, body);
        return card;
    }

    private Label createMetricValue(String text) {
        Label label = new Label(text);
        label.getStyleClass().add("metric-value");
        label.setWrapText(true);
        return label;
    }

    private VBox createInsightTile(String titleText, String copyText) {
        VBox tile = new VBox(4);
        tile.getStyleClass().add("insight-tile");
        Label title = new Label(titleText);
        title.getStyleClass().add("insight-title");
        Label copy = new Label(copyText);
        copy.getStyleClass().add("insight-copy");
        copy.setWrapText(true);
        tile.getChildren().addAll(title, copy);
        return tile;
    }

    private Label createFeedbackLabel(String text) {
        Label label = new Label(text);
        label.setWrapText(true);
        return label;
    }

    private void setFeedback(Label label, String message, boolean error) {
        label.setText(message);
        label.getStyleClass().setAll("feedback-label", error ? "error-text" : "success-text");
    }

    private void setStatus(String message, boolean error) {
        if (statusLabel != null) {
            setFeedback(statusLabel, message, error);
            statusLabel.getStyleClass().add("status-bar");
        }
    }

    private void showError(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(title);
        alert.setContentText(message);
        alert.showAndWait();
        setStatus(message, true);
    }

    private void showFatalError(String summary, Exception exception) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("CipherVault startup error");
        alert.setHeaderText(summary);
        alert.setContentText(exception.getMessage());
        alert.showAndWait();
        throw new IllegalStateException(summary, exception);
    }

    private void applyStyles(Scene scene) {
        scene.getStylesheets().add(Objects.requireNonNull(
                getClass().getResource("/styles/app.css")).toExternalForm());
    }

    private String formatAuditEntry(AuditEntry entry) {
        return DATE_FORMATTER.format(entry.createdAt()) + "  |  "
                + humanizeEvent(entry.eventType()) + "  |  " + entry.details();
    }

    private String humanizeEvent(String eventType) {
        return Arrays.stream(eventType.toLowerCase(Locale.ROOT).split("_"))
                .map(token -> Character.toUpperCase(token.charAt(0)) + token.substring(1))
                .collect(Collectors.joining(" "));
    }

    private String formatFileSize(long sizeBytes) {
        if (sizeBytes < 1024) {
            return sizeBytes + " B";
        }
        double size = sizeBytes;
        String[] units = {"KB", "MB", "GB", "TB"};
        int unitIndex = -1;
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        return String.format(Locale.ROOT, "%.1f %s", size, units[unitIndex]);
    }
}
