package com.ciphervault.service;

import com.ciphervault.config.AppPaths;
import com.ciphervault.db.AuditLogRepository;
import com.ciphervault.db.DatabaseManager;
import com.ciphervault.db.UserRepository;
import com.ciphervault.db.VaultFileRepository;
import com.ciphervault.model.AuditEntry;
import com.ciphervault.model.UserRecord;
import com.ciphervault.model.VaultFileRecord;
import com.ciphervault.security.CryptoService;
import com.ciphervault.security.EncryptedPayload;
import com.ciphervault.security.PasswordHash;
import com.ciphervault.security.PasswordService;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.SecretKey;

public final class AppService {
    private static final int MASTER_PASSWORD_MIN_LENGTH = 10;
    private static final int LOCKOUT_THRESHOLD = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofSeconds(45);

    private final AppPaths appPaths;
    private final DatabaseManager databaseManager;
    private final UserRepository userRepository;
    private final VaultFileRepository vaultFileRepository;
    private final AuditLogRepository auditLogRepository;
    private final PasswordService passwordService;
    private final CryptoService cryptoService;

    private SecretKey sessionKey;

    public AppService(
            AppPaths appPaths,
            DatabaseManager databaseManager,
            UserRepository userRepository,
            VaultFileRepository vaultFileRepository,
            AuditLogRepository auditLogRepository,
            PasswordService passwordService,
            CryptoService cryptoService
    ) {
        this.appPaths = appPaths;
        this.databaseManager = databaseManager;
        this.userRepository = userRepository;
        this.vaultFileRepository = vaultFileRepository;
        this.auditLogRepository = auditLogRepository;
        this.passwordService = passwordService;
        this.cryptoService = cryptoService;
    }

    public void initialize() throws IOException, SQLException, ClassNotFoundException {
        databaseManager.initialize();
    }

    public boolean isSetupComplete() throws SQLException {
        return userRepository.findPrimaryUser().isPresent();
    }

    public void createVault(char[] masterPassword) throws SQLException, GeneralSecurityException {
        try {
            validateMasterPassword(masterPassword);
            if (isSetupComplete()) {
                throw new IllegalStateException("This device already has a configured CipherVault.");
            }

            int iterations = passwordService.defaultIterations();
            PasswordHash passwordHash = passwordService.hashPassword(masterPassword, iterations);
            String keySaltBase64 = passwordService.generateSaltBase64();
            SecretKey derivedKey = passwordService.deriveEncryptionKey(masterPassword, keySaltBase64, iterations);

            userRepository.save(new UserRecord(
                    1L,
                    passwordHash.hashBase64(),
                    passwordHash.saltBase64(),
                    keySaltBase64,
                    passwordHash.iterations(),
                    iterations,
                    Instant.now(),
                    0,
                    null
            ));

            this.sessionKey = derivedKey;
            auditLogRepository.log("MASTER_PASSWORD_CREATED", "Initialized encrypted local vault", Instant.now());
        } finally {
            PasswordService.wipe(masterPassword);
        }
    }

    public LoginResult login(char[] masterPassword) throws SQLException, GeneralSecurityException {
        try {
            Optional<UserRecord> userRecordOptional = userRepository.findPrimaryUser();
            if (userRecordOptional.isEmpty()) {
                throw new IllegalStateException("Set up CipherVault before trying to log in.");
            }

            UserRecord userRecord = userRecordOptional.get();
            Instant now = Instant.now();

            if (userRecord.lockedUntil() != null && now.isBefore(userRecord.lockedUntil())) {
                auditLogRepository.log("LOGIN_BLOCKED", "Attempted login while lockout was active", now);
                return new LoginResult(false, "Vault locked. Try again in "
                        + secondsRemaining(now, userRecord.lockedUntil()) + " seconds.");
            }

            if (userRecord.lockedUntil() != null && !now.isBefore(userRecord.lockedUntil())) {
                userRepository.resetLockState();
                userRecord = new UserRecord(
                        userRecord.id(),
                        userRecord.passwordHashBase64(),
                        userRecord.passwordSaltBase64(),
                        userRecord.keySaltBase64(),
                        userRecord.passwordIterations(),
                        userRecord.keyIterations(),
                        userRecord.createdAt(),
                        0,
                        null
                );
            }

            boolean matches = passwordService.matches(
                    masterPassword,
                    userRecord.passwordHashBase64(),
                    userRecord.passwordSaltBase64(),
                    userRecord.passwordIterations()
            );

            if (matches) {
                this.sessionKey = passwordService.deriveEncryptionKey(
                        masterPassword,
                        userRecord.keySaltBase64(),
                        userRecord.keyIterations()
                );
                userRepository.resetLockState();
                auditLogRepository.log("LOGIN_SUCCESS", "Unlocked local vault", now);
                return new LoginResult(true, "Vault unlocked successfully.");
            }

            int failedAttempts = userRecord.failedAttempts() + 1;
            Instant lockedUntil = null;
            String message = "Incorrect master password.";

            if (failedAttempts >= LOCKOUT_THRESHOLD) {
                lockedUntil = now.plus(LOCKOUT_DURATION);
                message = "Too many failed attempts. Vault locked for "
                        + LOCKOUT_DURATION.toSeconds() + " seconds.";
            }

            userRepository.updateLockState(failedAttempts, lockedUntil);
            auditLogRepository.log("LOGIN_FAILURE", message, now);
            return new LoginResult(false, message);
        } finally {
            PasswordService.wipe(masterPassword);
        }
    }

    public void logout() {
        sessionKey = null;
    }

    public void shutdown() {
        logout();
    }

    public List<VaultFileRecord> getVaultFiles() throws SQLException {
        requireAuthenticated();
        return vaultFileRepository.findAll();
    }

    public List<AuditEntry> getRecentAuditEntries(int limit) throws SQLException {
        requireAuthenticated();
        return auditLogRepository.findRecent(limit);
    }

    public VaultFileRecord importFile(Path sourceFile) throws IOException, GeneralSecurityException, SQLException {
        requireAuthenticated();
        if (!Files.isRegularFile(sourceFile)) {
            throw new IllegalArgumentException("Choose a valid file to import.");
        }

        byte[] plaintext = Files.readAllBytes(sourceFile);
        String originalName = sourceFile.getFileName().toString();
        String storedName = UUID.randomUUID() + ".cvault";
        String mimeType = detectMimeType(sourceFile);
        Instant createdAt = Instant.now();

        EncryptedPayload payload = cryptoService.encrypt(
                plaintext,
                sessionKey,
                buildAssociatedData(originalName, plaintext.length)
        );

        Path encryptedFile = appPaths.vaultDirectory().resolve(storedName);
        Files.write(encryptedFile, payload.ciphertext(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

        try {
            VaultFileRecord record = new VaultFileRecord(
                    0L,
                    originalName,
                    storedName,
                    mimeType,
                    plaintext.length,
                    Base64.getEncoder().encodeToString(payload.iv()),
                    createdAt
            );
            long generatedId = vaultFileRepository.insert(record);
            auditLogRepository.log(
                    "FILE_IMPORTED",
                    "Imported " + originalName + " (" + formatBytes(plaintext.length) + ")",
                    createdAt
            );
            return record.withId(generatedId);
        } catch (SQLException exception) {
            Files.deleteIfExists(encryptedFile);
            throw exception;
        }
    }

    public Path exportFile(long fileId, Path destination) throws IOException, SQLException, GeneralSecurityException {
        requireAuthenticated();
        VaultFileRecord record = vaultFileRepository.findById(fileId)
                .orElseThrow(() -> new IllegalArgumentException("The selected vault file no longer exists."));

        byte[] ciphertext = Files.readAllBytes(appPaths.vaultDirectory().resolve(record.storedName()));
        EncryptedPayload payload = new EncryptedPayload(Base64.getDecoder().decode(record.ivBase64()), ciphertext);
        byte[] plaintext = cryptoService.decrypt(
                payload,
                sessionKey,
                buildAssociatedData(record.originalName(), record.sizeBytes())
        );

        Path parent = destination.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(destination, plaintext,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);

        auditLogRepository.log(
                "FILE_EXPORTED",
                "Exported decrypted copy of " + record.originalName(),
                Instant.now()
        );
        return destination;
    }

    public void deleteFile(long fileId) throws IOException, SQLException {
        requireAuthenticated();
        VaultFileRecord record = vaultFileRepository.findById(fileId)
                .orElseThrow(() -> new IllegalArgumentException("The selected vault file no longer exists."));

        Files.deleteIfExists(appPaths.vaultDirectory().resolve(record.storedName()));
        vaultFileRepository.deleteById(fileId);
        auditLogRepository.log("FILE_DELETED", "Deleted " + record.originalName() + " from vault", Instant.now());
    }

    public Path getVaultDirectory() {
        return appPaths.vaultDirectory();
    }

    private void requireAuthenticated() {
        if (sessionKey == null) {
            throw new IllegalStateException("Unlock the vault before performing this action.");
        }
    }

    private void validateMasterPassword(char[] password) {
        if (password == null || password.length < MASTER_PASSWORD_MIN_LENGTH) {
            throw new IllegalArgumentException(
                    "Choose a master password with at least " + MASTER_PASSWORD_MIN_LENGTH + " characters."
            );
        }
    }

    private long secondsRemaining(Instant now, Instant lockedUntil) {
        return Math.max(1, Duration.between(now, lockedUntil).toSeconds());
    }

    private byte[] buildAssociatedData(String fileName, long sizeBytes) {
        return (fileName + "|" + sizeBytes).getBytes(StandardCharsets.UTF_8);
    }

    private String detectMimeType(Path sourceFile) throws IOException {
        String mimeType = Files.probeContentType(sourceFile);
        if (mimeType == null || mimeType.isBlank()) {
            return "application/octet-stream";
        }
        return mimeType;
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double size = bytes;
        String[] units = {"KB", "MB", "GB", "TB"};
        int unitIndex = -1;
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        return String.format(Locale.ROOT, "%.1f %s", size, units[unitIndex]);
    }

    public record LoginResult(boolean success, String message) {
    }
}
