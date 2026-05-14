package com.ciphervault.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ciphervault.config.AppPaths;
import com.ciphervault.db.AuditLogRepository;
import com.ciphervault.db.DatabaseManager;
import com.ciphervault.db.UserRepository;
import com.ciphervault.db.VaultFileRepository;
import com.ciphervault.model.VaultFileRecord;
import com.ciphervault.service.AppService;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AppServiceTest {
    @TempDir
    Path tempDir;

    @Test
    void createsVaultAndRoundTripsEncryptedFile() throws Exception {
        AppPaths paths = new AppPaths(tempDir.resolve(".ciphervault-test"));
        DatabaseManager databaseManager = new DatabaseManager(paths);
        AppService service = new AppService(
                paths,
                databaseManager,
                new UserRepository(databaseManager),
                new VaultFileRepository(databaseManager),
                new AuditLogRepository(databaseManager),
                new PasswordService(),
                new CryptoService()
        );

        service.initialize();
        service.createVault("course-project-pass".toCharArray());
        assertTrue(service.isSetupComplete());

        Path source = tempDir.resolve("sample.txt");
        byte[] expectedBytes = "very secret content".getBytes(StandardCharsets.UTF_8);
        Files.write(source, expectedBytes);

        VaultFileRecord record = service.importFile(source);
        assertTrue(service.getVaultFiles().size() == 1);

        Path encryptedBlob = paths.vaultDirectory().resolve(record.storedName());
        assertFalse(java.util.Arrays.equals(expectedBytes, Files.readAllBytes(encryptedBlob)));

        Path exported = tempDir.resolve("exported.txt");
        service.exportFile(record.id(), exported);
        assertArrayEquals(expectedBytes, Files.readAllBytes(exported));

        service.deleteFile(record.id());
        assertTrue(service.getVaultFiles().isEmpty());
        assertTrue(service.getRecentAuditEntries(10).size() >= 4);
    }
}
