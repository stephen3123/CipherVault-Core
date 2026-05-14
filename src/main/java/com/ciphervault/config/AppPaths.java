package com.ciphervault.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class AppPaths {
    private final Path applicationHome;
    private final Path databaseFile;
    private final Path vaultDirectory;

    public AppPaths() {
        this(resolveApplicationHome());
    }

    public AppPaths(Path applicationHome) {
        this.applicationHome = applicationHome.toAbsolutePath().normalize();
        this.databaseFile = this.applicationHome.resolve("ciphervault.db");
        this.vaultDirectory = this.applicationHome.resolve("vault");
    }

    public Path applicationHome() {
        return applicationHome;
    }

    public Path databaseFile() {
        return databaseFile;
    }

    public Path vaultDirectory() {
        return vaultDirectory;
    }

    public void ensureExists() throws IOException {
        Files.createDirectories(applicationHome);
        Files.createDirectories(vaultDirectory);
    }

    private static Path resolveApplicationHome() {
        String customHome = System.getProperty("ciphervault.home");
        if (customHome != null && !customHome.isBlank()) {
            return Path.of(customHome);
        }
        return Path.of(System.getProperty("user.home"), ".ciphervault");
    }
}
