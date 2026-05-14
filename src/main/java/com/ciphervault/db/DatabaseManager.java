package com.ciphervault.db;

import com.ciphervault.config.AppPaths;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public final class DatabaseManager {
    private final AppPaths appPaths;

    public DatabaseManager(AppPaths appPaths) {
        this.appPaths = appPaths;
    }

    public void initialize() throws IOException, SQLException, ClassNotFoundException {
        appPaths.ensureExists();
        Class.forName("org.sqlite.JDBC");

        try (Connection connection = getConnection(); Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE IF NOT EXISTS app_user (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        password_hash TEXT NOT NULL,
                        password_salt TEXT NOT NULL,
                        key_salt TEXT NOT NULL,
                        password_iterations INTEGER NOT NULL,
                        key_iterations INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        failed_attempts INTEGER NOT NULL DEFAULT 0,
                        locked_until TEXT
                    )
                    """);

            statement.execute("""
                    CREATE TABLE IF NOT EXISTS vault_file (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_name TEXT NOT NULL,
                        stored_name TEXT NOT NULL UNIQUE,
                        mime_type TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL,
                        iv_base64 TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """);

            statement.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        details TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """);

            statement.execute("""
                    CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
                    ON audit_log(created_at DESC)
                    """);
        }
    }

    public Connection getConnection() throws SQLException {
        Connection connection = DriverManager.getConnection("jdbc:sqlite:" + appPaths.databaseFile());
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute("PRAGMA busy_timeout = 5000");
        }
        return connection;
    }
}
