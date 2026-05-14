package com.ciphervault.db;

import com.ciphervault.model.UserRecord;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.util.Optional;

public final class UserRepository {
    private final DatabaseManager databaseManager;

    public UserRepository(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
    }

    public Optional<UserRecord> findPrimaryUser() throws SQLException {
        String sql = """
                SELECT id, password_hash, password_salt, key_salt,
                       password_iterations, key_iterations, created_at,
                       failed_attempts, locked_until
                FROM app_user
                WHERE id = 1
                """;

        try (Connection connection = databaseManager.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet resultSet = statement.executeQuery()) {
            if (resultSet.next()) {
                return Optional.of(map(resultSet));
            }
            return Optional.empty();
        }
    }

    public void save(UserRecord userRecord) throws SQLException {
        String sql = """
                INSERT INTO app_user (
                    id, password_hash, password_salt, key_salt,
                    password_iterations, key_iterations, created_at,
                    failed_attempts, locked_until
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;

        try (Connection connection = databaseManager.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setLong(1, userRecord.id());
            statement.setString(2, userRecord.passwordHashBase64());
            statement.setString(3, userRecord.passwordSaltBase64());
            statement.setString(4, userRecord.keySaltBase64());
            statement.setInt(5, userRecord.passwordIterations());
            statement.setInt(6, userRecord.keyIterations());
            statement.setString(7, userRecord.createdAt().toString());
            statement.setInt(8, userRecord.failedAttempts());
            if (userRecord.lockedUntil() == null) {
                statement.setNull(9, Types.VARCHAR);
            } else {
                statement.setString(9, userRecord.lockedUntil().toString());
            }
            statement.executeUpdate();
        }
    }

    public void updateLockState(int failedAttempts, Instant lockedUntil) throws SQLException {
        String sql = """
                UPDATE app_user
                SET failed_attempts = ?, locked_until = ?
                WHERE id = 1
                """;

        try (Connection connection = databaseManager.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, failedAttempts);
            if (lockedUntil == null) {
                statement.setNull(2, Types.VARCHAR);
            } else {
                statement.setString(2, lockedUntil.toString());
            }
            statement.executeUpdate();
        }
    }

    public void resetLockState() throws SQLException {
        updateLockState(0, null);
    }

    private UserRecord map(ResultSet resultSet) throws SQLException {
        String lockedUntil = resultSet.getString("locked_until");
        return new UserRecord(
                resultSet.getLong("id"),
                resultSet.getString("password_hash"),
                resultSet.getString("password_salt"),
                resultSet.getString("key_salt"),
                resultSet.getInt("password_iterations"),
                resultSet.getInt("key_iterations"),
                Instant.parse(resultSet.getString("created_at")),
                resultSet.getInt("failed_attempts"),
                lockedUntil == null ? null : Instant.parse(lockedUntil)
        );
    }
}
