package com.ciphervault.model;

import java.time.Instant;

public record VaultFileRecord(
        long id,
        String originalName,
        String storedName,
        String mimeType,
        long sizeBytes,
        String ivBase64,
        Instant createdAt
) {
    public VaultFileRecord withId(long updatedId) {
        return new VaultFileRecord(updatedId, originalName, storedName, mimeType, sizeBytes, ivBase64, createdAt);
    }
}
