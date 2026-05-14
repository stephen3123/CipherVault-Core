package com.ciphervault.security;

public record EncryptedPayload(byte[] iv, byte[] ciphertext) {
}
