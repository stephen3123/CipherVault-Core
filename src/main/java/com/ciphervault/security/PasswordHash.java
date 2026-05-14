package com.ciphervault.security;

public record PasswordHash(String hashBase64, String saltBase64, int iterations) {
}
