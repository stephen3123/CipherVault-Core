package com.ciphervault.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

class PasswordServiceTest {
    private final PasswordService passwordService = new PasswordService();

    @Test
    void hashesPasswordAndMatchesCorrectValue() throws Exception {
        PasswordHash hash = passwordService.hashPassword("top-secret-pass".toCharArray());

        assertTrue(passwordService.matches(
                "top-secret-pass".toCharArray(),
                hash.hashBase64(),
                hash.saltBase64(),
                hash.iterations()
        ));
        assertFalse(passwordService.matches(
                "wrong-password".toCharArray(),
                hash.hashBase64(),
                hash.saltBase64(),
                hash.iterations()
        ));
    }

    @Test
    void derivesStableKeyFromSamePasswordAndSalt() throws Exception {
        String salt = passwordService.generateSaltBase64();

        SecretKey keyOne = passwordService.deriveEncryptionKey("repeatable-pass".toCharArray(), salt, passwordService.defaultIterations());
        SecretKey keyTwo = passwordService.deriveEncryptionKey("repeatable-pass".toCharArray(), salt, passwordService.defaultIterations());
        SecretKey keyThree = passwordService.deriveEncryptionKey("different-pass".toCharArray(), salt, passwordService.defaultIterations());

        assertTrue(java.util.Arrays.equals(keyOne.getEncoded(), keyTwo.getEncoded()));
        assertNotEquals(java.util.Base64.getEncoder().encodeToString(keyOne.getEncoded()),
                java.util.Base64.getEncoder().encodeToString(keyThree.getEncoded()));
    }
}
