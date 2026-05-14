package com.ciphervault.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;

class CryptoServiceTest {
    private final PasswordService passwordService = new PasswordService();
    private final CryptoService cryptoService = new CryptoService();

    @Test
    void encryptsAndDecryptsPayload() throws Exception {
        SecretKey key = passwordService.deriveEncryptionKey(
                "vault-master-pass".toCharArray(),
                passwordService.generateSaltBase64(),
                passwordService.defaultIterations()
        );

        byte[] plaintext = "cipher vault test payload".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] aad = "demo.txt|24".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        EncryptedPayload payload = cryptoService.encrypt(plaintext, key, aad);
        byte[] decrypted = cryptoService.decrypt(payload, key, aad);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void rejectsTamperedCiphertext() throws Exception {
        SecretKey key = passwordService.deriveEncryptionKey(
                "vault-master-pass".toCharArray(),
                passwordService.generateSaltBase64(),
                passwordService.defaultIterations()
        );

        byte[] plaintext = "cipher vault test payload".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        EncryptedPayload payload = cryptoService.encrypt(plaintext, key, null);
        payload.ciphertext()[0] ^= 0x01;

        assertThrows(AEADBadTagException.class, () -> cryptoService.decrypt(payload, key, null));
    }
}
