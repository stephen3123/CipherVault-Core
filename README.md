# CipherVault

**A secure, local-first encrypted file vault built with Java 21, JavaFX, and SQLite.**

Every file you import is encrypted using **AES-GCM** (authenticated encryption). The encryption key is derived from your master password using **PBKDF2**. All vault metadata is stored in a local **SQLite** database. A full **audit trail** records every login, import, export, and delete.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Java 21 |
| UI | JavaFX 21 |
| Build Tool | Maven 3 |
| Database | SQLite (via Xerial JDBC) |
| Encryption | AES/GCM/NoPadding (128-bit tag, 12-byte IV) |
| Key Derivation | PBKDF2 with random salt |
| Tests | JUnit 5 |

---

## Prerequisites

Before you start, make sure you have the following installed:

- **Java 21 JDK** (e.g., OpenJDK 21 or GraalVM 21)
    - Check: `java --version` → must show `21.x`
- **Maven 3.8+**
    - Check: `mvn --version`

> JavaFX is automatically downloaded by Maven. You do **not** need to install it manually.

---

## Clone the Repository

```bash
git clone https://github.com/stephen3123/CipherVault-Core.git
cd CipherVault-Core
```

---

## Run the Application

```bash
mvn javafx:run
```

This will:
1. Compile all Java source files.
2. Download JavaFX 21.0.8 and SQLite JDBC from Maven Central (first run only).
3. Launch the CipherVault desktop window.

---

## First-Time Setup

1. **On first launch**, you will see a "First-time setup" screen.
2. Enter a **master password** (minimum 10 characters recommended).
3. Confirm the password and click **"Create Secure Vault"**.
4. This creates the SQLite database and derives your encryption key from the password using PBKDF2 + a random salt.
5. You are redirected to the **Dashboard**.

> Your master password is **never stored**. It is used only to derive the AES key at runtime. If you forget it, there is no recovery.

---

## Daily Usage (Dashboard)

After unlocking with your master password, you will see the **CipherVault Dashboard** with:

### Import a File
1. Click **"Import File"**.
2. Select any file from your system (image, document, archive, etc.).
3. CipherVault reads the file, encrypts it using AES-GCM, and saves the ciphertext blob to the vault folder on disk.
4. The file metadata (name, type, size, date) is recorded in the SQLite database.

### Export a Decrypted Copy
1. Select a file from the **Encrypted Vault Contents** table.
2. Click **"Export Decrypted Copy"**.
3. Choose a save location.
4. CipherVault decrypts the blob using your session key and writes the plaintext file to the chosen location.

### Delete a File from Vault
1. Select a file from the table.
2. Click **"Delete From Vault"**.
3. Confirm the deletion. The encrypted blob and its database record are permanently removed.

### Reveal Vault Folder
- Click **"Reveal Vault Folder"** to open the folder where encrypted blobs are stored. The files here are raw ciphertext — unreadable without CipherVault.

### Audit Trail
- The right-hand panel shows the last **20 activity entries**: login attempts, imports, exports, and deletes. This is stored in the SQLite database under the `audit_log` table.

### Logout
- Click **"Logout"** to lock the vault. The AES key is wiped from memory. A password is required to unlock again.

---

## How the Encryption Works (Technical)

1. **Key Derivation**: At login, `PBKDF2WithHmacSHA256` derives a 256-bit `SecretKey` from your password + a stored random salt.
2. **Encryption** (`CryptoService.java`):
    - A fresh 12-byte IV is generated via `SecureRandom` for every file.
    - `AES/GCM/NoPadding` with a 128-bit authentication tag encrypts the plaintext.
    - The IV is stored alongside the ciphertext in the `EncryptedPayload`.
3. **Decryption**: The IV is retrieved from the payload and used to reconstruct the `GCMParameterSpec` for decryption.

---

## Run Tests

```bash
mvn test
```

Tests cover `CryptoService`, `PasswordService`, and `AppService` and are located in `src/test/java/com/ciphervault/security/`.

---

## Project Structure

```
CipherVault/
├── pom.xml                          # Maven build config
└── src/
    └── main/
        ├── java/com/ciphervault/
        │   ├── app/
        │   │   ├── CipherVaultApp.java   # Main JavaFX Application (all UI)
        │   │   └── Launcher.java         # Entry point (calls CipherVaultApp.main)
        │   ├── config/
        │   │   └── AppPaths.java         # Vault & DB file locations
        │   ├── db/
        │   │   ├── DatabaseManager.java  # SQLite connection + schema setup
        │   │   ├── UserRepository.java   # User table operations
        │   │   ├── VaultFileRepository.java # Encrypted file records
        │   │   └── AuditLogRepository.java  # Audit trail operations
        │   ├── model/
        │   │   ├── VaultFileRecord.java  # Encrypted file metadata
        │   │   ├── UserRecord.java       # User + salt + hash record
        │   │   └── AuditEntry.java       # Single audit log event
        │   ├── security/
        │   │   ├── CryptoService.java    # AES-GCM encrypt/decrypt
        │   │   ├── PasswordService.java  # PBKDF2 key derivation
        │   │   ├── PasswordHash.java     # Argon2 password hashing
        │   │   └── EncryptedPayload.java # IV + ciphertext container
        │   └── service/
        │       └── AppService.java       # Business logic (import/export/login)
        └── resources/
            └── styles/
                └── app.css              # JavaFX stylesheet
```
