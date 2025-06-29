**GhostBox** is a secure ephemeral file sharing CLI tool that exposes local files/folders to the internet with:

- 🔐 One-time access tokens (HMAC + RSA encrypted)
- 🛡️ OS-level sandboxing (Linux with bubblewrap, macOS support coming)
- ⏱️ TTL-based auto-expiration
- 🔓 Optional fetch helper with token decryption and `curl` execution

---

## 🚀 Features

- Expose any local folder or file with time-limited access
- Tokens are:
  - Signed with HMAC (SHA-256)
  - Encrypted with recipient’s RSA public key
- Files are sandboxed and isolated from the rest of your system
- File access is read-only, executable-safe, and scoped

---

## 📦 Installation

```bash
make build      # Build the CLI
make install    # Install to $GOBIN (usually ~/go/bin)
```

---

## 🧪 Usage

### Expose a Directory
```bash
ghostbox --dir ./share \
         --ttl 60 \
         --pubkey ./receiver_pub.pem \
         --secret mysecret \
         --sandbox
```

### Generate Encrypted Token
```bash
ghostbox --gen-token \
         --token-path filename.txt \
         --pubkey ./receiver_pub.pem \
         --secret mysecret
```

### Decrypt Token (Client Side)
```bash
ghostbox --decrypt-token \
         --ciphertext "AHy49Fn...==" \
         --privkey ./my_private.pem
```

### Fetch File (Client Side)
```bash
ghostbox --fetch \
         --url http://host:8080 \
         --path filename.txt \
         --ciphertext "AHy49Fn...==" \
         --privkey ./my_private.pem
```
