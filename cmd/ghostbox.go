// ghostbox.go - GhostBox v0.4 prototype
// OS: Linux/macOS
// Function: Secure ephemeral file sharing with sandboxing, encrypted token, and CLI fetch helper

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	dirToShare       string
	readOnly         bool
	ttlSeconds       int
	sharedSecret     string
	tokenPath        string
	generateTokenOnly bool
	decryptTokenMode bool
	cipherText       string
	privateKeyPath   string
	publicKeyPath    string
	sandboxEnabled   bool
	fetchMode        bool
	fetchURL         string
	fetchPath        string
)

func init() {
	flag.StringVar(&dirToShare, "dir", "", "Directory to expose")
	flag.BoolVar(&readOnly, "readonly", true, "Expose as read-only")
	flag.IntVar(&ttlSeconds, "ttl", 60, "Time to live in seconds")
	flag.StringVar(&sharedSecret, "secret", "changeme", "Shared secret for token HMAC")
	flag.StringVar(&tokenPath, "token-path", "", "Generate token for file path")
	flag.BoolVar(&generateTokenOnly, "gen-token", false, "Only generate token for a file path")
	flag.BoolVar(&decryptTokenMode, "decrypt-token", false, "Decrypt encrypted token")
	flag.StringVar(&cipherText, "ciphertext", "", "Encrypted token to decrypt")
	flag.StringVar(&privateKeyPath, "privkey", "", "Path to RSA private key")
	flag.StringVar(&publicKeyPath, "pubkey", "", "Path to RSA public key")
	flag.BoolVar(&sandboxEnabled, "sandbox", false, "Enable OS-level sandboxing for isolation")
	flag.BoolVar(&fetchMode, "fetch", false, "Fetch file from GhostBox server")
	flag.StringVar(&fetchURL, "url", "", "Base URL of server")
	flag.StringVar(&fetchPath, "path", "", "Path of file to fetch")
}

func generateToken(filePath string, timestamp int64, secret string) string {
	data := fmt.Sprintf("%s|%d", filePath, timestamp)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func encryptTokenRSA(token string, pubKeyPath string) (string, error) {
	pubData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pubData)
	if block == nil {
		return "", fmt.Errorf("Invalid PEM format")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	pubKey := pubInterface.(*rsa.PublicKey)
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, []byte(token), nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func decryptTokenRSA(ciphertext string, privKeyPath string) (string, error) {
	privData, err := os.ReadFile(privKeyPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(privData)
	if block == nil {
		return "", fmt.Errorf("Invalid PEM format")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	encBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encBytes, nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func tokenValid(filePath, token string, secret string) bool {
	timestamp := time.Now().Unix()
	for i := -10; i <= 10; i++ {
		tryTime := timestamp + int64(i)
		if generateToken(filePath, tryTime, secret) == token {
			return true
		}
	}
	return false
}

func serveFile(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	token := r.URL.Query().Get("token")
	absPath := filepath.Join(dirToShare, filepath.Clean("/"+filePath))

	if !strings.HasPrefix(absPath, dirToShare) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	if !tokenValid(filePath, token, sharedSecret) {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	f, err := os.Open(absPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	if readOnly {
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(absPath))
	}
	io.Copy(w, f)
}

func runSandboxedProcess() {
	exePath, _ := os.Executable()
	args := []string{"--dir", dirToShare, "--ttl", fmt.Sprint(ttlSeconds), "--readonly", "--secret", sharedSecret}
	cmd := exec.Command("bwrap",
		"--ro-bind", dirToShare, dirToShare,
		"--proc", "/proc",
		"--dev", "/dev",
		"--unshare-all",
		"--die-with-parent",
		exePath,
	)
	cmd.Args = append(cmd.Args, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Fatal(cmd.Run())
}

func fetchFile() {
	if fetchURL == "" || fetchPath == "" || cipherText == "" || privateKeyPath == "" {
		log.Fatal("--url, --path, --ciphertext, and --privkey are required in fetch mode")
	}
	decryptedToken, err := decryptTokenRSA(cipherText, privateKeyPath)
	if err != nil {
		log.Fatal("Token decryption failed:", err)
	}
	fullURL := fmt.Sprintf("%s/fetch?path=%s&token=%s", fetchURL, fetchPath, decryptedToken)
	fmt.Println("[INFO] Fetching:", fullURL)
	exec.Command("curl", "-O", fullURL).Run()
}

func main() {
	flag.Parse()

	if fetchMode {
		fetchFile()
		return
	}

	if decryptTokenMode {
		if privateKeyPath == "" || cipherText == "" {
			log.Fatal("--privkey and --ciphertext are required for decrypt-token mode")
		}
		tok, err := decryptTokenRSA(cipherText, privateKeyPath)
		if err != nil {
			log.Fatal("Decryption failed:", err)
		}
		fmt.Println("Decrypted token:", tok)
		return
	}

	if generateTokenOnly {
		if tokenPath == "" || publicKeyPath == "" {
			log.Fatal("--token-path and --pubkey are required for token generation")
		}
		ts := time.Now().Unix()
		tok := generateToken(tokenPath, ts, sharedSecret)
		encryptedTok, err := encryptTokenRSA(tok, publicKeyPath)
		if err != nil {
			log.Fatal("Encryption failed:", err)
		}
		fmt.Println("Encrypted token (Base64):", encryptedTok)
		fmt.Println("Use within ~10s of timestamp:", ts)
		return
	}

	if dirToShare == "" {
		log.Fatal("Please specify a directory to expose with --dir")
	}

	if sandboxEnabled && runtime.GOOS == "linux" {
		runSandboxedProcess()
		return
	}

	http.HandleFunc("/fetch", serveFile)
	server := &http.Server{
		Addr: ":8080",
		ReadTimeout: 5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Printf("[INFO] Serving %s on http://localhost:8080/fetch (ttl: %d sec)\n", dirToShare, ttlSeconds)

	go func() {
		time.Sleep(time.Duration(ttlSeconds) * time.Second)
		fmt.Println("[INFO] TTL expired. Shutting down.")
		server.Close()
		os.Exit(0)
	}()

	log.Fatal(server.ListenAndServe())
}
