package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFileTokenStorageHashesKeyToFilename(t *testing.T) {
	dir := t.TempDir()
	storage := NewFileTokenStorage(dir)

	token := &OAuthToken{AccessToken: "abc", ExpiresIn: 3600}
	if err := storage.Save("https://instance.service-now.com/client/id", token); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one token file, got %d", len(entries))
	}
	if filepath.Ext(entries[0].Name()) != ".json" {
		t.Fatalf("unexpected token extension: %s", entries[0].Name())
	}
	if len(entries[0].Name()) != len("0000000000000000000000000000000000000000000000000000000000000000.json") {
		t.Fatalf("token filename should be sha256 hex + .json, got %s", entries[0].Name())
	}

	loaded, err := storage.Load("https://instance.service-now.com/client/id")
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded == nil || loaded.AccessToken != "abc" {
		t.Fatalf("unexpected loaded token: %#v", loaded)
	}
	if loaded.ExpiresIn <= 0 || loaded.ExpiresIn > 3600 {
		t.Fatalf("unexpected remaining expiry seconds: %d", loaded.ExpiresIn)
	}
}

func TestMemoryTokenStorageRoundTrip(t *testing.T) {
	storage := NewMemoryTokenStorage()
	key := "oauth_cc_test"
	token := &OAuthToken{
		AccessToken:  "mem-token",
		RefreshToken: "mem-refresh",
		ExpiresIn:    120,
	}

	if err := storage.Save(key, token); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := storage.Load(key)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded == nil {
		t.Fatalf("expected token, got nil")
	}
	if loaded.AccessToken != token.AccessToken || loaded.RefreshToken != token.RefreshToken {
		t.Fatalf("unexpected loaded token: %#v", loaded)
	}

	if err := storage.Delete(key); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	loaded, err = storage.Load(key)
	if err != nil {
		t.Fatalf("load after delete failed: %v", err)
	}
	if loaded != nil {
		t.Fatalf("expected nil token after delete, got %#v", loaded)
	}
}

func TestEncryptedFileTokenStorageRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	storage, err := NewEncryptedFileTokenStorage(dir, key)
	if err != nil {
		t.Fatalf("failed to create encrypted storage: %v", err)
	}

	token := &OAuthToken{
		AccessToken:  "super-secret-access",
		RefreshToken: "super-secret-refresh",
		ExpiresIn:    3600,
	}
	if err := storage.Save("oauth_cc_test", token); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one token file, got %d", len(entries))
	}

	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read encrypted token file failed: %v", err)
	}
	if bytes.Contains(data, []byte(token.AccessToken)) || bytes.Contains(data, []byte(token.RefreshToken)) {
		t.Fatalf("token file should not contain plaintext token values")
	}

	loaded, err := storage.Load("oauth_cc_test")
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded == nil {
		t.Fatalf("expected token, got nil")
	}
	if loaded.AccessToken != token.AccessToken || loaded.RefreshToken != token.RefreshToken {
		t.Fatalf("unexpected loaded token: %#v", loaded)
	}
}

func TestEncryptedFileTokenStorageWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	goodKey := []byte("0123456789abcdef0123456789abcdef")
	badKey := []byte("abcdef0123456789abcdef0123456789")

	goodStorage, err := NewEncryptedFileTokenStorage(dir, goodKey)
	if err != nil {
		t.Fatalf("failed to create encrypted storage: %v", err)
	}

	if err := goodStorage.Save("oauth_cc_test", &OAuthToken{AccessToken: "secret", ExpiresIn: 60}); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	badStorage, err := NewEncryptedFileTokenStorage(dir, badKey)
	if err != nil {
		t.Fatalf("failed to create bad-key storage: %v", err)
	}

	if _, err := badStorage.Load("oauth_cc_test"); err == nil {
		t.Fatalf("expected decryption error with wrong key")
	}
}

func TestEncryptedFileTokenStorageCanReadLegacyPlaintext(t *testing.T) {
	dir := t.TempDir()
	plain := NewFileTokenStorage(dir)
	key := []byte("0123456789abcdef0123456789abcdef")
	encrypted, err := NewEncryptedFileTokenStorage(dir, key)
	if err != nil {
		t.Fatalf("failed to create encrypted storage: %v", err)
	}

	if err := plain.Save("oauth_cc_test", &OAuthToken{AccessToken: "legacy", ExpiresIn: 120}); err != nil {
		t.Fatalf("legacy save failed: %v", err)
	}

	loaded, err := encrypted.Load("oauth_cc_test")
	if err != nil {
		t.Fatalf("encrypted storage should read legacy token: %v", err)
	}
	if loaded == nil || loaded.AccessToken != "legacy" {
		t.Fatalf("unexpected loaded legacy token: %#v", loaded)
	}
}
