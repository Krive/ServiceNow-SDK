package core

import (
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
