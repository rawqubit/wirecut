package ca

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateAndMintLeaf(t *testing.T) {
	dir := t.TempDir()

	root, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate first run failed: %v", err)
	}
	if !root.Certificate().IsCA {
		t.Fatal("expected generated cert to have IsCA=true")
	}

	if _, err := os.Stat(filepath.Join(dir, CertFileName)); err != nil {
		t.Fatalf("ca.pem missing: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, KeyFileName))
	if err != nil {
		t.Fatalf("ca-key.pem missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected ca-key.pem mode 0600, got %o", info.Mode().Perm())
	}

	// Reload from disk and ensure serial matches.
	reloaded, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate reload failed: %v", err)
	}
	if reloaded.Certificate().SerialNumber.Cmp(root.Certificate().SerialNumber) != 0 {
		t.Fatal("reloaded CA serial does not match original")
	}

	// Mint DNS leaf.
	leafDNS, err := reloaded.MintLeaf("api.example.com:443")
	if err != nil {
		t.Fatalf("MintLeaf DNS failed: %v", err)
	}
	if leafDNS.Leaf == nil {
		t.Fatal("expected Leaf to be populated")
	}

	pool := reloaded.CertPool()
	if _, err := leafDNS.Leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "api.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("DNS leaf chain verification failed: %v", err)
	}

	// Cached hit returns same leaf serial.
	leafDNS2, err := reloaded.MintLeaf("API.EXAMPLE.COM")
	if err != nil {
		t.Fatalf("MintLeaf DNS cache lookup failed: %v", err)
	}
	if leafDNS2.Leaf.SerialNumber.Cmp(leafDNS.Leaf.SerialNumber) != 0 {
		t.Fatal("expected cached leaf certificate for same host")
	}

	// Mint IP leaf.
	leafIP, err := reloaded.MintLeaf("127.0.0.1:8443")
	if err != nil {
		t.Fatalf("MintLeaf IP failed: %v", err)
	}
	if _, err := leafIP.Leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "127.0.0.1",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("IP leaf chain verification failed: %v", err)
	}
}

func TestIncompleteCADirErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, CertFileName), []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("expected error when only ca.pem exists without ca-key.pem")
	}
}
