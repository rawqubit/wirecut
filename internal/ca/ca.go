package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	CertFileName = "ca.pem"
	KeyFileName  = "ca-key.pem"
)

type CA struct {
	dir     string
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer

	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".wirecut"), nil
}

func LoadOrCreate(dir string) (*CA, error) {
	if dir == "" {
		var err error
		dir, err = DefaultDir()
		if err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir %s: %w", dir, err)
	}

	certPath := filepath.Join(dir, CertFileName)
	keyPath := filepath.Join(dir, KeyFileName)

	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	switch {
	case certErr == nil && keyErr == nil:
		return load(dir, certPath, keyPath)
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		return generate(dir, certPath, keyPath)
	case certErr != nil && !errors.Is(certErr, os.ErrNotExist):
		return nil, fmt.Errorf("stat %s: %w", certPath, certErr)
	case keyErr != nil && !errors.Is(keyErr, os.ErrNotExist):
		return nil, fmt.Errorf("stat %s: %w", keyPath, keyErr)
	default:
		return nil, fmt.Errorf("incomplete CA state in %s: both %s and %s must exist or both be absent", dir, CertFileName, KeyFileName)
	}
}

func load(dir, certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", keyPath, err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate in %s is not a CA", certPath)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid private key PEM in %s", keyPath)
	}
	signer, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca private key: %w", err)
	}

	return &CA{
		dir:     dir,
		cert:    cert,
		certPEM: certPEM,
		key:     signer,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := k.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, errors.New("pkcs8 key does not implement crypto.Signer")
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format")
}

func generate(dir, certPath, keyPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "wirecut Local Root CA",
			Organization: []string{"wirecut"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create ca certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated ca certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ca key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", keyPath, err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write %s: %w", certPath, err)
	}

	return &CA{
		dir:     dir,
		cert:    cert,
		certPEM: certPEM,
		key:     key,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func (c *CA) Dir() string                  { return c.dir }
func (c *CA) CertPath() string             { return filepath.Join(c.dir, CertFileName) }
func (c *CA) KeyPath() string              { return filepath.Join(c.dir, KeyFileName) }
func (c *CA) Certificate() *x509.Certificate { return c.cert }
func (c *CA) CertPEM() []byte              { return append([]byte(nil), c.certPEM...) }

func (c *CA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

func (c *CA) MintLeaf(hosts ...string) (*tls.Certificate, error) {
	dnsNames, ips, cacheKey := normalizeHosts(hosts)
	if cacheKey == "" {
		return nil, errors.New("at least one host is required to mint a leaf certificate")
	}

	c.mu.RLock()
	if cached, ok := c.cache[cacheKey]; ok && cached.Leaf != nil && time.Now().Add(time.Hour).Before(cached.Leaf.NotAfter) {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if cached, ok := c.cache[cacheKey]; ok && cached.Leaf != nil && time.Now().Add(time.Hour).Before(cached.Leaf.NotAfter) {
		return cached, nil
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	cn := ""
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	} else if len(ips) > 0 {
		cn = ips[0].String()
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"wirecut"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(0, 1, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &leafKey.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate for %s: %w", cacheKey, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse signed leaf certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}
	c.cache[cacheKey] = tlsCert
	return tlsCert, nil
}

func normalizeHosts(raw []string) (dnsNames []string, ips []net.IP, key string) {
	seen := make(map[string]struct{})
	var all []string
	for _, h := range raw {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		h = strings.TrimPrefix(h, "[")
		h = strings.TrimSuffix(h, "]")
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			norm := ip.String()
			if _, ok := seen[norm]; !ok {
				seen[norm] = struct{}{}
				ips = append(ips, ip)
				all = append(all, norm)
			}
			continue
		}
		norm := strings.ToLower(h)
		if _, ok := seen[norm]; !ok {
			seen[norm] = struct{}{}
			dnsNames = append(dnsNames, norm)
			all = append(all, norm)
		}
	}
	sort.Strings(all)
	return dnsNames, ips, strings.Join(all, ",")
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	if serial.Sign() <= 0 {
		serial = big.NewInt(1)
	}
	return serial, nil
}
