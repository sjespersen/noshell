package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func handler(t *testing.T) http.Handler {
	t.Helper()
	site, err := fs.Sub(embedded, "site")
	if err != nil {
		t.Fatal(err)
	}
	return secure(staticHandler(site))
}

func do(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	handler(t).ServeHTTP(rr, req)
	return rr
}

func TestIndex(t *testing.T) {
	rr := do(t, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d", rr.Code)
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing security headers")
	}
}

func TestNotFound(t *testing.T) {
	rr := do(t, httptest.NewRequest(http.MethodGet, "/does-not-exist", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("got %d", rr.Code)
	}
}

func TestTraversal(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.URL.Path = "/../../etc/passwd"
	if rr := do(t, req); rr.Code != http.StatusNotFound {
		t.Fatalf("got %d", rr.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		rr := do(t, httptest.NewRequest(m, "/", nil))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: got %d", m, rr.Code)
		}
	}
}

func TestRejectsBodiesAndEncodings(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", strings.NewReader("x"))
	if rr := do(t, req); rr.Code != http.StatusBadRequest {
		t.Fatalf("body: got %d", rr.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Content-Encoding", "br")
	if rr := do(t, req); rr.Code != http.StatusBadRequest {
		t.Fatalf("content-encoding: got %d", rr.Code)
	}
}

func TestHiddenFilesNeverServed(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html":        {Data: []byte("ok")},
		".env":              {Data: []byte("SECRET=1")},
		"_drafts/post.html": {Data: []byte("draft")},
		"sub/.htpasswd":     {Data: []byte("x")},
	}
	h := secure(staticHandler(fsys))
	for _, p := range []string{"/.env", "/_drafts/post.html", "/sub/.htpasswd", "/%2eenv", "/sub/../.env"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = strings.ReplaceAll(p, "%2e", ".")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s: got %d", p, rr.Code)
		}
	}
}

func TestEmbedExcludesHiddenFiles(t *testing.T) {
	err := fs.WalkDir(embedded, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != "." && hiddenPath(p) {
			t.Errorf("hidden file embedded: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMultiRangeIgnored(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", "bytes=0-0,2-2,4-4")
	if rr := do(t, req); rr.Code != http.StatusOK {
		t.Fatalf("multi-range: got %d, want full 200", rr.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Range", "bytes=0-9")
	if rr := do(t, req); rr.Code != http.StatusPartialContent || rr.Body.Len() != 10 {
		t.Fatalf("single range: got %d len %d", rr.Code, rr.Body.Len())
	}
}

func TestOptionsStarRejected(t *testing.T) {
	srv := httptest.NewUnstartedServer(handler(t))
	srv.Config = newServer("", handler(t))
	srv.Start()
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestProbeURL(t *testing.T) {
	if got, _ := probeURL(":8443", true); got != "https://127.0.0.1:8443/" {
		t.Errorf("https: got %q", got)
	}
	cases := map[string]string{
		":8080":        "http://127.0.0.1:8080/",
		"0.0.0.0:9000": "http://127.0.0.1:9000/",
		"localhost:1":  "http://127.0.0.1:1/",
		"[::]:8080":    "http://[::1]:8080/",
		"[::1]:8080":   "http://[::1]:8080/",
		"10.0.0.5:80":  "http://10.0.0.5:80/",
	}
	for in, want := range cases {
		got, err := probeURL(in, false)
		if err != nil || got != want {
			t.Errorf("%s: got %q %v, want %q", in, got, err, want)
		}
	}
	if _, err := probeURL("8080", false); err == nil {
		t.Error("expected error for address without colon")
	}
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(handler(t))
	defer ok.Close()
	if code := healthcheck(ok.Listener.Addr().String(), false); code != 0 {
		t.Errorf("healthy server: got %d", code)
	}
	foreign := httptest.NewServer(http.NotFoundHandler())
	defer foreign.Close()
	if code := healthcheck(foreign.Listener.Addr().String(), false); code != 1 {
		t.Errorf("foreign 404 server: got %d, want 1", code)
	}
	addr := foreign.Listener.Addr().String()
	foreign.Close()
	if code := healthcheck(addr, false); code != 1 {
		t.Errorf("nothing listening: got %d, want 1", code)
	}
}

func TestLimitListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := limitListener(ln, 1)
	defer l.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	c1, _ := net.Dial("tcp", ln.Addr().String())
	defer c1.Close()
	first := <-accepted
	c2, _ := net.Dial("tcp", ln.Addr().String())
	defer c2.Close()
	select {
	case <-accepted:
		t.Fatal("second connection accepted while at limit")
	case <-time.After(200 * time.Millisecond):
	}
	first.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("slot not released after close")
	}
}

// writeCert writes a fresh self-signed certificate for cn into dir.
func writeCert(t *testing.T, dir, cn string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func startTLS(t *testing.T) (addr string, certs *certReloader) {
	t.Helper()
	certs, err := newCertReloader(writeCert(t, t.TempDir(), "example.test"))
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer("", handler(t))
	srv.TLSConfig = tlsConfig(certs)
	ln, err := listen("127.0.0.1:0", 4, srv.TLSConfig)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), certs
}

func TestTLS(t *testing.T) {
	addr, _ := startTLS(t)
	c := http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}},
		ForceAttemptHTTP2: true,
	}}
	resp, err := c.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if resp.ProtoMajor != 1 {
		t.Errorf("negotiated %s, want HTTP/1.1 only", resp.Proto)
	}
	if !strings.HasPrefix(resp.Header.Get("Strict-Transport-Security"), "max-age=") {
		t.Error("missing HSTS over TLS")
	}

	_, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11})
	if err == nil {
		t.Error("TLS 1.1 handshake succeeded")
	}

	if code := healthcheck(addr, true); code != 0 {
		t.Errorf("TLS healthcheck: got %d", code)
	}
}

func TestNoHSTSOverPlainHTTP(t *testing.T) {
	if rr := do(t, httptest.NewRequest(http.MethodGet, "/", nil)); rr.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS sent over plain HTTP")
	}
}

func TestCertReload(t *testing.T) {
	dir := t.TempDir()
	certs, err := newCertReloader(writeCert(t, dir, "old.test"))
	if err != nil {
		t.Fatal(err)
	}
	cn := func() string {
		t.Helper()
		c, err := certs.GetCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf.Subject.CommonName
	}
	future := time.Now().Add(time.Hour)

	// A broken renewal keeps serving the old certificate.
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(filepath.Join(dir, "cert.pem"), future, future)
	certs.checked = time.Time{}
	if got := cn(); got != "old.test" {
		t.Fatalf("after bad renewal: got %q", got)
	}

	// Within the check interval nothing is re-read.
	writeCert(t, dir, "new.test")
	_ = os.Chtimes(filepath.Join(dir, "cert.pem"), future.Add(time.Minute), future.Add(time.Minute))
	if got := cn(); got != "old.test" {
		t.Fatalf("reloaded before interval: got %q", got)
	}

	certs.checked = time.Time{}
	if got := cn(); got != "new.test" {
		t.Fatalf("after renewal: got %q", got)
	}
}
