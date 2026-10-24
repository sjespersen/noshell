package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
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
	cases := map[string]string{
		":8080":        "http://127.0.0.1:8080/",
		"0.0.0.0:9000": "http://127.0.0.1:9000/",
		"localhost:1":  "http://127.0.0.1:1/",
		"[::]:8080":    "http://[::1]:8080/",
		"[::1]:8080":   "http://[::1]:8080/",
		"10.0.0.5:80":  "http://10.0.0.5:80/",
	}
	for in, want := range cases {
		got, err := probeURL(in)
		if err != nil || got != want {
			t.Errorf("%s: got %q %v, want %q", in, got, err, want)
		}
	}
	if _, err := probeURL("8080"); err == nil {
		t.Error("expected error for address without colon")
	}
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(handler(t))
	defer ok.Close()
	if code := healthcheck(ok.Listener.Addr().String()); code != 0 {
		t.Errorf("healthy server: got %d", code)
	}
	foreign := httptest.NewServer(http.NotFoundHandler())
	defer foreign.Close()
	if code := healthcheck(foreign.Listener.Addr().String()); code != 1 {
		t.Errorf("foreign 404 server: got %d, want 1", code)
	}
	addr := foreign.Listener.Addr().String()
	foreign.Close()
	if code := healthcheck(addr); code != 1 {
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
