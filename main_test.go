package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
