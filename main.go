// noshell: a static web server meant to run alone in a FROM scratch image.
//
// The whole site is embedded in this binary at build time, so the running
// container contains exactly one file: this executable. There is no shell,
// no libc, no package manager, no coreutils, and no writable filesystem.
//
// It deliberately does very little:
//   - only GET and HEAD
//   - never reads or decodes a request body (Go's net/http has no Brotli,
//     and this server additionally rejects bodies and Content-Encoding)
//   - no compression, no CGI, no proxying, no directory listings
//   - never serves dotfiles or _underscore files
//   - single-range requests only, connection cap, strict timeouts
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Plain "site" (not "all:site") so files starting with "." or "_" are never
// compiled in, e.g. a stray .env, .DS_Store or _drafts/.
//
//go:embed site
var embedded embed.FS

func main() {
	addr := flag.String("addr", envOr("ADDR", ":8080"), "listen address (env ADDR)")
	maxConns := flag.Int("max-conns", envInt("MAX_CONNS", 1024), "maximum concurrent connections (env MAX_CONNS)")
	quiet := flag.Bool("quiet", os.Getenv("QUIET") != "", "disable access log (env QUIET)")
	health := flag.Bool("healthcheck", false, "probe the local server and exit 0/1 (for Docker HEALTHCHECK, since there is no curl or shell)")
	flag.Parse()

	if *health {
		os.Exit(healthcheck(*addr))
	}

	site, err := fs.Sub(embedded, "site")
	if err != nil {
		log.Fatal(err)
	}

	var h http.Handler = secure(staticHandler(site))
	if !*quiet {
		h = accessLog(h)
	}
	srv := newServer(*addr, h)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	ln = limitListener(ln, *maxConns)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Printf("serving embedded site on %s (max %d connections)", ln.Addr(), *maxConns)

	select {
	case err := <-errc:
		log.Fatal(err)
	case <-ctx.Done():
	}
	log.Print("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Print(err)
	}
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Go allows 4 KiB on top of this, so the effective limit is ~16 KiB.
		MaxHeaderBytes: 12 << 10,
		// Send "OPTIONS *" to our handler (-> 405) instead of Go's built-in 200.
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     log.New(io.Discard, "", 0), // drop noisy TLS/scan errors
	}
}

// hiddenPath reports whether any path segment starts with "." or "_".
func hiddenPath(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if strings.HasPrefix(seg, ".") || strings.HasPrefix(seg, "_") {
			return true
		}
	}
	return false
}

// staticHandler serves files from fsys without directory listings.
func staticHandler(fsys fs.FS) http.Handler {
	files := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean("/" + r.URL.Path)
		name := strings.TrimPrefix(p, "/")
		if hiddenPath(name) {
			notFound(w, fsys)
			return
		}
		if name == "" || strings.HasSuffix(r.URL.Path, "/") {
			name = path.Join(name, "index.html")
		}
		st, err := fs.Stat(fsys, name)
		if err == nil && st.IsDir() {
			_, err = fs.Stat(fsys, path.Join(name, "index.html"))
		}
		if err != nil {
			notFound(w, fsys)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func notFound(w http.ResponseWriter, fsys fs.FS) {
	body, err := fs.ReadFile(fsys, "404.html")
	if err != nil {
		http.Error(w, "404 not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(body)
}

// secure restricts methods, refuses request bodies, limits Range and sets
// hardening headers.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// A static site never needs a request body or an encoded one.
		if r.ContentLength != 0 || len(r.TransferEncoding) > 0 || len(r.Header.Values("Content-Encoding")) > 0 {
			http.Error(w, "request body not accepted", http.StatusBadRequest)
			return
		}
		// Multi-range (multipart/byteranges) responses amplify traffic; allow
		// a single range only and otherwise serve the whole file.
		if rv := r.Header.Values("Range"); len(rv) > 1 || (len(rv) == 1 && strings.Contains(rv[0], ",")) {
			r.Header.Del("Range")
		}
		next.ServeHTTP(w, r)
	})
}

// --- access log ---

type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		// %q escapes control characters, so request data can't forge log lines.
		log.Printf("%s %q %q %d %d %s", r.RemoteAddr, r.Method, r.URL.RequestURI(), rec.status, rec.bytes, time.Since(start).Round(time.Millisecond))
	})
}

// --- connection limit ---

type limitedListener struct {
	net.Listener
	sem chan struct{}
}

func limitListener(l net.Listener, n int) net.Listener {
	if n <= 0 {
		return l
	}
	return &limitedListener{Listener: l, sem: make(chan struct{}, n)}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitedConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// --- healthcheck ---

// probeURL turns a listen address into a URL the healthcheck can reach from
// inside the container. Unspecified hosts and "localhost" map to loopback,
// because a scratch image has no /etc/hosts.
func probeURL(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	switch host {
	case "", "0.0.0.0", "localhost":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/", nil
}

func healthcheck(addr string) int {
	u, err := probeURL(addr)
	if err != nil {
		return 1
	}
	c := http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{Proxy: nil}, // never route the probe through HTTP(S)_PROXY
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := c.Get(u)
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// --- env helpers ---

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}
