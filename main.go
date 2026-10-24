// noshell: a static web server meant to run alone in a FROM scratch image.
//
// The whole site is embedded in this binary at build time, so the running
// container contains exactly one file: this executable. There is no shell,
// no libc, no package manager, no coreutils, and no writable filesystem.
//
// It deliberately does very little:
//   - only GET and HEAD
//   - never reads or decodes a request body (so no Brotli/gzip decoder is
//     ever reachable from the network; Go's net/http has no Brotli at all)
//   - no compression, no CGI, no proxying, no directory listings
//   - strict timeouts and header size limits
package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

//go:embed all:site
var embedded embed.FS

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	health := flag.Bool("healthcheck", false, "probe the local server and exit 0/1 (for Docker HEALTHCHECK, since there is no curl or shell)")
	flag.Parse()

	if *health {
		os.Exit(healthcheck(*addr))
	}

	site, err := fs.Sub(embedded, "site")
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           secure(staticHandler(site)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10, // 16 KiB
	}
	log.Printf("serving embedded site on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}

// staticHandler serves files from the embedded FS without directory listings.
func staticHandler(site fs.FS) http.Handler {
	files := http.FileServer(http.FS(site))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean("/" + r.URL.Path)
		name := strings.TrimPrefix(p, "/")
		if name == "" || strings.HasSuffix(p, "/") {
			name = path.Join(name, "index.html")
		}
		st, err := fs.Stat(site, name)
		if err == nil && st.IsDir() {
			_, err = fs.Stat(site, path.Join(name, "index.html"))
		}
		if err != nil {
			notFound(w, site)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func notFound(w http.ResponseWriter, site fs.FS) {
	body, err := fs.ReadFile(site, "404.html")
	if err != nil {
		http.Error(w, "404 not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(body)
}

// secure restricts methods, refuses request bodies and sets hardening headers.
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
		if r.ContentLength > 0 || len(r.TransferEncoding) > 0 || r.Header.Get("Content-Encoding") != "" {
			http.Error(w, "request body not accepted", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func healthcheck(addr string) int {
	host := addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Head("http://" + host + "/")
	if err != nil || resp.StatusCode >= 500 {
		return 1
	}
	return 0
}
