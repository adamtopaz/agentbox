package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// cmdDebugEcho is the e2e test upstream: it reports exactly what it received
// (method, path, query, header names+values) so test/e2e.sh can assert on
// stripping and injection, plus an /sse mode for streaming checks.
func cmdDebugEcho(args []string) int {
	fs := flag.NewFlagSet("debug-echo", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:0", "listen address")
	if _, ok := parseArgs(fs, args); !ok {
		return 2
	}
	// Loopback only: this handler echoes every request header it receives.
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return fail(fmt.Errorf("--listen must be host:port: %w", err))
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fail(fmt.Errorf("--listen must be a loopback address, got %q", host))
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("LISTEN %s\n", ln.Addr())
	os.Stdout.Sync()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/sse") {
			w.Header().Set("Content-Type", "text/event-stream")
			fl, _ := w.(http.Flusher)
			for i := range 3 {
				fmt.Fprintf(w, "data: event-%d %d\n\n", i, time.Now().UnixMilli())
				if fl != nil {
					fl.Flush()
				}
				time.Sleep(400 * time.Millisecond)
			}
			return
		}
		headers := map[string]string{}
		for k, v := range r.Header {
			headers[k] = strings.Join(v, ", ")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method":  r.Method,
			"path":    r.URL.Path,
			"query":   r.URL.RawQuery,
			"headers": headers,
		})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.Serve(ln); err != nil {
		return fail(err)
	}
	return 0
}
