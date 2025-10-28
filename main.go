package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Config struct {
	ListenAddr      string
	TargetURL       string
	BodyLimitBytes  int64
	RateLimitCount  int           // requests
	RateLimitWindow time.Duration // per window
	LogFile         string
}

var cfg = Config{
	ListenAddr:      ":8443",                 // waf app
	TargetURL:       "http://localhost:8080", // target app
	BodyLimitBytes:  1 << 20,                 // 1MB
	RateLimitCount:  100,                     // 120 req
	RateLimitWindow: time.Minute,             // per 60s
	LogFile:         "waf_attacks.log",
}

type ipEntry struct {
	count       int
	windowStart time.Time
}

var (
	ipMutex sync.Mutex
	ipMap   = map[string]*ipEntry{}
)

// Attack prototypes
var patterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]*>`),                       // XSS tag
	regexp.MustCompile(`(?i)onerror\s*=`),                         // XSS attribute
	regexp.MustCompile(`(?i)javascript:`),                         // XSS uri
	regexp.MustCompile(`(?i)union\s+select`),                      // SQLi
	regexp.MustCompile(`(?i)or\s+1=1`),                            // SQLi
	regexp.MustCompile(`(?i)select.+from`),                        // SQL-like
	regexp.MustCompile(`(?i)\.\.\/`),                              // directory traversal
	regexp.MustCompile(`(?i)/etc/passwd`),                         // LFI attempt
	regexp.MustCompile(`(?i)base64_decode\(`),                     // RCE/php patterns
	regexp.MustCompile(`(?i)preg_replace\(.*/e`),                  // php eval pattern
	regexp.MustCompile(`(?i)wget\s+http`),                         // download attempts
	regexp.MustCompile(`(?i)curl\s+http`),                         // download attempts
	regexp.MustCompile(`(?i)\bexec\b|\bsystem\b|\bpopen\b`),       // command exec
	regexp.MustCompile(`(?i)eval\(`),                              // eval
	regexp.MustCompile(`(?i)<iframe`),                             // iframe injection
}

// blacklist
var ipBlacklist = map[string]bool{
	// "1.2.3.4": true,
}
// whitelist
var ipWhitelist = map[string]bool{
	// "127.0.0.1": true,
}

var attackLogger *log.Logger

func initLogger() {
	f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		log.Fatalf("error on logfile: %v", err)
	}
	attackLogger = log.New(f, "", log.LstdFlags)
}

// fingerprint: UA + Accept-Language + Accept-Encoding + IP, sha1
func fingerprint(r *http.Request, remoteIP string) string {
	h := sha1.New()
	write := func(s string) { h.Write([]byte(s)) }
	write(strings.ToLower(strings.TrimSpace(r.UserAgent())))
	write("|")
	write(strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language"))))
	write("|")
	write(strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Encoding"))))
	write("|")
	write(remoteIP)
	return hex.EncodeToString(h.Sum(nil))
}

// sliding window rate limit per IP
func allowRequest(remoteIP string) bool {
	now := time.Now()
	ipMutex.Lock()
	defer ipMutex.Unlock()
	e, ok := ipMap[remoteIP]
	if !ok || now.Sub(e.windowStart) > cfg.RateLimitWindow {
		ipMap[remoteIP] = &ipEntry{count: 1, windowStart: now}
		return true
	}
	e.count++
	if e.count > cfg.RateLimitCount {
		return false
	}
	return true
}

func logAttack(remoteIP, reason string, r *http.Request, bodySnippet string) {
	line := fmt.Sprintf("%s - %s - %s - %s - %s\n", time.Now().Format(time.RFC3339), remoteIP, reason, r.Method, r.URL.String())
	attackLogger.Printf(line)
	// console
	log.Printf("ATTACK BLOCKED: %s - %s - bodySnippet=%q\n", remoteIP, reason, bodySnippet)
}

// profit: search for real IP (X-Forwarded-For)
func clientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func inspectRequest(r *http.Request, body []byte, remoteIP string) (blocked bool, reason string, snippet string) {
	// 1) IP blacklist
	if ipBlacklist[remoteIP] {
		return true, "ip-blacklist", ""
	}
	// 2) whitelist short-circuit
	if ipWhitelist[remoteIP] {
		return false, "", ""
	}
	// 3) rate limit
	if !allowRequest(remoteIP) {
		return true, "rate-limit", ""
	}
	// 4) fingerprinting (we compute but not block here; could be used for anomaly)
	fp := fingerprint(r, remoteIP)
	_ = fp // for now we might log it later

	// make string pieces to test
	urlStr := r.URL.RawQuery + " " + r.URL.Path
	bodyStr := string(body)
	headerStr := r.UserAgent() + " " + r.Header.Get("Referer") + " " + r.Header.Get("Cookie")

	combined := urlStr + " " + bodyStr + " " + headerStr

	// 5) pattern matching
	for _, p := range patterns {
		if p.MatchString(combined) {
			snippetLen := 200
			if len(bodyStr) < snippetLen {
				snippet = bodyStr
			} else {
				snippet = bodyStr[:snippetLen]
			}
			return true, fmt.Sprintf("pattern-%s", p.String()), snippet
		}
	}

	// not blocked
	return false, "", ""
}

func makeProxy(target string) (*httputil.ReverseProxy, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(u)

	// Optional: tweak transport settings here if needed (timeouts, keepalives)
	return proxy, nil
}

func wafHandler(proxy *httputil.ReverseProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remoteIP := clientIP(r)

		// read body up to limit and restore r.Body for proxy
		var body []byte
		if r.Body != nil {
			limited := io.LimitReader(r.Body, cfg.BodyLimitBytes)
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(limited)
			if err != nil && err != io.EOF {
				log.Printf("error on reading body: %v", err)
			}
			body = buf.Bytes()
			// restore
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		blocked, reason, snippet := inspectRequest(r, body, remoteIP)
		if blocked {
			logAttack(remoteIP, reason, r, snippet)
			http.Error(w, "403 - Forbidden (blocked by WAF)", http.StatusForbidden)
			return
		}

		// Passed checks -> proxy
		proxy.ServeHTTP(w, r)
	}
}

func main() {
	initLogger()
	log.Printf("Starting simple WAF on %s -> %s", cfg.ListenAddr, cfg.TargetURL)
	proxy, err := makeProxy(cfg.TargetURL)
	if err != nil {
		log.Fatalf("proxy error: %v", err)
	}
	http.HandleFunc("/", wafHandler(proxy))

	// Not TLS in this example. For real use, terminate TLS here or use a TLS-enabled reverse proxy in front.
	if err := http.ListenAndServe(cfg.ListenAddr, nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
