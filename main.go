package main

import (
	"container/list"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"context"
)

/*
Mini CDN Edge (plantilla)
- Reverse proxy to origin
- In-memory TTL LRU cache
- Honors basic Cache-Control
- Vary-aware cache key (Accept-Encoding)
- PURGE endpoint (token protected)
- Basic IP rate limiting
	"net"
	"sync"

*/

type Config struct {
	ListenAddr        string
	Origin            *url.URL
	CacheMaxBytes     int64
	CacheMaxEntries   int
	DefaultTTL        time.Duration
	PurgeToken        string
	PurgePath         string
	ClientTimeout     time.Duration
	OriginTimeout     time.Duration
	RateLimitRPS      float64
	RateLimitBurst    int
	TrustedProxyCIDRs []string // opcional: si estás detrás de LB, para usar X-Forwarded-For
}
func main() {
	origin, _ := url.Parse("http://127.0.0.1:8080")

	cfg := Config{
		ListenAddr:      ":3000",
		Origin:          origin,
		CacheMaxBytes:   128 * 1024 * 1024, // 128MB
		CacheMaxEntries: 50000,
		DefaultTTL:      2 * time.Minute,
		PurgeToken:      "CAMBIAME-por-un-token-largo",
		PurgePath:       "/__purge",
		ClientTimeout:   15 * time.Second,
		OriginTimeout:   10 * time.Second,
		RateLimitRPS:    10,
		RateLimitBurst:  20,
	}

	cache := NewLRUCache(cfg.CacheMaxEntries, cfg.CacheMaxBytes)
	limiter := NewIPLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst, 10*time.Minute)

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          200,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.OriginTimeout,
	}

	proxy := httputil.NewSingleHostReverseProxy(cfg.Origin)
	proxy.Transport = transport
	// Ajustes del proxy: Host, headers, etc.
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		origDirector(r)
		// Preservar Host original (útil si tu origin hace virtual-hosting)
		// Si preferís host del origin, comentá la línea:
		r.Host = r.Header.Get("Host")
		// Limpieza básica para evitar comportamientos raros
		r.RequestURI = ""
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[ERR] proxy error path=%s err=%v", r.URL.Path, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	mux := http.NewServeMux()

	// Endpoint de purga (token en header)
	mux.HandleFunc(cfg.PurgePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-Purge-Token") != cfg.PurgeToken {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		path := r.URL.Query().Get("path")
		prefix := r.URL.Query().Get("prefix")

		switch {
		case path != "":
			n := cache.PurgeExact(path)
			fmt.Fprintf(w, "purged_exact=%d\n", n)
		case prefix != "":
			n := cache.PurgePrefix(prefix)
			fmt.Fprintf(w, "purged_prefix=%d\n", n)
		default:
			n := cache.PurgeAll()
			fmt.Fprintf(w, "purged_all=%d\n", n)
		}
	})

	// Handler principal CDN
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Rate limit por IP (básico)
		ip := clientIP(r)
		if !limiter.Allow(ip) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// Solo cachear GET/HEAD
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			proxy.ServeHTTP(w, r)
			logLine(r, ip, "BYPASS", time.Since(start), 0)
			return
		}

		// Construir cache key (path+query + Vary: Accept-Encoding)
		key := cacheKey(r)

		// 1) intentar cache
		if ent, ok := cache.Get(key); ok {
			// Escribir desde cache
			writeCached(w, r, ent)
			logLine(r, ip, "HIT", time.Since(start), ent.Size)
			return
		}

		// 2) Cache miss: fetch al origin capturando respuesta
		rec := NewResponseRecorder()
		rr := &requestWithTimeout{r: r, timeout: cfg.ClientTimeout}

		// Servir usando proxy pero escribiendo a recorder
		proxy.ServeHTTP(rec, rr.Request())

		// Copiar respuesta al cliente
		for k, vv := range rec.HeaderMap {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		// Marcar cache
		w.Header().Set("X-Cache", "MISS")

		       w.WriteHeader(rec.StatusCode)
		       if r.Method != http.MethodHead {
			       _, _ = w.Write(rec.buf)
		       }

		// Decidir si cachear
		       ttl, cacheable := cacheDecision(rec.StatusCode, rec.HeaderMap, cfg.DefaultTTL)
		       if cacheable && rec.Body.Len() > 0 {
			       ent := &CacheEntry{
				       Status:  rec.StatusCode,
				       Header: cloneHeader(rec.HeaderMap),
				       Body:    rec.buf,
				       Expires: time.Now().Add(ttl),
			       }
			       cache.Set(key, ent)
		       }

		logLine(r, ip, "MISS", time.Since(start), int64(rec.Body.Len()))
	})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           withBasicSecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("CDN edge listening on %s → origin %s", cfg.ListenAddr, cfg.Origin)
	log.Fatal(srv.ListenAndServe())
}

/* --------------------------
   Cache decision helpers
---------------------------*/

func cacheDecision(status int, hdr http.Header, defaultTTL time.Duration) (time.Duration, bool) {
	// Solo algunos status típicamente cacheables
	cacheableStatus := status == 200 || status == 203 || status == 204 || status == 206 ||
		status == 301 || status == 404

	if !cacheableStatus {
		return 0, false
	}

	cc := parseCacheControl(hdr.Get("Cache-Control"))

	// Reglas base
	if _, ok := cc["no-store"]; ok {
		return 0, false
	}
	if _, ok := cc["private"]; ok {
		return 0, false
	}
	if _, ok := cc["no-cache"]; ok {
		// “no-cache” significa: puede almacenarse pero debe revalidar.
		// Para CDN simple: no cachear para no mentirte.
		return 0, false
	}

	if v, ok := cc["s-maxage"]; ok {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second, secs > 0
		}
	}
	if v, ok := cc["max-age"]; ok {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second, secs > 0
		}
	}

	// Fallback: TTL por defecto
	if defaultTTL <= 0 {
		return 0, false
	}
	return defaultTTL, true
}

func parseCacheControl(s string) map[string]string {
	out := map[string]string{}
	if s == "" {
		return out
	}
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			continue
		}
		if strings.Contains(p, "=") {
			kv := strings.SplitN(p, "=", 2)
			out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		} else {
			out[p] = ""
		}
	}
	return out
}

func cloneHeader(h http.Header) http.Header {
	cp := make(http.Header, len(h))
	for k, vv := range h {
		v2 := make([]string, len(vv))
		copy(v2, vv)
		cp[k] = v2
	}
	return cp
}

func writeCached(w http.ResponseWriter, r *http.Request, ent *CacheEntry) {
	for k, vv := range ent.Header {
		// Evitar headers hop-by-hop
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-Cache", "HIT")
	w.WriteHeader(ent.Status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(ent.Body)
	}
}

func isHopByHopHeader(k string) bool {
	k = strings.ToLower(k)
	switch k {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

/* --------------------------
   Cache key
---------------------------*/

func cacheKey(r *http.Request) string {
	// Importante: incluir host si sirve múltiples dominios
	host := r.Host
	pathQuery := r.URL.Path
	if r.URL.RawQuery != "" {
		pathQuery += "?" + r.URL.RawQuery
	}
	ae := r.Header.Get("Accept-Encoding")
	// Normalizar para no explotar el cache
	ae = normalizeAcceptEncoding(ae)

	raw := r.Method + "|" + host + "|" + pathQuery + "|ae=" + ae
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func normalizeAcceptEncoding(ae string) string {
	ae = strings.ToLower(ae)
	// solo diferenciamos gzip/br para simplificar
	hasBr := strings.Contains(ae, "br")
	hasGz := strings.Contains(ae, "gzip")
	switch {
	case hasBr:
		return "br"
	case hasGz:
		return "gzip"
	default:
		return "identity"
	}
}

/* --------------------------
   Response recorder
---------------------------*/

type ResponseRecorder struct {
	StatusCode int
	HeaderMap  http.Header
	Body       *strings.Builder
	buf        []byte
}

func NewResponseRecorder() *ResponseRecorder {
	return &ResponseRecorder{
		StatusCode: 200,
		HeaderMap:  make(http.Header),
		Body:       &strings.Builder{},
	}
}

func (r *ResponseRecorder) Header() http.Header { return r.HeaderMap }
func (r *ResponseRecorder) WriteHeader(code int) { r.StatusCode = code }
func (r *ResponseRecorder) Write(b []byte) (int, error) {
	// Guardar copia
	r.buf = append(r.buf, b...)
	r.Body.WriteString(string(b))
	return len(b), nil
}
func (r *ResponseRecorder) Bytes() []byte { return r.buf }

/* --------------------------
   LRU TTL Cache
---------------------------*/

type CacheEntry struct {
	Status  int
	Header  http.Header
	Body    []byte
	Expires time.Time
	Size    int64
}

type LRUCache struct {
	mu        sync.Mutex
	maxEnt    int
	maxBytes  int64
	usedBytes int64
	ll        *list.List
	items     map[string]*list.Element
}

type lruItem struct {
	key string
	val *CacheEntry
}

func NewLRUCache(maxEntries int, maxBytes int64) *LRUCache {
	return &LRUCache{
		maxEnt:   maxEntries,
		maxBytes: maxBytes,
		ll:      list.New(),
		items:   make(map[string]*list.Element),
	}
}

func (c *LRUCache) Get(key string) (*CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		it := el.Value.(*lruItem)
		// TTL check
		if time.Now().After(it.val.Expires) {
			c.removeElement(el)
			return nil, false
		}
		c.ll.MoveToFront(el)
		return it.val, true
	}
	return nil, false
}

func (c *LRUCache) Set(key string, ent *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ent.Size = int64(len(ent.Body))

	if el, ok := c.items[key]; ok {
		// replace
		c.removeElement(el)
	}
	el := c.ll.PushFront(&lruItem{key: key, val: ent})
	c.items[key] = el
	c.usedBytes += ent.Size

	// Evictions
	for (c.maxEnt > 0 && c.ll.Len() > c.maxEnt) || (c.maxBytes > 0 && c.usedBytes > c.maxBytes) {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.removeElement(back)
	}
}

func (c *LRUCache) removeElement(el *list.Element) {
	it := el.Value.(*lruItem)
	delete(c.items, it.key)
	c.ll.Remove(el)
	c.usedBytes -= it.val.Size
}

func (c *LRUCache) PurgeExact(path string) int {
	// Nota: como la key es hash, purgar por path exacto requiere estrategia.
	// Plantilla simple: purga total o por prefix. Para exacto real, guarda un índice path->keys.
	// Igual dejamos esto para que lo completes con índice.
	return c.PurgeAll()
}

func (c *LRUCache) PurgePrefix(prefix string) int {
	// Igual que arriba: requeriría índice.
	return c.PurgeAll()
}

func (c *LRUCache) PurgeAll() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.ll.Len()
	c.ll.Init()
	c.items = make(map[string]*list.Element)
	c.usedBytes = 0
	return n
}

/* --------------------------
   IP Rate limiting (token bucket simple)
---------------------------*/

type tokenBucket struct {
	tokens float64
	last   time.Time
}

type IPLimiter struct {
	mu       sync.Mutex
	rps      float64
	burst    float64
	ttl      time.Duration
	buckets  map[string]*tokenBucket
	lastSweep time.Time
}

func NewIPLimiter(rps float64, burst int, ttl time.Duration) *IPLimiter {
	return &IPLimiter{
		rps:      rps,
		burst:    float64(burst),
		ttl:      ttl,
		buckets:  make(map[string]*tokenBucket),
		lastSweep: time.Now(),
	}
}

func (l *IPLimiter) Allow(ip string) bool {
	if l.rps <= 0 {
		return true
	}
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	// sweep ocasional
	if now.Sub(l.lastSweep) > l.ttl {
		for k, b := range l.buckets {
			if now.Sub(b.last) > l.ttl {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}

	b, ok := l.buckets[ip]
	if !ok {
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}

	// refill
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rps
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}

/* --------------------------
   Misc helpers
---------------------------*/

func clientIP(r *http.Request) string {
	// Simple: RemoteAddr. Si estás detrás de proxy/LB, manejá X-Forwarded-For con allowlist.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func logLine(r *http.Request, ip, cache string, dur time.Duration, size int64) {
	log.Printf("[REQ] ip=%s method=%s path=%s status=? cache=%s dur=%s bytes=%d",
		ip, r.Method, r.URL.RequestURI(), cache, dur.Round(time.Millisecond), size)
}

func withBasicSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Esto es “higiene” útil para edges simples
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

type requestWithTimeout struct {
	r       *http.Request
	timeout time.Duration
}

func (rw *requestWithTimeout) Request() *http.Request {
       if rw.timeout <= 0 {
	       return rw.r
       }
       ctx := rw.r.Context()
       ctx, _ = context.WithTimeout(ctx, rw.timeout)
       return rw.r.WithContext(ctx)
}

// Pequeña alternativa para no importar context explícitamente arriba (mantener plantilla compacta)
type cancelFunc func()

func withTimeout(parent interface{ Done() <-chan struct{} }, d time.Duration) (interface{ Done() <-chan struct{} }, cancelFunc) {
	// Esto es una simplificación. En producción: usá context.WithTimeout.
	// La dejamos así para plantilla: si querés, te la convierto a context proper.
	return parent, func() {}
}

/* --------------------------
   Notes / TODOs para mejorar (tu roadmap)
---------------------------*/

// TODO 1: Usar context.WithTimeout real (import "context").
// TODO 2: Implementar índice path->keys para PurgeExact / PurgePrefix.
// TODO 3: Soportar revalidación con ETag/If-None-Match (cache con stale-while-revalidate).
// TODO 4: Compresión (gzip/br) o respetar la del origin.
// TODO 5: Métricas Prometheus: hit_ratio, latency p95, 5xx, bytes.
// TODO 6: Persistir cache (opcional) o usar Redis para cache compartido entre nodos.
