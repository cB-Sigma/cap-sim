// Package sim simulates the two ends of a CAP exchange for tests: a
// feed server (Atom or RSS, with ETag and Last-Modified, whose entries
// embed or link to CAP documents) and a receiver that accepts CAP messages
// by HTTP POST.
package sim

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/cap"
)

// Format of a simulated feed.
type Format int

const (
	AtomEmbedded Format = iota // Atom entries carrying the alert in their content
	AtomLinked                 // Atom entries linking to the CAP document
	RSSLinked                  // RSS 2.0 items linking to the CAP document (SACHET's form)
)

// Feed is a CAP feed server.
type Feed struct {
	srv    *httptest.Server
	format Format

	mu          sync.Mutex
	docs        [][]byte // CAP documents, oldest first
	ids         []string
	version     int
	modified    time.Time
	Requests    int // feed GETs
	NotModified int // feed GETs answered 304
	DocGETs     int
	Down        bool // answer 503
}

// NewFeed starts a feed server on a loopback port.
func NewFeed(f Format) *Feed {
	s := &Feed{format: f, modified: time.Now().UTC().Truncate(time.Second)}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// NewFeedAt starts a feed server listening on addr ("127.0.0.1:8080").
func NewFeedAt(f Format, addr string) (*Feed, error) {
	s := &Feed{format: f, modified: time.Now().UTC().Truncate(time.Second)}
	srv, err := serveAt(addr, http.HandlerFunc(s.serve))
	if err != nil {
		return nil, err
	}
	s.srv = srv
	return s, nil
}

// serveAt starts h on addr.
func serveAt(addr string, h http.Handler) (*httptest.Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := httptest.NewUnstartedServer(h)
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	return srv, nil
}

// URL is the feed's address.
func (s *Feed) URL() string { return s.srv.URL + "/feed" }

// Close stops the server.
func (s *Feed) Close() { s.srv.Close() }

// Add publishes an alert.
func (s *Feed) Add(a *cap.Alert) {
	b, err := a.Marshal()
	if err != nil {
		panic(err)
	}
	s.AddRaw(a.Identifier, b)
}

// AddRaw publishes a document as is (for malformed or invalid ones).
func (s *Feed) AddRaw(id string, doc []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs = append(s.docs, doc)
	s.ids = append(s.ids, id)
	s.version++
	s.modified = s.modified.Add(time.Second)
}

// Stats returns the request counters.
func (s *Feed) Stats() (requests, notModified, docs int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Requests, s.NotModified, s.DocGETs
}

// SetDown makes the server answer 503.
func (s *Feed) SetDown(down bool) {
	s.mu.Lock()
	s.Down = down
	s.mu.Unlock()
}

func (s *Feed) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/docs/") {
		s.DocGETs++
		n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/docs/"), ".xml"))
		if err != nil || n < 0 || n >= len(s.docs) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", cap.MediaType)
		_, _ = w.Write(s.docs[n])
		return
	}
	if r.URL.Path != "/feed" {
		http.NotFound(w, r)
		return
	}
	s.Requests++
	etag := fmt.Sprintf(`"v%d"`, s.version)
	if r.Header.Get("If-None-Match") == etag {
		s.NotModified++
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", s.modified.Format(http.TimeFormat))
	var b strings.Builder
	switch s.format {
	case RSSLinked:
		w.Header().Set("Content-Type", "application/rss+xml")
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Simulated CAP feed</title>`)
		for i := len(s.docs) - 1; i >= 0; i-- {
			fmt.Fprintf(&b, `<item><title>alert %d</title><link>/docs/%d.xml</link><guid>%s</guid><pubDate>%s</pubDate></item>`,
				i, i, s.ids[i], s.modified.Format(time.RFC1123Z))
		}
		b.WriteString(`</channel></rss>`)
	default:
		w.Header().Set("Content-Type", "application/atom+xml")
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom"><id>urn:sim</id><title>Simulated CAP feed</title>`)
		for i := len(s.docs) - 1; i >= 0; i-- {
			fmt.Fprintf(&b, `<entry><id>urn:sim:%d</id><title>alert %d</title><updated>%s</updated>`, i, i, s.modified.Format(time.RFC3339))
			if s.format == AtomEmbedded {
				doc := string(s.docs[i])
				if j := strings.Index(doc, "?>"); j >= 0 && strings.HasPrefix(doc, "<?xml") {
					doc = doc[j+2:]
				}
				fmt.Fprintf(&b, `<content type="application/cap+xml">%s</content>`, doc)
			} else {
				fmt.Fprintf(&b, `<link rel="alternate" type="application/cap+xml" href="%s/docs/%d.xml"/>`, "http://"+r.Host, i)
			}
			b.WriteString(`</entry>`)
		}
		b.WriteString(`</feed>`)
	}
	_, _ = io.WriteString(w, b.String())
}

// Receiver accepts CAP messages by POST.
type Receiver struct {
	srv *httptest.Server
	// Token, when set, is the bearer token required.
	Token string

	mu    sync.Mutex
	msgs  []*cap.Alert
	raws  [][]byte
	fails int
	down  bool
}

// Raw returns the bodies of the valid messages received, in order.
func (rc *Receiver) Raw() [][]byte {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([][]byte(nil), rc.raws...)
}

// NewReceiver starts a receiver on a loopback port.
func NewReceiver(token string) *Receiver {
	rc := &Receiver{Token: token}
	rc.srv = httptest.NewServer(http.HandlerFunc(rc.serve))
	return rc
}

// NewReceiverAt starts a receiver listening on addr.
func NewReceiverAt(token, addr string) (*Receiver, error) {
	rc := &Receiver{Token: token}
	srv, err := serveAt(addr, http.HandlerFunc(rc.serve))
	if err != nil {
		return nil, err
	}
	rc.srv = srv
	return rc, nil
}

// URL is the receiver's address.
func (rc *Receiver) URL() string { return rc.srv.URL + "/cap" }

// Close stops the receiver.
func (rc *Receiver) Close() { rc.srv.Close() }

// FailNext makes the next n posts fail with 503.
func (rc *Receiver) FailNext(n int) {
	rc.mu.Lock()
	rc.fails = n
	rc.mu.Unlock()
}

// SetDown makes every post fail with 503 until it is called with false.
func (rc *Receiver) SetDown(down bool) {
	rc.mu.Lock()
	rc.down = down
	rc.mu.Unlock()
}

// Messages returns the valid messages received, in order.
func (rc *Receiver) Messages() []*cap.Alert {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]*cap.Alert(nil), rc.msgs...)
}

func (rc *Receiver) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if rc.Token != "" && r.Header.Get("Authorization") != "Bearer "+rc.Token {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), cap.MediaType) {
		http.Error(w, "not CAP", http.StatusUnsupportedMediaType)
		return
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	if rc.fails > 0 {
		rc.fails--
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	b, _ := io.ReadAll(r.Body)
	a, err := cap.Parse(b)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.Validate(cap.Options{}); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	rc.msgs = append(rc.msgs, a)
	rc.raws = append(rc.raws, b)
	w.WriteHeader(http.StatusNoContent)
}
