// Package sim simulates the two ends of a CAP exchange for tests: a
// feed server (Atom or RSS whose entries embed or link to CAP documents,
// or an EDXL-DE envelope; ETag, Last-Modified and conditional GETs; signed
// alerts on request) and a receiver that accepts CAP messages by HTTP
// POST, optionally checking signatures and profiles.
package sim

import (
	"errors"
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
	AtomEmbedded  Format = iota // Atom entries carrying the alert in their content
	AtomLinked                  // Atom entries linking to the CAP document
	RSSLinked                   // RSS 2.0 items linking to the CAP document (SACHET's form)
	EDXLEmbedded                // an EDXL-DE 1.0 envelope with one content object per alert
	EDXL2Embedded               // an EDXL-DE 2.0 envelope with one content object per alert
	BareAlert                   // the newest alert itself, no feed around it
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
	signer      *cap.Signer
	// PageSize, when over 0, pages an Atom feed (RFC 5005): /feed holds the
	// newest PageSize entries and links rel="next" to /feed?page=2.
	PageSize int
}

// SetSigner makes the feed sign the alerts added after it with s (nil
// stops signing).
func (s *Feed) SetSigner(sg *cap.Signer) {
	s.mu.Lock()
	s.signer = sg
	s.mu.Unlock()
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

// Add publishes an alert, signed when a signer is set. It panics when the
// alert cannot be encoded or signed.
func (s *Feed) Add(a *cap.Alert) {
	b, err := a.Marshal()
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	sg := s.signer
	s.mu.Unlock()
	if sg != nil {
		if b, err = sg.Sign(b); err != nil {
			panic(err)
		}
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
		name := strings.TrimPrefix(r.URL.Path, "/docs/")
		asJSON := strings.HasSuffix(name, ".json")
		n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSuffix(name, ".xml"), ".json"))
		if err != nil || n < 0 || n >= len(s.docs) {
			http.NotFound(w, r)
			return
		}
		if asJSON {
			// The alert in JSON with CAP element names (cap.MarshalJSONCAP).
			a, err := cap.Parse(s.docs[n])
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
			b, err := a.MarshalJSONCAP()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
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
	inm, ims := r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since")
	notModified := inm == etag
	if inm == "" && ims != "" {
		if t, err := http.ParseTime(ims); err == nil && !s.modified.After(t) {
			notModified = true
		}
	}
	if notModified {
		s.NotModified++
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", s.modified.Format(http.TimeFormat))
	var b strings.Builder
	switch s.format {
	case BareAlert:
		if len(s.docs) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", cap.MediaType)
		b.Write(s.docs[len(s.docs)-1])
	case EDXL2Embedded:
		cs := make([]cap.EDXLContent, 0, len(s.docs))
		for i := len(s.docs) - 1; i >= 0; i-- {
			cs = append(cs, cap.EDXLContent{Doc: s.docs[i], Description: fmt.Sprintf("alert %d", i)})
		}
		if len(cs) == 0 {
			http.NotFound(w, r)
			return
		}
		out, err := cap.WriteEDXLDE2(cap.Distribution{ID: fmt.Sprintf("sim-%d", s.version), SenderID: "capsim@example.test",
			Sent: cap.FormatTime(s.modified), Expires: cap.FormatTime(s.modified.Add(24 * time.Hour)),
			Status: "Exercise", Type: "Report"}, cs...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		b.Write(out)
	case RSSLinked:
		w.Header().Set("Content-Type", "application/rss+xml")
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Simulated CAP feed</title>`)
		for i := len(s.docs) - 1; i >= 0; i-- {
			fmt.Fprintf(&b, `<item><title>alert %d</title><link>/docs/%d.xml</link><guid>%s</guid><pubDate>%s</pubDate></item>`,
				i, i, s.ids[i], s.modified.Format(time.RFC1123Z))
		}
		b.WriteString(`</channel></rss>`)
	case EDXLEmbedded:
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?><EDXLDistribution xmlns="%s"><distributionID>sim-%d</distributionID>`+
			`<senderID>capsim@example.test</senderID><dateTimeSent>%s</dateTimeSent><distributionStatus>Exercise</distributionStatus>`+
			`<distributionType>Report</distributionType><combinedConfidentiality>UNCLASSIFIED AND NOT SENSITIVE</combinedConfidentiality>`,
			cap.EDXLDE10Namespace, s.version, cap.FormatTime(s.modified))
		for i := len(s.docs) - 1; i >= 0; i-- {
			fmt.Fprintf(&b, `<contentObject><contentDescription>alert %d</contentDescription><xmlContent><embeddedXMLContent>%s</embeddedXMLContent></xmlContent></contentObject>`,
				i, withoutDecl(s.docs[i]))
		}
		b.WriteString(`</EDXLDistribution>`)
	default:
		w.Header().Set("Content-Type", "application/atom+xml")
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom"><id>urn:sim</id><title>Simulated CAP feed</title>`)
		from, to := len(s.docs)-1, 0 // newest first
		if s.PageSize > 0 {
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page < 1 {
				page = 1
			}
			from = len(s.docs) - 1 - (page-1)*s.PageSize
			to = max(from-s.PageSize+1, 0)
			if to > 0 {
				fmt.Fprintf(&b, `<link rel="next" href="%s/feed?page=%d"/>`, scheme(r)+"://"+r.Host, page+1)
			}
		}
		for i := from; i >= to; i-- {
			fmt.Fprintf(&b, `<entry><id>urn:sim:%d</id><title>alert %d</title><updated>%s</updated>`, i, i, s.modified.Format(time.RFC3339))
			if s.format == AtomEmbedded {
				fmt.Fprintf(&b, `<content type="application/cap+xml">%s</content>`, withoutDecl(s.docs[i]))
			} else {
				fmt.Fprintf(&b, `<link rel="alternate" type="application/cap+xml" href="%s/docs/%d.xml"/>`, scheme(r)+"://"+r.Host, i)
			}
			b.WriteString(`</entry>`)
		}
		b.WriteString(`</feed>`)
	}
	_, _ = io.WriteString(w, b.String())
}

// withoutDecl drops a document's XML declaration, to embed it.
func withoutDecl(b []byte) string {
	doc := string(b)
	if j := strings.Index(doc, "?>"); j >= 0 && strings.HasPrefix(doc, "<?xml") {
		doc = doc[j+2:]
	}
	return doc
}

// Receiver accepts CAP messages by POST.
type Receiver struct {
	srv *httptest.Server
	// Token, when set, is the bearer token required.
	Token string

	mu       sync.Mutex
	msgs     []*cap.Alert
	raws     [][]byte
	fails    int
	down     bool
	verifier *cap.Verifier
	profiles []cap.Profile
	refused  []string
}

// SetVerifier makes the receiver check signatures with v: a message whose
// signature does not verify (or an unsigned one, when v requires
// signatures) is refused with 403, and the alert kept is the verified
// one. nil stops checking.
func (rc *Receiver) SetVerifier(v *cap.Verifier) {
	rc.mu.Lock()
	rc.verifier = v
	rc.mu.Unlock()
}

// SetProfiles makes the receiver also validate against the profiles; an
// alert with profile errors (not warnings) is refused with 422.
func (rc *Receiver) SetProfiles(ps ...cap.Profile) {
	rc.mu.Lock()
	rc.profiles = ps
	rc.mu.Unlock()
}

// Refused returns why each refused post was refused, in order.
func (rc *Receiver) Refused() []string {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]string(nil), rc.refused...)
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
	refuse := func(msg string, code int) {
		rc.refused = append(rc.refused, msg)
		http.Error(w, msg, code)
	}
	doc := b
	if rc.verifier != nil {
		verified, _, err := rc.verifier.Verify(b)
		if err != nil {
			code := http.StatusForbidden
			if !errors.Is(err, cap.ErrUnsigned) && strings.Contains(err.Error(), "not well-formed") {
				code = http.StatusBadRequest
			}
			refuse(err.Error(), code)
			return
		}
		doc = verified
	}
	a, err := cap.Parse(doc)
	if err != nil {
		refuse(err.Error(), http.StatusBadRequest)
		return
	}
	if err := a.Validate(cap.Options{Profiles: rc.profiles}); err != nil {
		refuse(err.Error(), http.StatusUnprocessableEntity)
		return
	}
	rc.msgs = append(rc.msgs, a)
	rc.raws = append(rc.raws, b)
	w.WriteHeader(http.StatusNoContent)
}
