// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
	"github.com/cB-Sigma/cap-sim/sim"
)

// demoAlert is made-up content.
func demoAlert(id string) *cap.Alert {
	now := time.Now()
	return &cap.Alert{
		Identifier: id, Sender: "sim@example.test", Sent: cap.FormatTime(now),
		Status: "Exercise", MsgType: "Alert", Scope: "Public",
		Info: []cap.Info{{
			Category: []string{"Met"}, Event: "Heavy Rainfall",
			Urgency: "Expected", Severity: "Moderate", Certainty: "Likely",
			Area: []cap.Area{{AreaDesc: "Demo district", Circle: []string{"18.52,73.85 5"}}},
		}},
	}
}

func get(t *testing.T, url, etag string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestFeedRoundTrip(t *testing.T) {
	for _, f := range []sim.Format{sim.AtomEmbedded, sim.AtomLinked, sim.RSSLinked, sim.EDXLEmbedded} {
		feed := sim.NewFeed(f)
		feed.Add(demoAlert("SIM-1"))
		resp, body := get(t, feed.URL(), "")
		entries, err := cap.ParseFeed(body)
		if err != nil || len(entries) != 1 {
			t.Fatalf("format %d: %v, %d entries", f, err, len(entries))
		}
		a := entries[0].Alert
		if a == nil {
			link := entries[0].Link
			if f == sim.RSSLinked {
				link = feed.URL()[:len(feed.URL())-len("/feed")] + link
			}
			_, doc := get(t, link, "")
			if a, err = cap.Parse(doc); err != nil {
				t.Fatalf("format %d: linked document: %v", f, err)
			}
		}
		if a.Identifier != "SIM-1" || a.Validate(cap.Options{}) != nil {
			t.Errorf("format %d: alert %+v", f, a)
		}
		// An unchanged feed answers 304 to its ETag; a new alert changes it.
		etag := resp.Header.Get("ETag")
		if r, _ := get(t, feed.URL(), etag); r.StatusCode != http.StatusNotModified {
			t.Errorf("format %d: status %d, want 304", f, r.StatusCode)
		}
		lm := resp.Header.Get("Last-Modified")
		if r := getSince(t, feed.URL(), lm); r != http.StatusNotModified {
			t.Errorf("format %d: If-Modified-Since status %d, want 304", f, r)
		}
		feed.Add(demoAlert("SIM-2"))
		if r := getSince(t, feed.URL(), lm); r != http.StatusOK {
			t.Errorf("format %d: If-Modified-Since status %d after a new alert, want 200", f, r)
		}
		if r, _ := get(t, feed.URL(), etag); r.StatusCode != http.StatusOK {
			t.Errorf("format %d: status %d after a new alert, want 200", f, r.StatusCode)
		}
		feed.SetDown(true)
		if r, _ := get(t, feed.URL(), ""); r.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("format %d: status %d while down, want 503", f, r.StatusCode)
		}
		feed.Close()
	}
}

func getSince(t *testing.T, url, since string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("If-Modified-Since", since)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// keyPair makes a self-signed ECDSA certificate (PEM key, PEM certificate).
func keyPair(t *testing.T) (string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "capsim.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A signing feed serves signed alerts that a verifying receiver accepts;
// the receiver refuses unsigned (when required), tampered and
// profile-failing alerts, saying why.
func TestSignedFeedAndCheckingReceiver(t *testing.T) {
	key, cert := keyPair(t)
	sg, err := cap.NewSigner(cap.SignSettings{Key: key, Certificate: cert})
	if err != nil {
		t.Fatal(err)
	}
	feed := sim.NewFeed(sim.EDXLEmbedded)
	defer feed.Close()
	feed.SetSigner(sg)
	feed.Add(demoAlert("SIM-S1"))
	_, body := get(t, feed.URL(), "")
	entries, err := cap.ParseFeed(body)
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries %d, %v", len(entries), err)
	}
	v, _ := cap.NewVerifier(cap.VerifySettings{Trusted: []string{cert}, Require: true})
	if _, state, err := v.Verify(entries[0].Raw); err != nil || state != cap.SignatureValid {
		t.Fatalf("feed signature: %q, %v", state, err)
	}

	rc := sim.NewReceiver("")
	defer rc.Close()
	rc.SetVerifier(v)
	signed := entries[0].Raw
	if s := post(t, rc.URL(), "", signed); s != http.StatusNoContent {
		t.Errorf("signed: status %d (%v)", s, rc.Refused())
	}
	unsigned, _ := demoAlert("SIM-S2").Marshal()
	if s := post(t, rc.URL(), "", unsigned); s != http.StatusForbidden {
		t.Errorf("unsigned: status %d", s)
	}
	tampered := bytes.Replace(signed, []byte("Heavy Rainfall"), []byte("Light Drizzle"), 1)
	if s := post(t, rc.URL(), "", tampered); s != http.StatusForbidden {
		t.Errorf("tampered: status %d", s)
	}
	rc.SetVerifier(nil)
	rc.SetProfiles(cap.IPAWS())
	if s := post(t, rc.URL(), "", unsigned); s != http.StatusUnprocessableEntity {
		t.Errorf("IPAWS profile: status %d", s)
	}
	if r := rc.Refused(); len(r) != 3 || !bytes.Contains([]byte(r[2]), []byte("IPAWSv1.0")) {
		t.Errorf("refused = %q", r)
	}
	if len(rc.Messages()) != 1 {
		t.Errorf("messages = %d", len(rc.Messages()))
	}
}

func post(t *testing.T, url, token string, doc []byte) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(doc))
	req.Header.Set("Content-Type", cap.MediaType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestReceiverRoundTrip(t *testing.T) {
	rc := sim.NewReceiver("demo-token")
	defer rc.Close()
	doc, err := demoAlert("SIM-1").Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if s := post(t, rc.URL(), "wrong", doc); s != http.StatusUnauthorized {
		t.Errorf("wrong token: status %d", s)
	}
	rc.FailNext(1)
	if s := post(t, rc.URL(), "demo-token", doc); s != http.StatusServiceUnavailable {
		t.Errorf("injected failure: status %d", s)
	}
	if s := post(t, rc.URL(), "demo-token", []byte("<alert")); s != http.StatusBadRequest {
		t.Errorf("malformed: status %d", s)
	}
	if s := post(t, rc.URL(), "demo-token", doc); s != http.StatusNoContent {
		t.Errorf("valid alert: status %d", s)
	}
	msgs := rc.Messages()
	if len(msgs) != 1 || msgs[0].Identifier != "SIM-1" || !bytes.Equal(rc.Raw()[0], doc) {
		t.Errorf("messages = %+v", msgs)
	}
}

// A feed serves the alerts added to it; a receiver keeps the valid
// alerts posted to it.
func Example() {
	feed := sim.NewFeed(sim.AtomEmbedded)
	defer feed.Close()
	feed.Add(demoAlert("SIM-1"))
	resp, err := http.Get(feed.URL())
	if err != nil {
		panic(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	entries, _ := cap.ParseFeed(body)
	fmt.Println("feed:", entries[0].Alert.Identifier)

	rc := sim.NewReceiver("demo-token")
	defer rc.Close()
	doc, _ := entries[0].Alert.Marshal()
	req, _ := http.NewRequest(http.MethodPost, rc.URL(), bytes.NewReader(doc))
	req.Header.Set("Content-Type", cap.MediaType)
	req.Header.Set("Authorization", "Bearer demo-token")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		fmt.Println("receiver:", resp.StatusCode, rc.Messages()[0].Identifier)
	}
	// Output:
	// feed: SIM-1
	// receiver: 204 SIM-1
}
