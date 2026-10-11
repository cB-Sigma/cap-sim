// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"bytes"
	"fmt"
	"io"
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
	for _, f := range []sim.Format{sim.AtomEmbedded, sim.AtomLinked, sim.RSSLinked} {
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
		feed.Add(demoAlert("SIM-2"))
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
