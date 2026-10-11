// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func start(t *testing.T, args ...string) (string, *syncBuf) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuf{}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- run(ctx, args, out, ready) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	select {
	case url := <-ready:
		return url, out
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("not ready")
	}
	return "", nil
}

func TestFeedServesAValidAlert(t *testing.T) {
	for _, f := range []string{"atom", "atom-linked", "rss", "edxl", "edxl2", "bare"} {
		url, _ := start(t, "feed", "-listen", "127.0.0.1:0", "-format", f)
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		entries, err := cap.ParseFeed(body)
		if err != nil || len(entries) != 1 {
			t.Fatalf("%s: %v %d", f, err, len(entries))
		}
		if f == "atom" || f == "edxl" || f == "edxl2" || f == "bare" {
			if a := entries[0].Alert; a == nil || a.Validate(cap.Options{}) != nil {
				t.Errorf("embedded alert %+v is not valid", a)
			}
		} else if entries[0].Link == "" {
			t.Errorf("%s: no link", f)
		}
	}
}

func TestReceiverPrintsMessages(t *testing.T) {
	url, out := start(t, "receiver", "-listen", "127.0.0.1:0", "-token", "demo-token")
	doc, err := demoAlert(time.Now()).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(doc))
	req.Header.Set("Content-Type", cap.MediaType)
	req.Header.Set("Authorization", "Bearer demo-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "received Alert SIM-0001") {
		if time.Now().After(deadline) {
			t.Fatalf("output: %s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestUsage(t *testing.T) {
	if err := run(context.Background(), nil, io.Discard, nil); err == nil {
		t.Error("no mode accepted")
	}
	if err := run(context.Background(), []string{"receiver", "-profile", "nowhere"}, io.Discard, nil); err == nil || !strings.Contains(err.Error(), "unknown -profile") {
		t.Errorf("unknown profile: %v", err)
	}
}

// With -profile the receiver refuses an alert that breaks the profile.
func TestReceiverProfile(t *testing.T) {
	url, _ := start(t, "receiver", "-listen", "127.0.0.1:0", "-profile", "IPAWS")
	doc, _ := demoAlert(time.Now()).Marshal()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(doc))
	req.Header.Set("Content-Type", cap.MediaType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body), "IPAWSv1.0") {
		t.Errorf("status %d: %s", resp.StatusCode, body)
	}
}
