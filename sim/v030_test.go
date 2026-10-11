// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/cap"
	"github.com/cB-Sigma/cap-sim/sim"
	"github.com/cB-Sigma/cap/capnet"
)

// Covers: SIG-IPE-7327
//
// The feed over HTTPS, paged, as an EDXL-DE 2.0 envelope and as a bare
// alert, read by capnet.Poller; documents also in JSON.
func TestFeedFormatsHTTPSAndPaging(t *testing.T) {
	for _, f := range []struct {
		name  string
		fmt   sim.Format
		pages int
	}{{"atom-paged", sim.AtomEmbedded, 3}, {"edxl-de-2.0", sim.EDXL2Embedded, 1}, {"bare", sim.BareAlert, 1}} {
		t.Run(f.name, func(t *testing.T) {
			feed := sim.NewFeedTLS(f.fmt)
			defer feed.Close()
			if f.fmt == sim.AtomEmbedded {
				feed.PageSize = 2
			}
			for i := 0; i < 5; i++ {
				feed.Add(demoAlert(fmt.Sprintf("P-%d", i)))
			}
			p := &capnet.Poller{URL: feed.URL(), Client: feed.Client(), MaxPages: f.pages}
			items, err := p.Poll(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := 5 // paged: three pages of two hold all five
			if f.fmt == sim.BareAlert {
				want = 1
			}
			if len(items) != want {
				t.Fatalf("%d items, want %d", len(items), want)
			}
		})
	}
	// Two pages read of three: four alerts.
	feed := sim.NewFeedTLS(sim.AtomEmbedded)
	defer feed.Close()
	feed.PageSize = 2
	for i := 0; i < 5; i++ {
		feed.Add(demoAlert(fmt.Sprintf("Q-%d", i)))
	}
	items, err := (&capnet.Poller{URL: feed.URL(), Client: feed.Client(), MaxPages: 2}).Poll(context.Background())
	if err != nil || len(items) != 4 {
		t.Fatalf("%d items, %v", len(items), err)
	}
	resp, err := feed.Client().Get(strings.TrimSuffix(feed.URL(), "/feed") + "/docs/0.json")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if a, err := cap.ParseJSON(b); err != nil || a.Identifier != "Q-0" {
		t.Fatalf("JSON document: %v %s", err, b)
	}
}

// Covers: SIG-IPE-7327
//
// Update and Cancel publish a chain a reader's History follows.
func TestFeedLifecycle(t *testing.T) {
	feed := sim.NewFeed(sim.AtomEmbedded)
	defer feed.Close()
	first := demoAlert("L-1")
	feed.Add(first)
	time.Sleep(1100 * time.Millisecond) // a later sent time
	next := demoAlert("L-2")
	feed.Update(first, next)
	cancel := feed.Cancel(next, "L-3")
	h := cap.NewHistory()
	items, err := (&capnet.Poller{URL: feed.URL(), History: h}).Poll(context.Background())
	if err != nil || len(items) != 3 {
		t.Fatalf("%d items, %v", len(items), err)
	}
	if next.MsgType != "Update" || cancel.MsgType != "Cancel" || len(h.Missing(cancel, time.Now())) != 0 {
		t.Fatalf("chain: %s %s missing %v", next.MsgType, cancel.MsgType, h.Missing(cancel, time.Now()))
	}
}

// Covers: SIG-IPE-7327
//
// Alerts signed under the simulated CA verify with CRL and OCSP checks
// fetched from it, until the certificate is revoked.
func TestCARevocation(t *testing.T) {
	ca, err := sim.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()
	sg, cert, err := ca.Issue("alerts.example.test")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := demoAlert("R-1").Marshal()
	signed, err := sg.Sign(doc)
	if err != nil {
		t.Fatal(err)
	}
	fetchCRL := func() ([]byte, error) {
		resp, err := http.Get(cert.CRLDistributionPoints[0])
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	verify := func(useCRL bool) error {
		v, err := cap.NewVerifier(cap.VerifySettings{Roots: []string{ca.RootPEM()}, Require: true})
		if err != nil {
			return err
		}
		if useCRL {
			der, err := fetchCRL()
			if err != nil {
				return err
			}
			crls, err := cap.ParseCRLs(der)
			if err != nil {
				return err
			}
			v.Revoked = cap.CRLCheck(crls...)
		} else {
			v.Revoked = cap.OCSPCheck(cap.OCSPOptions{Strict: true})
		}
		_, _, _, err = v.VerifyChain(signed)
		return err
	}
	for _, crl := range []bool{true, false} {
		if err := verify(crl); err != nil {
			t.Fatalf("before revocation (CRL %v): %v", crl, err)
		}
	}
	ca.Revoke(cert)
	for _, crl := range []bool{true, false} {
		if err := verify(crl); err == nil {
			t.Fatalf("a revoked certificate verified (CRL %v)", crl)
		}
	}
}
