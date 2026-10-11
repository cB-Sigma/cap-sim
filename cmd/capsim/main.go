// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Command capsim serves a simulated CAP feed holding one demo alert, or a
// receiver that accepts CAP messages by HTTP POST and prints each one, so
// a CAP reader or publisher can be tried without a real alerting
// authority. For example:
//
//	capsim feed -listen 127.0.0.1:8098 -format rss
//	capsim feed -listen 127.0.0.1:8098 -format edxl
//	capsim feed -listen 127.0.0.1:8098 -format edxl2
//	capsim receiver -listen 127.0.0.1:8099 -token demo-token -profile IPAWS
//
// The feed is at /feed; the receiver takes POSTs at /cap.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cB-Sigma/cap"
	"github.com/cB-Sigma/cap-sim/sim"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, nil); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "capsim:", err)
		os.Exit(1)
	}
}

// demoAlert is the alert the feed serves: made-up content.
func demoAlert(now time.Time) *cap.Alert {
	return &cap.Alert{
		Identifier: "SIM-0001", Sender: "capsim@example.test", Sent: cap.FormatTime(now),
		Status: "Exercise", MsgType: "Alert", Scope: "Public",
		Info: []cap.Info{{
			Language: "en", Category: []string{"Met"}, Event: "Heavy Rainfall",
			Urgency: "Expected", Severity: "Moderate", Certainty: "Likely",
			Expires:  cap.FormatTime(now.Add(24 * time.Hour)),
			Headline: "Simulated heavy rainfall warning",
			Area: []cap.Area{{
				AreaDesc: "Demo district",
				Circle:   []string{"18.52,73.85 5"},
			}},
		}},
	}
}

// run serves until ctx ends. ready, when not nil, receives the address
// served.
func run(ctx context.Context, args []string, out io.Writer, ready chan<- string) error {
	if len(args) == 0 || (args[0] != "feed" && args[0] != "receiver") {
		return errors.New("usage: capsim feed|receiver [-listen addr] [-format atom|atom-linked|rss|edxl|edxl2|bare] [-token t] [-profile CAP-CP|IPAWS|India]")
	}
	fs := flag.NewFlagSet("capsim "+args[0], flag.ContinueOnError)
	fs.SetOutput(out)
	listen := fs.String("listen", "127.0.0.1:8098", "address to listen on")
	format := fs.String("format", "atom", "feed format: atom (embedded alerts), atom-linked, rss, edxl (an EDXL-DE 1.0 envelope), edxl2 (EDXL-DE 2.0) or bare (the alert alone)")
	token := fs.String("token", "", "receiver: bearer token required (empty: none)")
	profile := fs.String("profile", "", "receiver: also validate against this profile (CAP-CP, IPAWS or India)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	var profiles []cap.Profile
	if *profile != "" {
		p, ok := cap.ProfileByName(*profile)
		if !ok {
			return fmt.Errorf("unknown -profile %q (known: %v)", *profile, cap.ProfileNames())
		}
		profiles = append(profiles, p)
	}
	var url string
	var receiver *sim.Receiver
	switch args[0] {
	case "feed":
		f, ok := map[string]sim.Format{"atom": sim.AtomEmbedded, "atom-linked": sim.AtomLinked, "rss": sim.RSSLinked, "edxl": sim.EDXLEmbedded, "edxl2": sim.EDXL2Embedded, "bare": sim.BareAlert}[*format]
		if !ok {
			return fmt.Errorf("unknown -format %q", *format)
		}
		feed, err := sim.NewFeedAt(f, *listen)
		if err != nil {
			return err
		}
		defer feed.Close()
		feed.Add(demoAlert(time.Now()))
		url = feed.URL()
	case "receiver":
		rc, err := sim.NewReceiverAt(*token, *listen)
		if err != nil {
			return err
		}
		defer rc.Close()
		rc.SetProfiles(profiles...)
		receiver, url = rc, rc.URL()
	}
	fmt.Fprintf(out, "capsim %s at %s\n", args[0], url)
	if ready != nil {
		ready <- url
	}
	seen := 0
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if receiver == nil {
				continue
			}
			msgs := receiver.Messages()
			for _, a := range msgs[seen:] {
				fmt.Fprintf(out, "received %s %s from %s\n", a.MsgType, a.Identifier, a.Sender)
			}
			seen = len(msgs)
		}
	}
}
