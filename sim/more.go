// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim

import (
	"crypto"
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
	"net/http/httptest"
	"sync"
	"time"

	"github.com/cB-Sigma/cap"
	"golang.org/x/crypto/ocsp"
)

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// NewFeedTLS starts a feed server over HTTPS on a loopback port, with a
// self-signed certificate that Client trusts.
func NewFeedTLS(f Format) *Feed {
	s := &Feed{format: f, modified: time.Now().UTC().Truncate(time.Second)}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	return s
}

// Client is an HTTP client that trusts the feed's certificate (for a feed
// from NewFeedTLS; a plain client otherwise).
func (s *Feed) Client() *http.Client { return s.srv.Client() }

// NewReceiverTLS starts a receiver over HTTPS on a loopback port.
func NewReceiverTLS(token string) *Receiver {
	rc := &Receiver{Token: token}
	rc.srv = httptest.NewTLSServer(http.HandlerFunc(rc.serve))
	return rc
}

// Client is an HTTP client that trusts the receiver's certificate.
func (rc *Receiver) Client() *http.Client { return rc.srv.Client() }

// Update publishes next as an Update of prev: its msgType becomes Update
// and its references name prev (and what prev referenced), as CAP 1.2
// 3.2.1 has it. Cancel publishes a Cancel of prev the same way.
func (s *Feed) Update(prev, next *cap.Alert) {
	next.MsgType = "Update"
	next.References = refsOf(prev)
	s.Add(next)
}

// Cancel publishes a Cancel of prev with the identifier given.
func (s *Feed) Cancel(prev *cap.Alert, identifier string) *cap.Alert {
	c := *prev
	c.Identifier, c.MsgType, c.References = identifier, "Cancel", refsOf(prev)
	c.Sent = cap.FormatTime(time.Now())
	c.Info = append([]cap.Info(nil), prev.Info...)
	s.Add(&c)
	return &c
}

func refsOf(prev *cap.Alert) string {
	r := prev.Sender + "," + prev.Identifier + "," + prev.Sent
	if prev.References != "" {
		r = prev.References + " " + r
	}
	return r
}

// CA is a simulated certificate authority for signed alerts: it issues
// signing certificates that point to its CRL and OCSP responder (served
// by Handler) and revokes them on request, so a reader's revocation checks
// can be tried end to end.
type CA struct {
	srv  *httptest.Server
	key  crypto.Signer
	cert *x509.Certificate

	mu      sync.Mutex
	serial  int64
	revoked map[string]time.Time // serial (decimal) -> revocation time
}

// NewCA starts a CA whose CRL is at URL()+"/crl" and OCSP responder at
// URL()+"/ocsp".
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "capsim CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	ca := &CA{key: key, cert: cert, serial: 1, revoked: map[string]time.Time{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/crl", ca.serveCRL)
	mux.HandleFunc("/ocsp", ca.serveOCSP)
	ca.srv = httptest.NewServer(mux)
	return ca, nil
}

// URL is the CA's address.
func (ca *CA) URL() string { return ca.srv.URL }

// Close stops the CA's server.
func (ca *CA) Close() { ca.srv.Close() }

// RootPEM is the CA certificate, for cap.VerifySettings.Roots.
func (ca *CA) RootPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
}

// Issue makes a signing key and certificate for cn and returns a
// cap.Signer with them and the certificate.
func (ca *CA) Issue(cn string) (*cap.Signer, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ca.mu.Lock()
	ca.serial++
	serial := ca.serial
	ca.mu.Unlock()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, CRLDistributionPoints: []string{ca.URL() + "/crl"},
		OCSPServer: []string{ca.URL() + "/ocsp"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return nil, nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	s, err := cap.NewSigner(cap.SignSettings{
		Key:         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})),
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))})
	return s, cert, err
}

// Revoke revokes a certificate the CA issued.
func (ca *CA) Revoke(cert *x509.Certificate) {
	ca.mu.Lock()
	ca.revoked[cert.SerialNumber.String()] = time.Now().Add(-time.Minute)
	ca.mu.Unlock()
}

func (ca *CA) serveCRL(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	var entries []x509.RevocationListEntry
	for s, at := range ca.revoked {
		n, _ := new(big.Int).SetString(s, 10)
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: at})
	}
	ca.mu.Unlock()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(time.Now().UnixNano()),
		ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour), RevokedCertificateEntries: entries}, ca.cert, ca.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(der)
}

func (ca *CA) serveOCSP(w http.ResponseWriter, r *http.Request) {
	var body []byte
	var err error
	if r.Method == http.MethodPost {
		body, err = io.ReadAll(io.LimitReader(r.Body, 64<<10))
	} else {
		err = fmt.Errorf("POST only")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := ocsp.ParseRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ca.mu.Lock()
	at, isRevoked := ca.revoked[req.SerialNumber.String()]
	ca.mu.Unlock()
	tmpl := ocsp.Response{Status: ocsp.Good, SerialNumber: req.SerialNumber, ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour)}
	if isRevoked {
		tmpl.Status, tmpl.RevokedAt, tmpl.RevocationReason = ocsp.Revoked, at, ocsp.KeyCompromise
	}
	resp, err := ocsp.CreateResponse(ca.cert, ca.cert, tmpl, ca.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	_, _ = w.Write(resp)
}
