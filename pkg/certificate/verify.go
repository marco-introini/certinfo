package certificate

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"
)

// VerifyOptions contains optional parameters for certificate chain verification.
type VerifyOptions struct {
	CAFiles   []string
	Roots     *x509.CertPool
	CheckCRL  bool
	CheckOCSP bool
}

// Verify validates the certificate against the provided roots or the system
// trust store. Returns nil if the chain is valid.
func (c *CertificateInfo) Verify(opts VerifyOptions) error {
	if c == nil || c.x509Certificate == nil {
		return fmt.Errorf("certificate is required")
	}

	roots := opts.Roots
	if len(opts.CAFiles) > 0 {
		pool := x509.NewCertPool()
		for _, caFile := range opts.CAFiles {
			data, err := os.ReadFile(caFile)
			if err != nil {
				return fmt.Errorf("failed to read CA file %s: %w", caFile, err)
			}
			if !pool.AppendCertsFromPEM(data) {
				return fmt.Errorf("no valid CA certificates found in %s", caFile)
			}
		}
		roots = pool
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Intermediates: x509.NewCertPool(),
	}

	chains, err := c.x509Certificate.Verify(verifyOpts)
	if err != nil {
		return err
	}

	if opts.CheckCRL {
		if err := c.checkCRL(); err != nil {
			return err
		}
	}

	if opts.CheckOCSP && len(chains) > 0 && len(chains[0]) > 1 {
		if err := c.checkOCSP(chains[0][1]); err != nil {
			return err
		}
	}

	return nil
}

func (c *CertificateInfo) checkCRL() error {
	if len(c.CRLDistributionPoints) == 0 {
		return fmt.Errorf("no CRL distribution points available")
	}

	for _, url := range c.CRLDistributionPoints {
		crl, err := fetchCRL(url)
		if err != nil {
			return fmt.Errorf("failed to fetch CRL from %s: %w", url, err)
		}

		if time.Now().After(crl.NextUpdate) {
			return fmt.Errorf("CRL from %s is expired", url)
		}

		serial := c.x509Certificate.SerialNumber
		for _, revoked := range crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(serial) == 0 {
				return fmt.Errorf("certificate was revoked by CRL %s", url)
			}
		}
	}

	return nil
}

func (c *CertificateInfo) checkOCSP(issuer *x509.Certificate) error {
	if len(c.OCSPServers) == 0 {
		return fmt.Errorf("no OCSP servers available")
	}

	req, err := ocsp.CreateRequest(c.x509Certificate, issuer, nil)
	if err != nil {
		return fmt.Errorf("failed to create OCSP request: %w", err)
	}

	for _, server := range c.OCSPServers {
		resp, err := postOCSP(server, req)
		if err != nil {
			return fmt.Errorf("OCSP request to %s failed: %w", server, err)
		}

		parsed, err := ocsp.ParseResponse(resp, issuer)
		if err != nil {
			return fmt.Errorf("failed to parse OCSP response from %s: %w", server, err)
		}

		switch parsed.Status {
		case ocsp.Good:
			return nil
		case ocsp.Revoked:
			return fmt.Errorf("certificate revoked according to OCSP %s", server)
		case ocsp.Unknown:
			return fmt.Errorf("OCSP %s returned unknown status", server)
		default:
			return fmt.Errorf("OCSP %s returned unexpected status %d", server, parsed.Status)
		}
	}

	return fmt.Errorf("no valid OCSP response received")
}

func postOCSP(url string, req []byte) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(url, "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func fetchCRL(url string) (*x509.RevocationList, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseRevocationList(data)
}
