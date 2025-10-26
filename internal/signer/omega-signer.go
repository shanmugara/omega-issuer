package signer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	omegaissuerapi "github.com/cert-manager/sample-external-issuer/api/v1alpha1"
	"github.com/cert-manager/sample-external-issuer/internal/controllers"
	"github.com/shanmugara/spireauthlib"
	"github.com/sirupsen/logrus"
)

func OmegaSignerFromIssuerAndSecretData(s *omegaissuerapi.IssuerSpec, b map[string][]byte) (controllers.Signer, error) {
	return &omegaSigner{spec: s}, nil
}

func OmegaSignerHealthCheckerFromIssuerAndSecretData(s *omegaissuerapi.IssuerSpec, b map[string][]byte) (controllers.HealthChecker, error) {
	return &omegaSigner{spec: s}, nil
}

type omegaSigner struct {
	spec *omegaissuerapi.IssuerSpec
}

func (o *omegaSigner) Check() error {
	return nil
}

func (o *omegaSigner) Sign(csr []byte) ([]byte, error) {
	// payload structure expected by the signing API
	type payload struct {
		CSRpem string `json:"csrpem,omitempty"`
		CSRb64 string `json:"csrb64,omitempty"`
		Token  string `json:"authtoken,omitempty"`
	}

	// response structure expected from the signing API
	type responseData struct {
		Certificate string `json:"certificate"`
	}

	if o == nil || o.spec == nil {
		return nil, fmt.Errorf("signer not configured")
	}
	if o.spec.URL == "" {
		return nil, fmt.Errorf("signer URL not configured in issuer spec")
	}

	// Build payload: include CSR as base64 (CSR is typically DER from cert-manager)
	pl := payload{
		CSRb64: base64.StdEncoding.EncodeToString(csr),
	}

	jsonData, err := json.Marshal(pl)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request JSON: %w", err)
	}

	ctx := context.Background()
	// use spire svid auth
	cauth := spireauthlib.ClientAuth{Logger: logrus.New()}
	tlsClient, err := cauth.GetTlsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tls client: %w", err)
	}
	req, err := http.NewRequest("POST", o.spec.URL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tlsClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("signing request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("signing API returned status %d: %s", resp.StatusCode, string(body))
	}

	var rd responseData
	if err := json.Unmarshal(body, &rd); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signing response JSON: %w (body: %s)", err, string(body))
	}

	if rd.Certificate == "" {
		return nil, fmt.Errorf("signing API returned empty certificate")
	}

	// The API returns the certificate as PEM text; return as bytes
	return []byte(rd.Certificate), nil
}
