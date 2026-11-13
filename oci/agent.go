package oci

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
	agentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const defaultIMDSURL = "http://169.254.169.254/opc/v2/identity"

type agentConfig struct {
	// Only overridden in tests; on an instance IMDS is always at the link-local address.
	IMDSURL string `hcl:"imds_url"`
}

// Agent reads the identity certificate and key fresh from IMDS on every attestation. Nothing is
// cached or written to disk: the leaf rotates about every 2 hours and IMDS always has the current one.
type Agent struct {
	agentv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mu   sync.RWMutex
	imds string
}

func (a *Agent) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	c := new(agentConfig)
	if err := hcl.Decode(c, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode configuration: %v", err)
	}
	if c.IMDSURL == "" {
		c.IMDSURL = defaultIMDSURL
	}
	a.mu.Lock()
	a.imds = strings.TrimSuffix(c.IMDSURL, "/")
	a.mu.Unlock()
	return &configv1.ConfigureResponse{}, nil
}

func (a *Agent) AidAttestation(stream agentv1.NodeAttestor_AidAttestationServer) error {
	a.mu.RLock()
	base := a.imds
	a.mu.RUnlock()
	if base == "" {
		return status.Error(codes.FailedPrecondition, "not configured")
	}
	ctx := stream.Context()
	get := func(name string) (string, error) { return imdsGet(ctx, base+"/"+name) }

	cert, err := get("cert.pem")
	if err != nil {
		return err
	}
	inter, err := get("intermediate.pem")
	if err != nil {
		return err
	}
	keyPEM, err := get("key.pem")
	if err != nil {
		return err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return status.Errorf(codes.Internal, "parse IMDS key: %v", err)
	}

	payload, _ := json.Marshal(Payload{Cert: cert, Intermediate: inter})
	if err := stream.Send(&agentv1.PayloadOrChallengeResponse{
		Data: &agentv1.PayloadOrChallengeResponse_Payload{Payload: payload},
	}); err != nil {
		return err
	}
	ch, err := stream.Recv()
	if err != nil {
		return err
	}
	sig, err := signChallenge(key, ch.Challenge)
	if err != nil {
		return status.Errorf(codes.Internal, "sign challenge: %v", err)
	}
	return stream.Send(&agentv1.PayloadOrChallengeResponse{
		Data: &agentv1.PayloadOrChallengeResponse_ChallengeResponse{ChallengeResponse: sig},
	})
}

func imdsGet(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	// IMDSv2 requires this exact header (and IMDSv1 may be disabled on the instance).
	req.Header.Set("Authorization", "Bearer Oracle")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "IMDS %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", status.Errorf(codes.Unavailable, "IMDS %s: status %d: %v", url, resp.StatusCode, err)
	}
	return string(b), nil
}

func parseKey(s string) (crypto.Signer, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key type %T cannot sign", k)
	}
	return signer, nil
}
