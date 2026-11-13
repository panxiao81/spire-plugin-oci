package oci

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/hcl"
	serverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serverConfig struct {
	// PEM file with the OCI region root(s) from
	// GET https://auth.<region>.oraclecloud.com/v1/instancePrincipalRootCACertificates.
	// Re-read on every attestation so a rotated root only needs the file replaced, no restart.
	TrustBundlePath string `hcl:"trust_bundle_path"`
	// Tenancy OCIDs whose instances may attest. Required: the roots are shared by every OCI
	// customer in the region, so without this any OCI instance anywhere would get in.
	TenancyAllowList []string `hcl:"tenancy_allow_list"`
}

type serverState struct {
	trustDomain string
	bundlePath  string
	tenancies   map[string]bool
}

type Server struct {
	serverv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mu  sync.RWMutex
	cfg *serverState
	now func() time.Time // tests pin the clock
}

func (s *Server) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	c := new(serverConfig)
	if err := hcl.Decode(c, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "decode configuration: %v", err)
	}
	if c.TrustBundlePath == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_bundle_path is required")
	}
	if len(c.TenancyAllowList) == 0 {
		return nil, status.Error(codes.InvalidArgument, "tenancy_allow_list is required")
	}
	if _, err := loadRoots(c.TrustBundlePath); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "trust bundle: %v", err)
	}
	td := req.GetCoreConfiguration().GetTrustDomain()
	if td == "" {
		return nil, status.Error(codes.InvalidArgument, "core configuration has no trust domain")
	}
	st := &serverState{trustDomain: td, bundlePath: c.TrustBundlePath, tenancies: map[string]bool{}}
	for _, t := range c.TenancyAllowList {
		st.tenancies[t] = true
	}
	s.mu.Lock()
	s.cfg = st
	s.mu.Unlock()
	return &configv1.ConfigureResponse{}, nil
}

func (s *Server) Attest(stream serverv1.NodeAttestor_AttestServer) error {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	if cfg == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}
	var p Payload
	if err := json.Unmarshal(req.GetPayload(), &p); err != nil {
		return status.Errorf(codes.InvalidArgument, "payload: %v", err)
	}
	roots, err := loadRoots(cfg.bundlePath)
	if err != nil {
		return status.Errorf(codes.Internal, "trust bundle: %v", err)
	}
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	leaf, id, err := verifyChain(p, roots, now)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "%v", err)
	}
	if !cfg.tenancies[id.tenant] {
		return status.Errorf(codes.PermissionDenied, "tenancy %s not allowed", id.tenant)
	}

	// The certificate is public (anyone who once saw it could replay it for ~2h), so the agent
	// must also prove it holds the IMDS private key.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return status.Errorf(codes.Internal, "nonce: %v", err)
	}
	if err := stream.Send(&serverv1.AttestResponse{Response: &serverv1.AttestResponse_Challenge{Challenge: nonce}}); err != nil {
		return err
	}
	resp, err := stream.Recv()
	if err != nil {
		return err
	}
	if err := verifyChallenge(leaf.PublicKey, nonce, resp.GetChallengeResponse()); err != nil {
		return status.Errorf(codes.PermissionDenied, "challenge: %v", err)
	}

	return stream.Send(&serverv1.AttestResponse{Response: &serverv1.AttestResponse_AgentAttributes{
		AgentAttributes: &serverv1.AgentAttributes{
			// Stable across leaf rotation, so entries can parent to it directly (unlike x509pop,
			// whose agent ID embeds the leaf fingerprint).
			SpiffeId: fmt.Sprintf("spiffe://%s/spire/agent/%s/%s", cfg.trustDomain, PluginName, id.instance),
			SelectorValues: []string{
				"tenancy:" + id.tenant,
				"compartment:" + id.compartment,
				"instance:" + id.instance,
				"region:" + id.region,
			},
			// Safe to re-attest: every attestation needs the live IMDS key, which only the
			// instance itself can read. Without it a lost data_dir would need a human.
			CanReattest: true,
		},
	}})
}

type instanceID struct{ tenant, compartment, instance, region string }

func verifyChain(p Payload, roots *x509.CertPool, now time.Time) (*x509.Certificate, instanceID, error) {
	var id instanceID
	leaf, err := parseCert(p.Cert)
	if err != nil {
		return nil, id, fmt.Errorf("leaf: %w", err)
	}
	inters := x509.NewCertPool()
	if !inters.AppendCertsFromPEM([]byte(p.Intermediate)) {
		return nil, id, fmt.Errorf("intermediate: no certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, id, fmt.Errorf("verify: %w", err)
	}

	ou := map[string]string{}
	for _, u := range leaf.Subject.OrganizationalUnit {
		if k, v, ok := strings.Cut(u, ":"); ok {
			ou[k] = v
		}
	}
	// The same CA also issues other cert types (e.g. resource principals); only instances may attest.
	if ou["opc-certtype"] != "instance" {
		return nil, id, fmt.Errorf("cert type %q is not instance", ou["opc-certtype"])
	}
	id = instanceID{tenant: ou["opc-tenant"], compartment: ou["opc-compartment"], instance: ou["opc-instance"]}
	if id.tenant == "" || id.compartment == "" || id.instance == "" || id.instance != leaf.Subject.CommonName {
		return nil, id, fmt.Errorf("incomplete or inconsistent subject %q", leaf.Subject)
	}
	// ocid1.instance.<realm>.<region>.<unique>
	parts := strings.Split(id.instance, ".")
	if len(parts) != 5 || parts[0] != "ocid1" || parts[1] != "instance" {
		return nil, id, fmt.Errorf("unexpected instance OCID %q", id.instance)
	}
	id.region = parts[3]
	return leaf, id, nil
}

func parseCert(s string) (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func loadRoots(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no certificates", path)
	}
	return pool, nil
}
