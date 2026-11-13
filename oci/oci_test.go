package oci

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	agentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	serverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

const (
	tenancy  = "ocid1.tenancy.oc1..aaaatest"
	instance = "ocid1.instance.oc1.ap-osaka-1.anvwtest"
)

// issue mirrors the shape of a real OCI instance chain: root (CA) -> intermediate (CA) -> leaf with
// EKU clientAuth only and no KeyUsage, identity in the subject OUs.
func issue(t *testing.T, subject pkix.Name, parent *x509.Certificate, parentKey *rsa.PrivateKey, ca bool) (*x509.Certificate, *rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(2 * time.Hour),
	}
	if ca {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		tmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func leafSubject(tenant string) pkix.Name {
	return pkix.Name{CommonName: instance, OrganizationalUnit: []string{
		"opc-certtype:instance", "opc-compartment:" + tenant, "opc-instance:" + instance, "opc-tenant:" + tenant,
	}}
}

type world struct {
	rootPEM, interPEM, leafPEM, keyPEM string
}

func newWorld(t *testing.T, tenant string) world {
	root, rootKey, rootPEM := issue(t, pkix.Name{CommonName: "OCI Instance Identity Root - test"}, nil, nil, true)
	inter, interKey, interPEM := issue(t, pkix.Name{CommonName: "PKISVC Identity Intermediate test"}, root, rootKey, true)
	_, leafKey, leafPEM := issue(t, leafSubject(tenant), inter, interKey, false)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}))
	return world{rootPEM, interPEM, leafPEM, keyPEM}
}

// attest runs a full agent<->server exchange through the real plugin gRPC plumbing.
func attest(t *testing.T, w world, trustedRoot string) (*serverv1.AgentAttributes, error) {
	t.Helper()
	imds := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer Oracle" {
			http.Error(rw, "no", http.StatusUnauthorized)
			return
		}
		body := map[string]string{"/cert.pem": w.leafPEM, "/intermediate.pem": w.interPEM, "/key.pem": w.keyPEM}[r.URL.Path]
		rw.Write([]byte(body))
	}))
	t.Cleanup(imds.Close)
	bundle := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(bundle, []byte(trustedRoot), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	agentNA, agentCfg := new(agentv1.NodeAttestorPluginClient), new(configv1.ConfigServiceClient)
	ag := new(Agent)
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: agentv1.NodeAttestorPluginServer(ag), PluginClient: agentNA,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(ag)}, ServiceClients: []pluginsdk.ServiceClient{agentCfg},
	})
	serverNA, serverCfg := new(serverv1.NodeAttestorPluginClient), new(configv1.ConfigServiceClient)
	sv := new(Server)
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: serverv1.NodeAttestorPluginServer(sv), PluginClient: serverNA,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(sv)}, ServiceClients: []pluginsdk.ServiceClient{serverCfg},
	})
	core := &configv1.CoreConfiguration{TrustDomain: "example.org"}
	if _, err := agentCfg.Configure(ctx, &configv1.ConfigureRequest{CoreConfiguration: core, HclConfiguration: `imds_url = "` + imds.URL + `"`}); err != nil {
		t.Fatal(err)
	}
	if _, err := serverCfg.Configure(ctx, &configv1.ConfigureRequest{CoreConfiguration: core,
		HclConfiguration: `trust_bundle_path = "` + bundle + `"
tenancy_allow_list = ["` + tenancy + `"]`}); err != nil {
		t.Fatal(err)
	}

	as, err := agentNA.AidAttestation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := serverNA.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Relay: agent payload -> server, server challenge -> agent, agent response -> server.
	m, err := as.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.Send(&serverv1.AttestRequest{Request: &serverv1.AttestRequest_Payload{Payload: m.GetPayload()}}); err != nil {
		t.Fatal(err)
	}
	r, err := ss.Recv()
	if err != nil {
		return nil, err
	}
	if err := as.Send(&agentv1.Challenge{Challenge: r.GetChallenge()}); err != nil {
		t.Fatal(err)
	}
	m, err = as.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if err := ss.Send(&serverv1.AttestRequest{Request: &serverv1.AttestRequest_ChallengeResponse{ChallengeResponse: m.GetChallengeResponse()}}); err != nil {
		t.Fatal(err)
	}
	r, err = ss.Recv()
	if err != nil {
		return nil, err
	}
	return r.GetAgentAttributes(), nil
}

func TestAttest(t *testing.T) {
	w := newWorld(t, tenancy)
	attrs, err := attest(t, w, w.rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	if want := "spiffe://example.org/spire/agent/oci_instance/" + instance; attrs.SpiffeId != want {
		t.Errorf("spiffe id %q, want %q", attrs.SpiffeId, want)
	}
	if got := strings.Join(attrs.SelectorValues, " "); !strings.Contains(got, "region:ap-osaka-1") || !strings.Contains(got, "tenancy:"+tenancy) {
		t.Errorf("selectors %q", got)
	}
	if !attrs.CanReattest {
		t.Error("CanReattest false")
	}
}

func TestReject(t *testing.T) {
	good := newWorld(t, tenancy)
	other := newWorld(t, tenancy)
	stolen := good
	stolen.keyPEM = other.keyPEM // valid public cert, but the attacker lacks its key

	for name, tc := range map[string]struct {
		w    world
		root string
		want string
	}{
		"untrusted root":  {good, other.rootPEM, "verify"},
		"foreign tenancy": {newWorld(t, "ocid1.tenancy.oc1..evil"), "", "not allowed"},
		"replayed cert":   {stolen, good.rootPEM, "challenge"},
	} {
		t.Run(name, func(t *testing.T) {
			root := tc.root
			if root == "" {
				root = tc.w.rootPEM
			}
			_, err := attest(t, tc.w, root)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}
