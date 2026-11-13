// Package oci implements a SPIRE node attestor for OCI compute instances, based on the instance
// identity certificate that every instance gets from IMDS (/opc/v2/identity/*.pem).
//
// Why a custom plugin: SPIRE has none for OCI, and the built-in x509pop rejects these
// certificates because the leaf carries no KeyUsage extension (only EKU clientAuth), while
// x509pop requires digitalSignature.
package oci

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

// PluginName is the name both sides are registered under; selectors become oci_instance:<k>:<v>.
const PluginName = "oci_instance"

// Payload is what the agent sends first. Only public certificates: the private key never leaves
// the instance, possession is proven by signing the server's nonce.
type Payload struct {
	Cert         string `json:"cert"`
	Intermediate string `json:"intermediate"`
}

// challengeDigest separates our signatures from any other use of the instance key: a signature
// produced here cannot be replayed as, say, an OCI request signature, and vice versa.
func challengeDigest(nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte("spire-plugin-oci/challenge/v1\x00"))
	h.Write(nonce)
	return h.Sum(nil)
}

func signChallenge(key crypto.Signer, nonce []byte) ([]byte, error) {
	// RSA keys sign PKCS#1 v1.5, EC keys ASN.1 ECDSA; verifyChallenge mirrors both.
	return key.Sign(nil, challengeDigest(nonce), crypto.SHA256)
}

func verifyChallenge(pub crypto.PublicKey, nonce, sig []byte) error {
	d := challengeDigest(nonce)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, d, sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, d, sig) {
			return errors.New("ecdsa signature mismatch")
		}
		return nil
	default:
		return errors.New("unsupported key type")
	}
}
