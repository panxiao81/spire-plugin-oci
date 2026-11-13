# spire-plugin-oci

A [SPIRE](https://spiffe.io/) NodeAttestor plugin (`oci_instance`) for Oracle Cloud
Infrastructure compute instances. It attests nodes with the instance identity certificate that
OCI provides to every instance through IMDS (`/opc/v2/identity/{cert,intermediate,key}.pem`).

SPIRE ships no OCI attestor, and the built-in `x509pop` rejects these certificates: the OCI
leaf has no KeyUsage extension (only EKU clientAuth), while `x509pop` requires `digitalSignature`.

## How it works

1. The **agent** fetches the certificate, intermediate and private key from IMDS on every
   attestation. It caches nothing; OCI rotates the leaf roughly every two hours.
2. The agent sends the public certificate and intermediate to the server.
3. The **server** verifies:
   - the chain up to a root in `trust_bundle_path`;
   - EKU clientAuth, and that the leaf is currently valid;
   - `opc-certtype:instance` in the subject;
   - a tenancy listed in `tenancy_allow_list`.
4. The server sends a random nonce. The agent signs it with the IMDS key, which proves it holds
   the key. Without this step, anyone who saw the public certificate could replay it until it expires.
5. On success:
   - the agent ID is `spiffe://<trust domain>/spire/agent/oci_instance/<instance OCID>`. It
     stays the same across certificate rotation, so registration entries can use it as their
     parent directly;
   - the selectors are `oci_instance:tenancy:<ocid>`, `oci_instance:compartment:<ocid>`,
     `oci_instance:instance:<ocid>` and `oci_instance:region:<region>`;
   - the agent may re-attest.

## Configuration

Server:

```hcl
NodeAttestor "oci_instance" {
  plugin_cmd      = "/opt/spire/plugins/spire-plugin-oci-server"
  plugin_checksum = "<sha256 from SHA256SUMS>"
  plugin_data {
    trust_bundle_path  = "/run/oci-roots/roots.pem"
    tenancy_allow_list = ["ocid1.tenancy.oc1..…"]
  }
}
```

`tenancy_allow_list` is required. The roots are per region and shared by every OCI customer in
that region, so verifying the chain alone would admit any instance of any tenancy.

Agent:

```hcl
NodeAttestor "oci_instance" {
  plugin_cmd      = "/opt/spire/plugins/spire-plugin-oci-agent"
  plugin_checksum = "<sha256 from SHA256SUMS>"
  plugin_data {}
}
```

## Trust bundle

The regional roots come from
`GET https://auth.<region>.oraclecloud.com/v1/instancePrincipalRootCACertificates`.

- The request must be signed by an authenticated OCI principal (for example
  `oci raw-request`). There is no anonymous download.
- The response's `certificates` are bare base64 DER, not PEM. Wrap each one in
  `-----BEGIN CERTIFICATE-----` lines.
- `refreshIn` in the response asks clients to fetch again daily, so expect roots to rotate.

The server reads the file on every attestation: to rotate roots, replace the file. No restart is needed.

## Releases

Tagged releases attach static `linux/amd64` and `linux/arm64` binaries for both sides, plus
`SHA256SUMS` for `plugin_checksum`.

The same binaries are published as a multi-arch image,
`ghcr.io/panxiao81/spire-plugin-oci:<tag>`, built `FROM scratch` and containing
`/spire-plugin-oci-server` and `/spire-plugin-oci-agent`. On Kubernetes 1.35+ you can mount it
straight into the SPIRE server Pod as an image volume:

```yaml
volumes:
  - name: oci-plugin
    image:
      reference: ghcr.io/panxiao81/spire-plugin-oci:v0.1.1@sha256:…
volumeMounts:
  - name: oci-plugin
    mountPath: /opt/spire/plugins/oci
    readOnly: true
```
