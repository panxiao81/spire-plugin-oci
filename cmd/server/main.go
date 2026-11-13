package main

import (
	"github.com/panxiao81/spire-plugin-oci/oci"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	serverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

func main() {
	p := new(oci.Server)
	pluginmain.Serve(serverv1.NodeAttestorPluginServer(p), configv1.ConfigServiceServer(p))
}
