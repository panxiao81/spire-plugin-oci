package main

import (
	"github.com/panxiao81/spire-plugin-oci/oci"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	agentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

func main() {
	p := new(oci.Agent)
	pluginmain.Serve(agentv1.NodeAttestorPluginServer(p), configv1.ConfigServiceServer(p))
}
