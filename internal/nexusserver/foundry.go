package nexusserver

import "github.com/newtype-ai-com/nexus/gate"

// foundryModelEndpoint is gate.FoundryModelEndpoint: the same rule validates
// the startup environment and an operator change of the default model.
func foundryModelEndpoint(raw, protocol string) (string, error) {
	return gate.FoundryModelEndpoint(raw, protocol)
}
