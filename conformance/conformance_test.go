package conformance_test

import (
	"github.com/newtype-ai-com/nexus/conformance"
	"github.com/newtype-ai-com/nexus/nexus"
	"testing"
)

func TestMemory(t *testing.T) { conformance.Run(t, func() nexus.Store { return nexus.NewMemStore() }) }
func TestMemoryRetried(t *testing.T) {
	conformance.Run(t, func() nexus.Store { return conformance.Retrying{Store: nexus.NewMemStore()} })
}
