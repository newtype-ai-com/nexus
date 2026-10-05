package main

import (
	"fmt"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
	"strings"
)

// Deliberately emit presence/count and a fixed protocol label, not configurable
// names, endpoints, email, schema, keys or arbitrary strings.
func startupSummary(c nexusserver.Config) string {
	protocol := "disabled"
	models := 0
	if c.ModelConfig != nil {
		protocol = "chat_completions"
		if strings.HasSuffix(c.ModelConfig.Upstream, "/responses") {
			protocol = "responses"
		}
		models = len(c.ModelConfig.Models)
	}
	return fmt.Sprintf("nexus: mode=serve enrolment=%t model=%t sealing=%t owner_configured=%t owner_only=%t model_count=%d model_protocol=%s", c.EnrolmentConfig != nil, c.ModelConfig != nil, c.Sealer != nil, c.OwnerEmail != "", c.OwnerOnly, models, protocol)
}
