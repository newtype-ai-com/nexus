package gate

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// FoundryModelEndpoint selects the resource-scoped OpenAI v1 inference route.
// A Foundry project URL is not itself a model endpoint. The resource key is
// sent as Bearer on this v1 route, not to the project/Agents API.
// No network discovery, host rewrite, or credential-dependent request is made.
// It is the single rule for the startup environment (MS_FOUNDRY_PROJECT_ENDPOINT)
// and for an operator change of the default model.
func FoundryModelEndpoint(raw, protocol string) (string, error) {
	invalid := errors.New("invalid MS_FOUNDRY_PROJECT_ENDPOINT or MODEL_PROTOCOL")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Port() != "" || u.RawPath != "" || strings.Contains(raw, "#") {
		return "", invalid
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.(services\.ai\.azure\.com|openai\.azure\.com)$`).MatchString(u.Host) {
		return "", invalid
	}
	path := strings.TrimSuffix(u.Path, "/")
	project := regexp.MustCompile(`^/api/projects/[A-Za-z0-9][A-Za-z0-9._-]*$`).MatchString(path)
	if path != "" && path != "/openai" && path != "/openai/v1" && !(project && strings.HasSuffix(u.Host, ".services.ai.azure.com")) {
		return "", invalid
	}
	switch protocol {
	case "", "chat/completions":
		u.Path = "/openai/v1/chat/completions"
	case "responses":
		u.Path = "/openai/v1/responses"
	default:
		return "", invalid
	}
	return u.String(), nil
}
