package console

import (
	"github.com/chenyme/grok2api/backend/internal/domain/account"
	modeldomain "github.com/chenyme/grok2api/backend/internal/domain/model"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

const (
	quotaModePrefix    = "console:"
	DefaultQuotaLimit  = 20
	DefaultQuotaWindow = 3600
)

type ModelSpec struct {
	PublicID               string
	UpstreamModel          string
	QuotaModel             string
	SupportsReasoning      bool
	DefaultReasoningEffort string
	MaxOutputTokens        int
	SearchTools            bool
}

var catalog = []ModelSpec{
	{PublicID: "grok-4.3", UpstreamModel: "grok-4.3", SupportsReasoning: true, DefaultReasoningEffort: "medium", MaxOutputTokens: 1_000_000, SearchTools: true},
	// xAI documents grok-4.20-0309 as an alias of the dated reasoning model.
	// Keep the accepted request ID, but share its quota and rate-limit state.
	{PublicID: "grok-4.20-0309", UpstreamModel: "grok-4.20-0309", QuotaModel: "grok-4.20-0309-reasoning", MaxOutputTokens: 1_000_000, SearchTools: true},
	{PublicID: "grok-4.20-0309-reasoning", UpstreamModel: "grok-4.20-0309-reasoning", SupportsReasoning: true, MaxOutputTokens: 1_000_000, SearchTools: true},
	{PublicID: "grok-4.20-0309-non-reasoning", UpstreamModel: "grok-4.20-0309-non-reasoning", MaxOutputTokens: 1_000_000, SearchTools: true},
	{PublicID: "grok-4.20-multi-agent-0309", UpstreamModel: "grok-4.20-multi-agent-0309", SupportsReasoning: true, DefaultReasoningEffort: "medium", MaxOutputTokens: 2_000_000, SearchTools: true},
	{PublicID: "grok-build-0.1", UpstreamModel: "grok-build-0.1", MaxOutputTokens: 256_000, SearchTools: true},
}

// Effort-suffixed aliases only include levels each model actually supports
// (see domain/model.SupportedReasoningEfforts). No blanket none/low/medium/high/xhigh/max template.
var aliases = []provider.ModelAlias{
	consoleAlias("grok-4.3-console", "grok-4.3", "grok-4.3", ""),
	consoleAlias("grok-4.20-0309-console", "grok-4.20-0309", "grok-4.20-0309", ""),
	consoleAlias("grok-4.20-0309-reasoning-console", "grok-4.20-0309-reasoning", "grok-4.20-0309-reasoning", ""),
	consoleAlias("grok-4.20-0309-non-reasoning-console", "grok-4.20-0309-non-reasoning", "grok-4.20-0309-non-reasoning", ""),
	consoleAlias("grok-4.20-multi-agent-console", "grok-4.20-multi-agent-0309", "grok-4.20-multi-agent-0309", ""),
	consoleAlias("grok-build-console", "grok-build-0.1", "grok-build-0.1", ""),
	consoleAlias("grok-4.3-low", "grok-4.3", "grok-4.3", "low"),
	consoleAlias("grok-4.3-medium", "grok-4.3", "grok-4.3", "medium"),
	consoleAlias("grok-4.3-high", "grok-4.3", "grok-4.3", "high"),
	consoleAlias("grok-4.20-multi-agent-low", "grok-4.20-multi-agent-0309", "grok-4.20-multi-agent-0309", "low"),
	consoleAlias("grok-4.20-multi-agent-medium", "grok-4.20-multi-agent-0309", "grok-4.20-multi-agent-0309", "medium"),
	consoleAlias("grok-4.20-multi-agent-high", "grok-4.20-multi-agent-0309", "grok-4.20-multi-agent-0309", "high"),
	consoleAlias("grok-4.20-multi-agent-xhigh", "grok-4.20-multi-agent-0309", "grok-4.20-multi-agent-0309", "xhigh"),
}

func consoleAlias(alias, publicModel, upstreamModel, effort string) provider.ModelAlias {
	canonical, _ := modeldomain.NormalizePublicID(account.ProviderConsole, publicModel)
	return provider.ModelAlias{
		Alias: alias, PublicModel: canonical, Provider: account.ProviderConsole,
		UpstreamModel: upstreamModel, ReasoningEffort: effort,
	}
}

func Catalog() []ModelSpec { return append([]ModelSpec(nil), catalog...) }

func Routes() []modeldomain.Route {
	values := make([]modeldomain.Route, 0, len(catalog))
	for _, spec := range catalog {
		publicID, _ := modeldomain.NormalizePublicID(account.ProviderConsole, spec.PublicID)
		values = append(values, modeldomain.Route{
			PublicID: publicID, Provider: account.ProviderConsole, UpstreamModel: spec.UpstreamModel,
			Capability: modeldomain.CapabilityResponses, Enabled: true,
		})
	}
	return values
}

func Resolve(upstreamModel string) (ModelSpec, bool) {
	for _, spec := range catalog {
		if spec.UpstreamModel == upstreamModel {
			return spec, true
		}
	}
	return ModelSpec{}, false
}

func quotaModeForModel(upstreamModel string) string {
	if spec, ok := Resolve(upstreamModel); ok {
		model := spec.QuotaModel
		if model == "" {
			model = spec.UpstreamModel
		}
		return quotaModePrefix + model
	}
	return ""
}

// QuotaModes returns one stable window per real upstream model. Accepted
// aliases that resolve to the same model intentionally share a window.
func QuotaModes() []string {
	seen := make(map[string]struct{}, len(catalog))
	values := make([]string, 0, len(catalog))
	for _, spec := range catalog {
		mode := quotaModeForModel(spec.UpstreamModel)
		if mode == "" {
			continue
		}
		if _, exists := seen[mode]; exists {
			continue
		}
		seen[mode] = struct{}{}
		values = append(values, mode)
	}
	return values
}

func resolveQuotaMode(mode string) (ModelSpec, bool) {
	for _, spec := range catalog {
		if quotaModeForModel(spec.UpstreamModel) == mode {
			return spec, true
		}
	}
	return ModelSpec{}, false
}

func Aliases() []provider.ModelAlias { return append([]provider.ModelAlias(nil), aliases...) }
