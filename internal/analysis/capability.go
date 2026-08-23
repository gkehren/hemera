package analysis

import (
	"sort"

	"github.com/gkehren/hemera/pkg/model"
)

// Capability identifies one normalized signal type implemented by a stable
// observation source. It describes static producer support, not whether that
// capability was observed completely during a particular scan.
type Capability struct {
	Source     string
	SignalType model.SignalType
}

var implementedCapabilities = []Capability{
	{Source: SourceBrowser, SignalType: model.SignalTypeCookie},
	{Source: SourceBrowser, SignalType: model.SignalTypeIframeURL},
	{Source: SourceBrowser, SignalType: model.SignalTypeNetworkRequest},
	{Source: SourceBrowser, SignalType: model.SignalTypeNetworkResponse},
	{Source: SourceBrowser, SignalType: model.SignalTypePageContent},
	{Source: SourceBrowser, SignalType: model.SignalTypeScriptURL},
	{Source: SourceDNSTLS, SignalType: model.SignalTypeDNSRecord},
	{Source: SourceDNSTLS, SignalType: model.SignalTypeTLSProperty},
	{Source: SourceHTTP, SignalType: model.SignalTypeCookie},
	{Source: SourceHTTP, SignalType: model.SignalTypeIframeURL},
	{Source: SourceHTTP, SignalType: model.SignalTypeNetworkResponse},
	{Source: SourceHTTP, SignalType: model.SignalTypePageContent},
	{Source: SourceHTTP, SignalType: model.SignalTypeRedirect},
	{Source: SourceHTTP, SignalType: model.SignalTypeResourceHost},
	{Source: SourceHTTP, SignalType: model.SignalTypeResponseHeader},
	{Source: SourceHTTP, SignalType: model.SignalTypeScriptURL},
}

// ImplementedCapabilities returns the current production source/signal support
// contract in stable source and signal-type order. The returned slice is a copy.
func ImplementedCapabilities() []Capability {
	capabilities := append([]Capability{}, implementedCapabilities...)
	sort.Slice(capabilities, func(i, j int) bool {
		if capabilities[i].Source != capabilities[j].Source {
			return capabilities[i].Source < capabilities[j].Source
		}
		return capabilities[i].SignalType < capabilities[j].SignalType
	})
	return capabilities
}

// SupportedSignalTypes returns the signal types implemented by source in stable
// order. Types present in the common model but not emitted by that production
// source are intentionally omitted.
func SupportedSignalTypes(source string) []model.SignalType {
	var signalTypes []model.SignalType
	for _, capability := range implementedCapabilities {
		if capability.Source == source {
			signalTypes = append(signalTypes, capability.SignalType)
		}
	}
	sort.Slice(signalTypes, func(i, j int) bool { return signalTypes[i] < signalTypes[j] })
	return signalTypes
}
