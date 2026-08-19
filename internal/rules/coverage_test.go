package rules

import (
	"reflect"
	"testing"

	"github.com/gkehren/hemera/pkg/model"
)

func TestRequiredSourcesFollowsConditionBranchesAndDependencies(t *testing.T) {
	t.Parallel()
	httpSource := "http_analyzer"
	browserSource := "browser_analyzer"
	ruleSet := RuleSet{SchemaVersion: CurrentSchemaVersion, Rules: []Rule{
		{
			ID: "dependency", Match: Condition{Signal: &Evidence{
				Type: model.SignalTypeCookie, Source: &TextPattern{Exact: &browserSource},
			}},
		},
		{
			ID: "fixture", Requires: []string{"dependency"},
			Match: Condition{All: []Condition{
				{Signal: &Evidence{Type: model.SignalTypeScriptURL, Source: &TextPattern{Exact: &httpSource}}},
				{Any: []Condition{
					{Signal: &Evidence{Type: model.SignalTypeCookie, Source: &TextPattern{Exact: &browserSource}}},
					{Signal: &Evidence{Type: model.SignalTypeCookie, Source: &TextPattern{Exact: &httpSource}}},
				}},
			}},
		},
	}}
	got := RequiredSources(ruleSet.Rules[1], ruleSet)
	want := []string{"browser_analyzer", "http_analyzer"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RequiredSources() = %#v, want %#v", got, want)
	}

	withoutDependency := ruleSet.Rules[1]
	withoutDependency.Requires = nil
	if got := RequiredSources(withoutDependency, ruleSet); !reflect.DeepEqual(got, []string{"http_analyzer"}) {
		t.Fatalf("alternative source intersection = %#v, want HTTP only", got)
	}
}
