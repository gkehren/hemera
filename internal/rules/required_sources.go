package rules

import "sort"

// RequiredSources returns the analyzer-independent signal sources that every
// successful branch of a rule requires. Sources used by only one alternative
// of an any condition are not mandatory.
func RequiredSources(rule Rule, ruleSet RuleSet) []string {
	byID := make(map[string]Rule, len(ruleSet.Rules))
	for _, candidate := range ruleSet.Rules {
		byID[candidate.ID] = candidate
	}
	visiting := make(map[string]bool)
	var required func(Rule) map[string]struct{}
	required = func(current Rule) map[string]struct{} {
		if visiting[current.ID] {
			return nil
		}
		visiting[current.ID] = true
		sources := conditionRequiredSources(current.Match)
		for _, dependency := range current.Requires {
			for source := range required(byID[dependency]) {
				sources[source] = struct{}{}
			}
		}
		delete(visiting, current.ID)
		return sources
	}
	sources := required(rule)
	result := make([]string, 0, len(sources))
	for source := range sources {
		result = append(result, source)
	}
	sort.Strings(result)
	return result
}

func conditionRequiredSources(condition Condition) map[string]struct{} {
	if condition.Signal != nil {
		result := make(map[string]struct{})
		if pattern := condition.Signal.Source; pattern != nil && pattern.Exact != nil {
			result[*pattern.Exact] = struct{}{}
		}
		return result
	}
	children := condition.All
	intersection := false
	if len(condition.Any) > 0 {
		children = condition.Any
		intersection = true
	}
	result := make(map[string]struct{})
	for index, child := range children {
		childSources := conditionRequiredSources(child)
		if intersection && index > 0 {
			for source := range result {
				if _, ok := childSources[source]; !ok {
					delete(result, source)
				}
			}
			continue
		}
		for source := range childSources {
			result[source] = struct{}{}
		}
	}
	return result
}
