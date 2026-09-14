package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/chromedp/cdproto/page"
	cdpruntime "github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

const (
	// maxInspectedForms bounds how many forms the inspector enumerates.
	maxInspectedForms = 32
	// maxInspectedFormFields bounds how many fields are counted per form.
	maxInspectedFormFields = 32
	// maxFormSubmissionsPerPage is the hard ceiling on submissions triggered
	// during one navigation. Exactly one form is submitted, once, without
	// retries; further submissions would require re-navigation and effectively
	// turn Hemera into a crawler.
	maxFormSubmissionsPerPage = 1
)

// FormSubmission records one bounded form submission performed during a
// navigation. Only the already-cleaned action URL and the method are retained;
// field names, field values, and submitted data are never collected.
type FormSubmission struct {
	ActionURL string
	Method    string
}

// formSubmissionLog is a session-scoped sink for submissions performed while a
// navigation was active. It never leaves the browser package un-minimized.
type formSubmissionLog struct {
	mu     sync.Mutex
	values []FormSubmission
}

func newFormSubmissionLog() *formSubmissionLog {
	return &formSubmissionLog{}
}

func (l *formSubmissionLog) add(value FormSubmission) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.values) >= maxFormSubmissionsPerPage {
		return
	}
	l.values = append(l.values, value)
}

func (l *formSubmissionLog) snapshot() []FormSubmission {
	l.mu.Lock()
	defer l.mu.Unlock()
	values := make([]FormSubmission, len(l.values))
	copy(values, l.values)
	return values
}

// formDescriptor is the bounded inspection result for one HTML form. It is an
// intermediate analysis value and never leaves the browser package.
type formDescriptor struct {
	Action    string         `json:"action"`
	Method    string         `json:"method"`
	Fields    map[string]int `json:"fields"`
	HasSubmit bool           `json:"has_submit"`
	Password  bool           `json:"password"`
	File      bool           `json:"file"`
	Fillable  int            `json:"fillable"`
}

type formInspection struct {
	Forms     []formDescriptor `json:"forms"`
	Truncated bool             `json:"truncated"`
}

// boundedFormInspector enumerates forms with bounded work inside an isolated
// world. It only counts field types and reads the resolved action URL; it
// never reads field names or values.
const boundedFormInspector = `(() => {
  "use strict";
  const maxForms = %d;
  const maxFields = %d;
  const fillable = new Set(["text", "search", "email", "url", "tel", "number", "date", "time", "datetime-local", "month", "week", "range", "select-one", "textarea"]);
  const forms = [];
  let truncated = false;
  for (const form of document.forms) {
    if (forms.length >= maxForms) {
      truncated = true;
      break;
    }
    const descriptor = {
      action: String(form.action || ""),
      method: String(form.getAttribute("method") || "get").toUpperCase(),
      fields: {},
      has_submit: false,
      password: false,
      file: false,
      fillable: 0
    };
    let counted = 0;
    for (const element of form.elements) {
      if (counted >= maxFields) {
        truncated = true;
        break;
      }
      counted++;
      const tag = String(element.tagName || "").toLowerCase();
      const type = String(element.type || "").toLowerCase();
      descriptor.fields[type] = (descriptor.fields[type] || 0) + 1;
      if (type === "password") descriptor.password = true;
      if (type === "file") descriptor.file = true;
      if (fillable.has(type) || (tag === "textarea" || tag === "select")) descriptor.fillable++;
      if ((tag === "input" && (type === "submit" || type === "image")) ||
          (tag === "button" && (!type || type === "submit"))) {
        descriptor.has_submit = true;
      }
    }
    forms.push(descriptor);
  }
  return JSON.stringify({forms: forms, truncated: truncated});
})()`

// boundedFormSubmitter fills one form with fixed benign synthetic values and
// submits it like a normal user action. Hidden fields are left untouched so
// anti-CSRF tokens keep working; password and file inputs are never touched.
const boundedFormSubmitter = `(() => {
  "use strict";
  const maxFields = %d;
  const form = document.forms[%d];
  if (!form) {
    return JSON.stringify({submitted: false, reason: "missing"});
  }
  const synthetic = {
    text: "Hemera scan observation",
    search: "hemera scan",
    email: "hemera-scan@example.invalid",
    url: "https://example.invalid/",
    tel: "555-0100",
    number: "1",
    date: "2026-01-01",
    time: "12:00",
    "datetime-local": "2026-01-01T12:00",
    month: "2026-01",
    week: "2026-W01"
  };
  const seenRadios = new Set();
  let filled = 0;
  for (const element of form.elements) {
    if (filled >= maxFields) {
      break;
    }
    const tag = String(element.tagName || "").toLowerCase();
    const type = String(element.type || "").toLowerCase();
    if (type === "hidden" || type === "password" || type === "file" ||
        type === "submit" || type === "image" || type === "button" || type === "reset") {
      continue;
    }
    if (tag === "textarea") {
      if (!element.value) {
        element.value = "Hemera scan observation.";
        filled++;
      }
      continue;
    }
    if (tag === "select") {
      if (element.options && element.options.length > 0) {
        element.selectedIndex = 0;
        filled++;
      }
      continue;
    }
    if (type === "checkbox") {
      if (!element.checked) {
        element.checked = true;
        filled++;
      }
      continue;
    }
    if (type === "radio") {
      if (!seenRadios.has(element.name) && !element.checked) {
        seenRadios.add(element.name);
        element.checked = true;
        filled++;
      }
      continue;
    }
    if (synthetic[type] !== undefined && !element.value) {
      element.value = synthetic[type];
      filled++;
    }
  }
  const submitter = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
  if (submitter) {
    submitter.click();
  } else if (form.requestSubmit) {
    form.requestSubmit();
  } else {
    form.submit();
  }
  return JSON.stringify({submitted: true, filled: filled});
})()`

// submitBoundedForm runs the bounded interaction phase for one navigation:
// inspect forms on the settled page, pick the first eligible form, fill it
// with fixed synthetic values, and submit it exactly once. A context
// destruction right after submission means the navigation started, which is a
// successful outcome. All budget and fetch-interception enforcement stays
// active because the phase runs inside the navigation lifecycle.
func submitBoundedForm(taskCtx, runCtx context.Context, finalURL string, log *formSubmissionLog) error {
	var inspectionJSON string
	inspect := fmt.Sprintf(boundedFormInspector, maxInspectedForms, maxInspectedFormFields)
	if err := evaluateBoundedFormJS(taskCtx, runCtx, inspect, &inspectionJSON); err != nil {
		return fmt.Errorf("inspect forms: %w", err)
	}
	var inspection formInspection
	if err := json.Unmarshal([]byte(inspectionJSON), &inspection); err != nil {
		return fmt.Errorf("decode form inspection: %w", err)
	}
	if inspection.Truncated {
		return nil
	}
	eligible := eligibleFormIndexes(inspection.Forms, finalURL, maxFormSubmissionsPerPage)
	if len(eligible) == 0 {
		return nil
	}
	descriptor := inspection.Forms[eligible[0]]
	// A throwaway collector performs the same URL minimization as the
	// capture boundary; its warnings are intentionally discarded.
	actionURL, ok := newCaptureCollector().cleanURL(descriptor.Action)
	if !ok || !sameOrigin(finalURL, actionURL) {
		return nil
	}
	method := strings.ToUpper(strings.TrimSpace(descriptor.Method))
	if method == "" {
		method = "GET"
	}

	submit := fmt.Sprintf(boundedFormSubmitter, maxInspectedFormFields, eligible[0])
	var submitJSON string
	submitErr := evaluateBoundedFormJS(taskCtx, runCtx, submit, &submitJSON)
	if submitErr != nil && !isTransientDOMContextError(submitErr) {
		return fmt.Errorf("submit form: %w", submitErr)
	}
	if submitErr == nil {
		var outcome struct {
			Submitted bool   `json:"submitted"`
			Reason    string `json:"reason"`
		}
		if err := json.Unmarshal([]byte(submitJSON), &outcome); err == nil && !outcome.Submitted {
			return nil
		}
	}
	log.add(FormSubmission{ActionURL: actionURL, Method: method})
	return nil
}

// evaluateBoundedFormJS evaluates one bounded form expression in an isolated
// world on the current main frame and decodes the returned JSON string.
func evaluateBoundedFormJS(taskCtx, runCtx context.Context, expression string, result *string) error {
	return runChromedpWithCaller(taskCtx, runCtx, chromedp.ActionFunc(func(actionCtx context.Context) error {
		frame, err := currentMainFrame(actionCtx)
		if err != nil {
			return err
		}
		contextID, err := page.CreateIsolatedWorld(frame.frameID).
			WithWorldName("hemera-bounded-forms").
			Do(actionCtx)
		if err != nil {
			return fmt.Errorf("Page.createIsolatedWorld: %w", err)
		}
		value, exception, err := cdpruntime.Evaluate(expression).
			WithContextID(contextID).
			WithReturnByValue(true).
			WithSilent(true).
			WithDisableBreaks(true).
			Do(actionCtx)
		if err != nil {
			return fmt.Errorf("Runtime.evaluate bounded form expression: %w", err)
		}
		if exception != nil {
			return formatBoundedDOMException(exception)
		}
		if value == nil || len(value.Value) == 0 {
			return errors.New("bounded form expression returned no value")
		}
		return json.Unmarshal(value.Value, result)
	}))
}

// eligibleFormIndexes returns the indexes of forms Hemera may submit, in DOM
// order, up to the per-navigation budget. Eligibility is deliberately
// conservative: same-origin http(s) actions only, no credential or upload
// forms, no auth-suggesting paths, and at least one fillable field.
func eligibleFormIndexes(descriptors []formDescriptor, finalURL string, budget int) []int {
	base, err := url.Parse(finalURL)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil
	}
	var eligible []int
	for index, descriptor := range descriptors {
		if len(eligible) >= budget {
			return eligible
		}
		if descriptor.Password || descriptor.File || !descriptor.HasSubmit {
			continue
		}
		if descriptor.Fillable == 0 || descriptor.Fillable > maxInspectedFormFields {
			continue
		}
		action, err := url.Parse(descriptor.Action)
		if err != nil || action.Host == "" {
			continue
		}
		if action.Scheme != base.Scheme || action.Host != base.Host {
			continue
		}
		if authSuggestingPath(action.Path) {
			continue
		}
		eligible = append(eligible, index)
	}
	return eligible
}

// authSuggestingPath reports whether a path looks like a credential flow.
// Hemera never submits such forms, so it can never perform credential attacks
// or create accounts.
func authSuggestingPath(path string) bool {
	lower := strings.ToLower(path)
	for _, marker := range []string{
		"login", "log-in", "log_in", "signin", "sign-in", "sign_in",
		"signup", "sign-up", "sign_up", "register", "registration",
		"passwd", "password", "credential", "token", "oauth", "auth", "session",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
