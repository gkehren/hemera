package browser

import (
	"testing"
)

func TestEligibleFormIndexes(t *testing.T) {
	t.Parallel()
	eligible := formDescriptor{
		Action: "https://example.test/contact", Method: "POST",
		HasSubmit: true, Fillable: 3,
	}
	tests := []struct {
		name        string
		descriptors []formDescriptor
		finalURL    string
		want        []int
	}{
		{
			name:        "eligible form",
			descriptors: []formDescriptor{eligible},
			finalURL:    "https://example.test/",
			want:        []int{0},
		},
		{
			name:        "cross-origin action rejected",
			descriptors: []formDescriptor{{Action: "https://third.test/contact", HasSubmit: true, Fillable: 1}},
			finalURL:    "https://example.test/",
			want:        nil,
		},
		{
			name:        "scheme downgrade rejected",
			descriptors: []formDescriptor{{Action: "http://example.test/contact", HasSubmit: true, Fillable: 1}},
			finalURL:    "https://example.test/",
			want:        nil,
		},
		{
			name:        "password form rejected",
			descriptors: []formDescriptor{{Action: "https://example.test/contact", HasSubmit: true, Fillable: 2, Password: true}},
			finalURL:    "https://example.test/",
			want:        nil,
		},
		{
			name:        "file upload form rejected",
			descriptors: []formDescriptor{{Action: "https://example.test/contact", HasSubmit: true, Fillable: 2, File: true}},
			finalURL:    "https://example.test/",
			want:        nil,
		},
		{
			name:        "missing submit rejected",
			descriptors: []formDescriptor{{Action: "https://example.test/contact", Fillable: 1}},
			finalURL:    "https://example.test/",
			want:        nil,
		},
		{
			name:        "no fillable fields rejected",
			descriptors: []formDescriptor{{Action: "https://example.test/contact", HasSubmit: true}},
			finalURL:    "https://example.test/",
			want:        nil,
		},
		{
			name:        "too many fields rejected",
			descriptors: []formDescriptor{{Action: "https://example.test/contact", HasSubmit: true, Fillable: maxInspectedFormFields + 1}},
			finalURL:    "https://example.test/",
			want:        nil,
		},
		{
			name:        "login action rejected",
			descriptors: []formDescriptor{{Action: "https://example.test/account/login", HasSubmit: true, Fillable: 1}},
			finalURL:    "https://example.test/",
			want:        nil,
		},
		{
			name:        "register action rejected",
			descriptors: []formDescriptor{{Action: "https://example.test/register", HasSubmit: true, Fillable: 1}},
			finalURL:    "https://example.test/",
			want:        nil,
		},
		{
			name:        "unparseable action rejected",
			descriptors: []formDescriptor{{Action: "not a url", HasSubmit: true, Fillable: 1}},
			finalURL:    "https://example.test/",
			want:        nil,
		},
		{
			name: "budget respected in DOM order",
			descriptors: []formDescriptor{
				{Action: "https://example.test/a", HasSubmit: true, Fillable: 1},
				{Action: "https://example.test/b", HasSubmit: true, Fillable: 1},
			},
			finalURL: "https://example.test/",
			want:     []int{0},
		},
		{
			name:        "invalid final URL rejects everything",
			descriptors: []formDescriptor{eligible},
			finalURL:    "",
			want:        nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := eligibleFormIndexes(test.descriptors, test.finalURL, maxFormSubmissionsPerPage)
			if len(got) != len(test.want) {
				t.Fatalf("eligible = %v, want %v", got, test.want)
			}
			for index := range got {
				if got[index] != test.want[index] {
					t.Fatalf("eligible = %v, want %v", got, test.want)
				}
			}
		})
	}
}

func TestFormSubmissionLogEnforcesBudget(t *testing.T) {
	t.Parallel()
	log := newFormSubmissionLog()
	log.add(FormSubmission{ActionURL: "https://example.test/first", Method: "POST"})
	log.add(FormSubmission{ActionURL: "https://example.test/second", Method: "POST"})
	snapshot := log.snapshot()
	if len(snapshot) != 1 || snapshot[0].ActionURL != "https://example.test/first" {
		t.Fatalf("snapshot = %#v, want only the first submission", snapshot)
	}
	snapshot[0].ActionURL = "changed"
	if log.snapshot()[0].ActionURL == "changed" {
		t.Error("snapshot is not an independent copy")
	}
}

func TestNormalizeCaptureEmitsInteractionSignals(t *testing.T) {
	t.Parallel()
	result := CaptureResult{
		FinalURL: "https://example.test/",
		Requests: []CaptureRequest{
			{Method: "GET", URL: "https://example.test/"},
			{Method: "POST", URL: "https://api.example.test/submit"},
		},
		Responses: []CaptureResponse{{URL: "https://example.test/", Status: 200}},
		Transactions: []CaptureTransaction{
			{Method: "GET", URL: "https://example.test/", Status: 200},
			{Method: "POST", URL: "https://api.example.test/submit", Status: 403, Protocol: "h2"},
			{Method: "POST", URL: "https://api.example.test/pending"},
		},
		FormSubmissions: []FormSubmission{{ActionURL: "https://example.test/contact", Method: "POST"}},
	}
	signals, err := normalizeCapture(result)
	if err != nil {
		t.Fatal(err)
	}
	var transactions, submissions int
	for _, signal := range signals {
		switch signal.Type {
		case "network_transaction":
			transactions++
			if signal.Key != "POST" || signal.Value != "403" || signal.URL != "https://api.example.test/submit" {
				t.Errorf("transaction signal = %#v, want the correlated denied POST", signal)
			}
		case "form_submission":
			submissions++
			if signal.Key != "action" || signal.Value != "https://example.test/contact" {
				t.Errorf("form submission signal = %#v, want the cleaned action URL", signal)
			}
		}
	}
	if transactions != 1 {
		t.Errorf("network_transaction signals = %d, want only the non-GET with status", transactions)
	}
	if submissions != 1 {
		t.Errorf("form_submission signals = %d, want 1", submissions)
	}
}
