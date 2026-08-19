package browser

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

const (
	fixtureManifestPath  = "testdata/cases.json"
	maxFixtureFileBytes  = 64 << 10
	maxFixtureTotalBytes = 256 << 10
)

var allowedFixtureBehaviors = map[string]struct{}{
	"completion-barrier":  {},
	"compressed-response": {},
	"redirect-loop":       {},
	"credential-redirect": {},
	"large-response":      {},
	"large-worker-script": {},
	"long-poll":           {},
	"held-resource":       {},
	"slow-response":       {},
	"private-subresource": {},
	"private-trap":        {},
}

type fixtureManifest struct {
	SchemaVersion int            `json:"schema_version"`
	Host          string         `json:"host"`
	Routes        []fixtureRoute `json:"routes"`
	Cases         []fixtureCase  `json:"cases"`
}

type fixtureRoute struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	RawQuery      string `json:"raw_query,omitempty"`
	Status        int    `json:"status"`
	ContentType   string `json:"content_type,omitempty"`
	Authorization string `json:"expected_authorization,omitempty"`
	File          string `json:"file,omitempty"`
	RedirectTo    string `json:"redirect_to,omitempty"`
	Behavior      string `json:"behavior,omitempty"`
	data          []byte
}

type fixtureCase struct {
	Name               string   `json:"name"`
	EntryRoute         string   `json:"entry_route"`
	FinalRoute         string   `json:"final_route"`
	CompletionSelector string   `json:"completion_selector"`
	DOMMarkers         []string `json:"dom_markers"`
	Traffic            []string `json:"traffic"`
	Scripts            []string `json:"scripts"`
	Iframes            []string `json:"iframes"`
	Cookies            []string `json:"cookies"`
	ForbiddenMetadata  []string `json:"forbidden_metadata"`
}

type fixtureCorpus struct {
	manifest fixtureManifest
	routes   map[string]*fixtureRoute
	byName   map[string]*fixtureRoute
}

type fixtureServer struct {
	corpus     *fixtureCorpus
	server     *httptest.Server
	baseURL    string
	behaviors  map[string]http.HandlerFunc
	mu         sync.Mutex
	requests   []string
	unexpected []string
}

func TestBrowserFixtureCorpus(t *testing.T) {
	t.Parallel()
	corpus, err := loadFixtureCorpus(fixtureManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus.manifest.Cases) < 2 {
		t.Fatalf("fixture cases = %d, want at least 2", len(corpus.manifest.Cases))
	}
	var total int64
	err = filepath.WalkDir(filepath.Dir(fixtureManifestPath), func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("fixture corpus contains symlink %q", filePath)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxFixtureFileBytes {
			return fmt.Errorf("fixture file %q exceeds %d bytes", filePath, maxFixtureFileBytes)
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if total > maxFixtureTotalBytes {
		t.Fatalf("fixture assets = %d bytes, want at most %d", total, maxFixtureTotalBytes)
	}
	for _, name := range []string{"dynamic-sequential", "static-negative"} {
		if _, ok := corpus.caseByName(name); !ok {
			t.Errorf("fixture case %q is missing", name)
		}
	}
}

func TestBrowserFixtureValidationRejectsUnsafeInputs(t *testing.T) {
	t.Parallel()
	corpus := &fixtureCorpus{}
	valid := fixtureRoute{Name: "valid", Path: "/valid", Status: http.StatusOK, ContentType: "text/plain", File: "valid.txt"}
	tests := []struct {
		name   string
		mutate func(*fixtureRoute)
	}{
		{"traversing route", func(route *fixtureRoute) { route.Path = "/safe/../outside" }},
		{"traversing asset", func(route *fixtureRoute) { route.File = "../outside.txt" }},
		{"absolute redirect", func(route *fixtureRoute) {
			route.File = ""
			route.Status = http.StatusFound
			route.RedirectTo = "https://outside.test/"
		}},
		{"unknown behavior", func(route *fixtureRoute) { route.File = ""; route.Behavior = "external-network" }},
		{"header injection", func(route *fixtureRoute) { route.ContentType = "text/plain\r\nX-Test: unsafe" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			route := valid
			test.mutate(&route)
			if err := corpus.validateRoute(&route); err == nil {
				t.Fatalf("validateRoute(%#v) error = nil", route)
			}
		})
	}
	for _, reference := range []string{
		"http://outside.test/a.js",
		"HTTPS://outside.test/a.js",
		"//outside.test/a.js",
		`src="//outside.test/a.js"`,
	} {
		if !containsExternalWebReference(reference) {
			t.Errorf("external web reference %q was accepted", reference)
		}
	}
	if containsExternalWebReference("// synthetic JavaScript comment") {
		t.Error("ordinary JavaScript comment was treated as an external web reference")
	}
}

func TestBrowserFixtureServerRejectsUnexpectedRequests(t *testing.T) {
	t.Parallel()
	corpus, err := loadFixtureCorpus(fixtureManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &fixtureServer{corpus: corpus}
	tests := []struct {
		name string
		host string
		path string
	}{
		{"unexpected host", "outside.test", "/negative/page"},
		{"unexpected route", corpus.manifest.Host, "/undeclared"},
	}
	for _, test := range tests {
		request := httptest.NewRequest(http.MethodGet, "http://"+test.host+test.path, nil)
		request.Host = test.host
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Errorf("%s status = %d, want %d", test.name, response.Code, http.StatusNotFound)
		}
	}
	served, unexpected := server.snapshot()
	if len(served) != 0 || len(unexpected) != len(tests) {
		t.Fatalf("served=%#v unexpected=%#v, want no served routes and %d rejections", served, unexpected, len(tests))
	}
}

func loadFixtureCorpus(manifestPath string) (*fixtureCorpus, error) {
	root := filepath.Dir(manifestPath)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read browser fixture manifest: %w", err)
	}
	if len(manifestData) > maxFixtureFileBytes {
		return nil, fmt.Errorf("browser fixture manifest exceeds %d bytes", maxFixtureFileBytes)
	}
	decoder := json.NewDecoder(strings.NewReader(string(manifestData)))
	decoder.DisallowUnknownFields()
	var manifest fixtureManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode browser fixture manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("browser fixture manifest must contain exactly one JSON value")
	}
	if manifest.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported browser fixture schema_version %d", manifest.SchemaVersion)
	}
	if manifest.Host != "fixture.test" {
		return nil, fmt.Errorf("browser fixture host = %q, want fixture.test", manifest.Host)
	}
	if len(manifest.Routes) == 0 || len(manifest.Cases) == 0 {
		return nil, errors.New("browser fixture routes and cases are required")
	}

	corpus := &fixtureCorpus{
		manifest: manifest,
		routes:   make(map[string]*fixtureRoute, len(manifest.Routes)),
		byName:   make(map[string]*fixtureRoute, len(manifest.Routes)),
	}
	total := 0
	for index := range corpus.manifest.Routes {
		route := &corpus.manifest.Routes[index]
		if err := corpus.validateRoute(route); err != nil {
			return nil, fmt.Errorf("route %d: %w", index, err)
		}
		key := routeKey(route.Path, route.RawQuery)
		if _, exists := corpus.routes[key]; exists {
			return nil, fmt.Errorf("duplicate browser fixture route %q", key)
		}
		if _, exists := corpus.byName[route.Name]; exists {
			return nil, fmt.Errorf("duplicate browser fixture route name %q", route.Name)
		}
		if route.File != "" {
			assetPath := filepath.Join(root, filepath.FromSlash(route.File))
			info, err := os.Lstat(assetPath)
			if err != nil {
				return nil, fmt.Errorf("inspect route %q asset: %w", route.Name, err)
			}
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("route %q asset is not a regular file", route.Name)
			}
			data, err := os.ReadFile(assetPath)
			if err != nil {
				return nil, fmt.Errorf("read route %q asset: %w", route.Name, err)
			}
			if len(data) > maxFixtureFileBytes {
				return nil, fmt.Errorf("route %q asset exceeds %d bytes", route.Name, maxFixtureFileBytes)
			}
			if !utf8.Valid(data) {
				return nil, fmt.Errorf("route %q asset is not valid UTF-8", route.Name)
			}
			if containsExternalWebReference(string(data)) {
				return nil, fmt.Errorf("route %q asset contains an absolute or protocol-relative HTTP(S) reference", route.Name)
			}
			route.data = data
			total += len(data)
		}
		corpus.routes[key] = route
		corpus.byName[route.Name] = route
	}
	if total > maxFixtureTotalBytes {
		return nil, fmt.Errorf("browser fixture corpus exceeds %d bytes", maxFixtureTotalBytes)
	}
	for _, route := range corpus.manifest.Routes {
		if route.RedirectTo == "" {
			continue
		}
		redirect, _ := url.Parse(route.RedirectTo)
		if _, ok := corpus.routes[routeKey(redirect.Path, redirect.RawQuery)]; !ok {
			return nil, fmt.Errorf("route %q redirects to undeclared fixture route %q", route.Name, route.RedirectTo)
		}
	}
	if err := corpus.validateCases(); err != nil {
		return nil, err
	}
	return corpus, nil
}

func (c *fixtureCorpus) validateRoute(route *fixtureRoute) error {
	if route.Name == "" || strings.TrimSpace(route.Name) != route.Name || strings.ContainsAny(route.Name, "\r\n\x00") {
		return errors.New("route name is required without surrounding whitespace")
	}
	if route.Path == "" || !strings.HasPrefix(route.Path, "/") || path.Clean(route.Path) != route.Path || strings.Contains(route.Path, "\\") {
		return fmt.Errorf("route %q has an unsafe path %q", route.Name, route.Path)
	}
	if strings.ContainsAny(route.RawQuery, "#\r\n") {
		return fmt.Errorf("route %q has an unsafe raw query", route.Name)
	}
	if route.Status < 200 || route.Status > 399 {
		return fmt.Errorf("route %q has unsupported status %d", route.Name, route.Status)
	}
	kinds := 0
	if route.File != "" {
		kinds++
		clean := path.Clean(route.File)
		if clean != route.File || clean == "." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) || strings.Contains(route.File, "\\") {
			return fmt.Errorf("route %q has an unsafe asset path %q", route.Name, route.File)
		}
	}
	if route.RedirectTo != "" {
		kinds++
		redirect, err := url.Parse(route.RedirectTo)
		if err != nil || route.Status < 300 || redirect.IsAbs() || redirect.Host != "" || !strings.HasPrefix(redirect.Path, "/") || path.Clean(redirect.Path) != redirect.Path {
			return fmt.Errorf("route %q has an unsafe redirect destination %q", route.Name, route.RedirectTo)
		}
	}
	if route.Behavior != "" {
		kinds++
		if _, ok := allowedFixtureBehaviors[route.Behavior]; !ok {
			return fmt.Errorf("route %q has unknown behavior %q", route.Name, route.Behavior)
		}
	}
	if kinds != 1 {
		return fmt.Errorf("route %q must declare exactly one file, redirect, or behavior", route.Name)
	}
	if route.RedirectTo == "" && route.ContentType == "" {
		return fmt.Errorf("route %q has no content type", route.Name)
	}
	if strings.ContainsAny(route.ContentType, "\r\n\x00") {
		return fmt.Errorf("route %q has an unsafe content type", route.Name)
	}
	if strings.ContainsAny(route.Authorization, "\r\n\x00") {
		return fmt.Errorf("route %q has an unsafe authorization expectation", route.Name)
	}
	return nil
}

func (c *fixtureCorpus) validateCases() error {
	seen := make(map[string]struct{}, len(c.manifest.Cases))
	for index, fixtureCase := range c.manifest.Cases {
		if fixtureCase.Name == "" || fixtureCase.CompletionSelector == "" || len(fixtureCase.DOMMarkers) == 0 || len(fixtureCase.Traffic) == 0 {
			return fmt.Errorf("case %d is missing required capture expectations", index)
		}
		if _, exists := seen[fixtureCase.Name]; exists {
			return fmt.Errorf("duplicate browser fixture case %q", fixtureCase.Name)
		}
		seen[fixtureCase.Name] = struct{}{}
		for _, routeName := range append([]string{fixtureCase.EntryRoute, fixtureCase.FinalRoute}, fixtureCase.Traffic...) {
			if _, exists := c.byName[routeName]; !exists {
				return fmt.Errorf("case %q references unknown route %q", fixtureCase.Name, routeName)
			}
		}
		if fixtureCase.Traffic[0] != fixtureCase.EntryRoute {
			return fmt.Errorf("case %q traffic does not start with its entry route", fixtureCase.Name)
		}
		for _, collection := range [][]string{fixtureCase.DOMMarkers, fixtureCase.Scripts, fixtureCase.Iframes, fixtureCase.Cookies, fixtureCase.ForbiddenMetadata} {
			for _, value := range collection {
				if value == "" || !utf8.ValidString(value) {
					return fmt.Errorf("case %q contains an empty or invalid expectation", fixtureCase.Name)
				}
			}
		}
	}
	return nil
}

func containsExternalWebReference(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "http://") || strings.Contains(lower, "https://") {
		return true
	}
	for offset := 0; offset < len(value); {
		index := strings.Index(value[offset:], "//")
		if index < 0 {
			return false
		}
		index += offset
		authority := index + 2
		if authority < len(value) {
			next := value[authority]
			if next != '/' && next != '*' && next != ' ' && next != '\t' && next != '\r' && next != '\n' {
				return true
			}
		}
		offset = authority
	}
	return false
}

func routeKey(routePath, rawQuery string) string {
	if rawQuery == "" {
		return routePath
	}
	return routePath + "?" + rawQuery
}

func (c *fixtureCorpus) caseByName(name string) (fixtureCase, bool) {
	for _, fixtureCase := range c.manifest.Cases {
		if fixtureCase.Name == name {
			return fixtureCase, true
		}
	}
	return fixtureCase{}, false
}

func (c *fixtureCorpus) route(name string) *fixtureRoute {
	return c.byName[name]
}

func newFixtureServer(t *testing.T, corpus *fixtureCorpus, behaviors map[string]http.HandlerFunc) *fixtureServer {
	t.Helper()
	fixture := &fixtureServer{corpus: corpus, behaviors: behaviors}
	fixture.server = httptest.NewServer(fixture)
	t.Cleanup(fixture.server.Close)
	serverURL, err := url.Parse(fixture.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	fixture.baseURL = "http://" + corpus.manifest.Host + ":" + port
	return fixture
}

func (s *fixtureServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	host, _, err := net.SplitHostPort(request.Host)
	if err != nil {
		host = request.Host
	}
	key := routeKey(request.URL.Path, request.URL.RawQuery)
	if request.Method != http.MethodGet || !strings.EqualFold(host, s.corpus.manifest.Host) {
		s.recordUnexpected(request.Method + " " + request.Host + " " + key)
		http.NotFound(writer, request)
		return
	}
	route, ok := s.corpus.routes[key]
	if !ok {
		s.recordUnexpected(request.Method + " " + request.Host + " " + key)
		http.NotFound(writer, request)
		return
	}
	if request.Header.Get("Authorization") != route.Authorization {
		s.recordUnexpected(request.Method + " " + request.Host + " " + key + " authorization mismatch")
		http.NotFound(writer, request)
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, route.Name)
	s.mu.Unlock()
	if route.RedirectTo != "" {
		writer.Header().Set("Location", route.RedirectTo)
		writer.WriteHeader(route.Status)
		return
	}
	writer.Header().Set("Content-Type", route.ContentType)
	if route.Behavior != "" {
		handler, ok := s.behaviors[route.Behavior]
		if !ok {
			s.recordUnexpected("missing behavior " + route.Behavior)
			http.Error(writer, "fixture behavior is unavailable", http.StatusInternalServerError)
			return
		}
		handler(writer, request)
		return
	}
	writer.WriteHeader(route.Status)
	_, _ = writer.Write(route.data)
}

func (s *fixtureServer) recordUnexpected(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unexpected = append(s.unexpected, value)
}

func (s *fixtureServer) snapshot() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests), slices.Clone(s.unexpected)
}
