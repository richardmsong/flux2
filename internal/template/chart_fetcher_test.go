/*
Copyright 2024 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package template

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

func TestIsVersionConstraint(t *testing.T) {
	tests := []struct {
		version      string
		isConstraint bool
	}{
		// Exact versions - NOT constraints
		{"1.0.0", false},
		{"2.3.4", false},
		{"v1.2.3", false},
		{"10.20.30", false},

		// Wildcard constraints
		{"1.*", true},
		{"1.2.*", true},
		{"*", true},
		{"1.x", true},
		{"1.X", true},
		{"1.2.x", true},

		// Range constraints
		{">=1.0.0", true},
		{"<=2.0.0", true},
		{">1.0.0", true},
		{"<2.0.0", true},
		{"~1.2.3", true},
		{"^1.2.3", true},

		// Multiple conditions
		{">=1.0.0 <2.0.0", true},
		{"1.0.0 - 2.0.0", true},
		{">=1.0.0 || >=2.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			result := isVersionConstraint(tt.version)
			if result != tt.isConstraint {
				t.Errorf("isVersionConstraint(%q) = %v, expected %v", tt.version, result, tt.isConstraint)
			}
		})
	}
}

// createTestChart creates a minimal Helm chart archive in memory
func createTestChart(name, version string) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Chart.yaml content
	chartYAML := fmt.Sprintf(`apiVersion: v2
name: %s
version: %s
description: A test chart
`, name, version)

	// Add Chart.yaml
	chartYAMLHeader := &tar.Header{
		Name: fmt.Sprintf("%s/Chart.yaml", name),
		Mode: 0644,
		Size: int64(len(chartYAML)),
	}
	if err := tw.WriteHeader(chartYAMLHeader); err != nil {
		return nil, err
	}
	if _, err := tw.Write([]byte(chartYAML)); err != nil {
		return nil, err
	}

	// Add a minimal values.yaml
	valuesYAML := "replicaCount: 1\n"
	valuesHeader := &tar.Header{
		Name: fmt.Sprintf("%s/values.yaml", name),
		Mode: 0644,
		Size: int64(len(valuesYAML)),
	}
	if err := tw.WriteHeader(valuesHeader); err != nil {
		return nil, err
	}
	if _, err := tw.Write([]byte(valuesYAML)); err != nil {
		return nil, err
	}

	// Add a minimal template
	templateContent := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}\n"
	templateHeader := &tar.Header{
		Name: fmt.Sprintf("%s/templates/configmap.yaml", name),
		Mode: 0644,
		Size: int64(len(templateContent)),
	}
	if err := tw.WriteHeader(templateHeader); err != nil {
		return nil, err
	}
	if _, err := tw.Write([]byte(templateContent)); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// createIndexYAML creates a Helm repository index.yaml
func createIndexYAML(chartName string, versions []string, baseURL string) ([]byte, error) {
	entries := make(map[string][]map[string]interface{})
	for _, version := range versions {
		entry := map[string]interface{}{
			"name":    chartName,
			"version": version,
			"urls":    []string{fmt.Sprintf("%s/%s-%s.tgz", baseURL, chartName, version)},
		}
		entries[chartName] = append(entries[chartName], entry)
	}

	index := map[string]interface{}{
		"apiVersion": "v1",
		"entries":    entries,
	}

	return yaml.Marshal(index)
}

// createHelmRepoSource creates an unstructured HelmRepository source
func createHelmRepoSource(name, namespace, url string, repoType string) *unstructured.Unstructured {
	source := &unstructured.Unstructured{}
	source.SetAPIVersion("source.toolkit.fluxcd.io/v1")
	source.SetKind("HelmRepository")
	source.SetName(name)
	source.SetNamespace(namespace)

	spec := map[string]interface{}{
		"url":      url,
		"interval": "1h",
	}
	if repoType != "" {
		spec["type"] = repoType
	}
	source.Object["spec"] = spec
	return source
}

func TestChartFetcher_FetchFromHTTP(t *testing.T) {
	chartName := "test-chart"
	chartVersion := "1.2.3"

	// Create test chart
	chartData, err := createTestChart(chartName, chartVersion)
	if err != nil {
		t.Fatalf("failed to create test chart: %v", err)
	}

	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.yaml":
			indexData, err := createIndexYAML(chartName, []string{chartVersion, "1.2.2", "1.2.1"}, "")
			if err != nil {
				http.Error(w, "failed to create index", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/x-yaml")
			w.Write(indexData)
		case fmt.Sprintf("/%s-%s.tgz", chartName, chartVersion):
			w.Header().Set("Content-Type", "application/x-tar")
			w.Write(chartData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tests := []struct {
		name         string
		chartName    string
		chartVersion string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "fetch specific version",
			chartName:    chartName,
			chartVersion: chartVersion,
			expectError:  false,
		},
		{
			name:         "fetch latest (empty version)",
			chartName:    chartName,
			chartVersion: "",
			expectError:  false,
		},
		{
			name:         "chart not found",
			chartName:    "nonexistent-chart",
			chartVersion: "1.0.0",
			expectError:  true,
			errorMsg:     "chart \"nonexistent-chart\" not found",
		},
		{
			name:         "version not found",
			chartName:    chartName,
			chartVersion: "9.9.9",
			expectError:  true,
			errorMsg:     "version \"9.9.9\" not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetcher := NewChartFetcher()
			source := createHelmRepoSource("test-repo", "flux-system", server.URL, "")

			chart, err := fetcher.Fetch(context.Background(), &FetchOptions{
				ChartName:    tt.chartName,
				ChartVersion: tt.chartVersion,
				Source:       source,
			})

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errorMsg)) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if chart.Metadata.Name != chartName {
				t.Errorf("expected chart name %q, got %q", chartName, chart.Metadata.Name)
			}
		})
	}
}

func TestChartFetcher_FetchFromHTTP_WithBasicAuth(t *testing.T) {
	chartName := "test-chart"
	chartVersion := "1.0.0"
	expectedUser := "testuser"
	expectedPass := "testpass"

	chartData, err := createTestChart(chartName, chartVersion)
	if err != nil {
		t.Fatalf("failed to create test chart: %v", err)
	}

	// Create mock HTTP server with basic auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != expectedUser || pass != expectedPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/index.yaml":
			indexData, _ := createIndexYAML(chartName, []string{chartVersion}, "")
			w.Header().Set("Content-Type", "application/x-yaml")
			w.Write(indexData)
		case fmt.Sprintf("/%s-%s.tgz", chartName, chartVersion):
			w.Header().Set("Content-Type", "application/x-tar")
			w.Write(chartData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tests := []struct {
		name        string
		creds       *RegistryCredentials
		expectError bool
	}{
		{
			name:        "with valid credentials",
			creds:       &RegistryCredentials{Username: expectedUser, Password: expectedPass},
			expectError: false,
		},
		{
			name:        "without credentials",
			creds:       nil,
			expectError: true,
		},
		{
			name:        "with invalid credentials",
			creds:       &RegistryCredentials{Username: "wrong", Password: "wrong"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetcher := NewChartFetcher()
			source := createHelmRepoSource("test-repo", "flux-system", server.URL, "")

			chart, err := fetcher.Fetch(context.Background(), &FetchOptions{
				ChartName:           chartName,
				ChartVersion:        chartVersion,
				Source:              source,
				RegistryCredentials: tt.creds,
			})

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if chart.Metadata.Name != chartName {
				t.Errorf("expected chart name %q, got %q", chartName, chart.Metadata.Name)
			}
		})
	}
}

func TestChartFetcher_FetchFromHTTP_ServerErrors(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		expectErr string
	}{
		{
			name: "index fetch 404",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r)
			}),
			expectErr: "HTTP 404",
		},
		{
			name: "index fetch 500",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}),
			expectErr: "HTTP 500",
		},
		{
			name: "invalid index yaml",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/index.yaml" {
					w.Write([]byte("not: valid: yaml: content: ["))
				}
			}),
			expectErr: "failed to parse repository index",
		},
		{
			name: "chart download 404",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/index.yaml" {
					indexData, _ := createIndexYAML("test-chart", []string{"1.0.0"}, "")
					w.Write(indexData)
				} else {
					http.NotFound(w, r)
				}
			}),
			expectErr: "HTTP 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			fetcher := NewChartFetcher()
			source := createHelmRepoSource("test-repo", "flux-system", server.URL, "")

			_, err := fetcher.Fetch(context.Background(), &FetchOptions{
				ChartName:    "test-chart",
				ChartVersion: "1.0.0",
				Source:       source,
			})

			if err == nil {
				t.Error("expected error, got nil")
				return
			}

			if !bytes.Contains([]byte(err.Error()), []byte(tt.expectErr)) {
				t.Errorf("expected error containing %q, got %q", tt.expectErr, err.Error())
			}
		})
	}
}

func TestChartFetcher_FetchFromHTTP_TLSConfig(t *testing.T) {
	chartName := "test-chart"
	chartVersion := "1.0.0"

	chartData, err := createTestChart(chartName, chartVersion)
	if err != nil {
		t.Fatalf("failed to create test chart: %v", err)
	}

	// Create TLS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.yaml":
			indexData, _ := createIndexYAML(chartName, []string{chartVersion}, "")
			w.Header().Set("Content-Type", "application/x-yaml")
			w.Write(indexData)
		case fmt.Sprintf("/%s-%s.tgz", chartName, chartVersion):
			w.Header().Set("Content-Type", "application/x-tar")
			w.Write(chartData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tests := []struct {
		name        string
		creds       *RegistryCredentials
		expectError bool
	}{
		{
			name:        "with insecure flag",
			creds:       &RegistryCredentials{Insecure: true},
			expectError: false,
		},
		{
			name:        "without insecure flag",
			creds:       nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetcher := NewChartFetcher()
			source := createHelmRepoSource("test-repo", "flux-system", server.URL, "")

			chart, err := fetcher.Fetch(context.Background(), &FetchOptions{
				ChartName:           chartName,
				ChartVersion:        chartVersion,
				Source:              source,
				RegistryCredentials: tt.creds,
			})

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if chart.Metadata.Name != chartName {
				t.Errorf("expected chart name %q, got %q", chartName, chart.Metadata.Name)
			}
		})
	}
}

func TestChartFetcher_Fetch_NilSource(t *testing.T) {
	fetcher := NewChartFetcher()

	_, err := fetcher.Fetch(context.Background(), &FetchOptions{
		ChartName:    "test-chart",
		ChartVersion: "1.0.0",
		Source:       nil,
	})

	if err == nil {
		t.Error("expected error, got nil")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("source is required")) {
		t.Errorf("expected error containing 'source is required', got %q", err.Error())
	}
}

func TestChartFetcher_Fetch_InvalidSource(t *testing.T) {
	fetcher := NewChartFetcher()

	// Source without spec
	source := &unstructured.Unstructured{}
	source.SetAPIVersion("source.toolkit.fluxcd.io/v1")
	source.SetKind("HelmRepository")
	source.SetName("test-repo")

	_, err := fetcher.Fetch(context.Background(), &FetchOptions{
		ChartName:    "test-chart",
		ChartVersion: "1.0.0",
		Source:       source,
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestChartFetcher_Fetch_SourceWithoutURL(t *testing.T) {
	fetcher := NewChartFetcher()

	// Source with spec but no URL
	source := &unstructured.Unstructured{}
	source.SetAPIVersion("source.toolkit.fluxcd.io/v1")
	source.SetKind("HelmRepository")
	source.SetName("test-repo")
	source.Object["spec"] = map[string]interface{}{
		"interval": "1h",
	}

	_, err := fetcher.Fetch(context.Background(), &FetchOptions{
		ChartName:    "test-chart",
		ChartVersion: "1.0.0",
		Source:       source,
	})

	if err == nil {
		t.Error("expected error, got nil")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("spec.url")) {
		t.Errorf("expected error containing 'spec.url', got %q", err.Error())
	}
}

func TestChartFetcher_FetchFromHTTP_RelativeChartURL(t *testing.T) {
	chartName := "test-chart"
	chartVersion := "1.0.0"

	chartData, err := createTestChart(chartName, chartVersion)
	if err != nil {
		t.Fatalf("failed to create test chart: %v", err)
	}

	// Create mock HTTP server with relative URLs in index
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/charts/index.yaml":
			// Return index with relative URL
			index := fmt.Sprintf(`apiVersion: v1
entries:
  %s:
    - name: %s
      version: %s
      urls:
        - charts/%s-%s.tgz
`, chartName, chartName, chartVersion, chartName, chartVersion)
			w.Header().Set("Content-Type", "application/x-yaml")
			w.Write([]byte(index))
		case fmt.Sprintf("/charts/charts/%s-%s.tgz", chartName, chartVersion):
			w.Header().Set("Content-Type", "application/x-tar")
			w.Write(chartData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	fetcher := NewChartFetcher()
	source := createHelmRepoSource("test-repo", "flux-system", server.URL+"/charts", "")

	chart, err := fetcher.Fetch(context.Background(), &FetchOptions{
		ChartName:    chartName,
		ChartVersion: chartVersion,
		Source:       source,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if chart.Metadata.Name != chartName {
		t.Errorf("expected chart name %q, got %q", chartName, chart.Metadata.Name)
	}
}

func TestChartFetcher_FetchFromHTTP_AbsoluteChartURL(t *testing.T) {
	chartName := "test-chart"
	chartVersion := "1.0.0"

	chartData, err := createTestChart(chartName, chartVersion)
	if err != nil {
		t.Fatalf("failed to create test chart: %v", err)
	}

	// Create a second server to serve the chart
	chartServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == fmt.Sprintf("/%s-%s.tgz", chartName, chartVersion) {
			w.Header().Set("Content-Type", "application/x-tar")
			w.Write(chartData)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer chartServer.Close()

	// Create mock HTTP server with absolute URL in index
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.yaml" {
			index := fmt.Sprintf(`apiVersion: v1
entries:
  %s:
    - name: %s
      version: %s
      urls:
        - %s/%s-%s.tgz
`, chartName, chartName, chartVersion, chartServer.URL, chartName, chartVersion)
			w.Header().Set("Content-Type", "application/x-yaml")
			w.Write([]byte(index))
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	fetcher := NewChartFetcher()
	source := createHelmRepoSource("test-repo", "flux-system", server.URL, "")

	chart, err := fetcher.Fetch(context.Background(), &FetchOptions{
		ChartName:    chartName,
		ChartVersion: chartVersion,
		Source:       source,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if chart.Metadata.Name != chartName {
		t.Errorf("expected chart name %q, got %q", chartName, chart.Metadata.Name)
	}
}

func TestChartFetcher_FetchFromHTTP_MultipleVersions(t *testing.T) {
	chartName := "test-chart"
	versions := []string{"2.0.0", "1.5.0", "1.0.0"}

	charts := make(map[string][]byte)
	for _, v := range versions {
		chartData, err := createTestChart(chartName, v)
		if err != nil {
			t.Fatalf("failed to create test chart: %v", err)
		}
		charts[v] = chartData
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.yaml":
			indexData, _ := createIndexYAML(chartName, versions, "")
			w.Header().Set("Content-Type", "application/x-yaml")
			w.Write(indexData)
		default:
			for v, data := range charts {
				if r.URL.Path == fmt.Sprintf("/%s-%s.tgz", chartName, v) {
					w.Header().Set("Content-Type", "application/x-tar")
					w.Write(data)
					return
				}
			}
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tests := []struct {
		name            string
		requestVersion  string
		expectedVersion string
	}{
		{
			name:            "specific version",
			requestVersion:  "1.5.0",
			expectedVersion: "1.5.0",
		},
		{
			name:            "latest version (empty)",
			requestVersion:  "",
			expectedVersion: "2.0.0",
		},
		{
			name:            "oldest version",
			requestVersion:  "1.0.0",
			expectedVersion: "1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetcher := NewChartFetcher()
			source := createHelmRepoSource("test-repo", "flux-system", server.URL, "")

			chart, err := fetcher.Fetch(context.Background(), &FetchOptions{
				ChartName:    chartName,
				ChartVersion: tt.requestVersion,
				Source:       source,
			})

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if chart.Metadata.Version != tt.expectedVersion {
				t.Errorf("expected version %q, got %q", tt.expectedVersion, chart.Metadata.Version)
			}
		})
	}
}

func TestChartFetcher_FetchFromHTTP_EmptyChartURLs(t *testing.T) {
	chartName := "test-chart"
	chartVersion := "1.0.0"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.yaml" {
			// Return index with empty URLs
			index := fmt.Sprintf(`apiVersion: v1
entries:
  %s:
    - name: %s
      version: %s
      urls: []
`, chartName, chartName, chartVersion)
			w.Header().Set("Content-Type", "application/x-yaml")
			w.Write([]byte(index))
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	fetcher := NewChartFetcher()
	source := createHelmRepoSource("test-repo", "flux-system", server.URL, "")

	_, err := fetcher.Fetch(context.Background(), &FetchOptions{
		ChartName:    chartName,
		ChartVersion: chartVersion,
		Source:       source,
	})

	if err == nil {
		t.Error("expected error, got nil")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("no download URL found")) {
		t.Errorf("expected error containing 'no download URL found', got %q", err.Error())
	}
}

func TestCreateHTTPClient(t *testing.T) {
	fetcher := &DefaultChartFetcher{}

	tests := []struct {
		name               string
		creds              *RegistryCredentials
		expectInsecureSkip bool
		expectError        bool
	}{
		{
			name:               "nil credentials",
			creds:              nil,
			expectInsecureSkip: false,
			expectError:        false,
		},
		{
			name:               "empty credentials",
			creds:              &RegistryCredentials{},
			expectInsecureSkip: false,
			expectError:        false,
		},
		{
			name:               "insecure flag",
			creds:              &RegistryCredentials{Insecure: true},
			expectInsecureSkip: true,
			expectError:        false,
		},
		{
			name:               "nonexistent CA file",
			creds:              &RegistryCredentials{CAFile: "/nonexistent/ca.crt"},
			expectInsecureSkip: false,
			expectError:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := fetcher.createHTTPClient(tt.creds)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			transport := client.Transport.(*http.Transport)
			if transport.TLSClientConfig.InsecureSkipVerify != tt.expectInsecureSkip {
				t.Errorf("expected InsecureSkipVerify=%v, got %v",
					tt.expectInsecureSkip, transport.TLSClientConfig.InsecureSkipVerify)
			}
		})
	}
}

func TestGetCredentials(t *testing.T) {
	fetcher := &DefaultChartFetcher{}

	tests := []struct {
		name       string
		opts       *FetchOptions
		expectNil  bool
		expectUser string
		expectPass string
	}{
		{
			name: "nil credentials",
			opts: &FetchOptions{
				RegistryCredentials: nil,
			},
			expectNil: true,
		},
		{
			name: "with credentials",
			opts: &FetchOptions{
				RegistryCredentials: &RegistryCredentials{
					Username: "user",
					Password: "pass",
				},
			},
			expectNil:  false,
			expectUser: "user",
			expectPass: "pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := fetcher.getCredentials(context.Background(), tt.opts)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.expectNil {
				if creds != nil {
					t.Errorf("expected nil credentials, got %+v", creds)
				}
				return
			}

			if creds == nil {
				t.Fatal("expected non-nil credentials")
			}

			if creds.Username != tt.expectUser {
				t.Errorf("expected username %q, got %q", tt.expectUser, creds.Username)
			}
			if creds.Password != tt.expectPass {
				t.Errorf("expected password %q, got %q", tt.expectPass, creds.Password)
			}
		})
	}
}

// TestChartFetcher_OCI_RouteSelection tests that OCI repositories are routed correctly
func TestChartFetcher_OCI_RouteSelection(t *testing.T) {
	// Create a mock HTTP server that will be used for the non-OCI path
	// If we hit this server when using OCI type, the test fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This should not be called for OCI repositories
		t.Error("HTTP handler was called for OCI repository - wrong route taken")
		http.Error(w, "should not reach here", http.StatusInternalServerError)
	}))
	defer server.Close()

	fetcher := NewChartFetcher()

	// Create OCI source - this should NOT go through HTTP path
	ociSource := createHelmRepoSource("test-repo", "flux-system", "oci://registry.example.com", "oci")

	// This will fail because we don't have a real OCI registry, but it should fail
	// trying to contact the OCI registry, not the HTTP server
	_, err := fetcher.Fetch(context.Background(), &FetchOptions{
		ChartName:    "test-chart",
		ChartVersion: "1.0.0",
		Source:       ociSource,
	})

	// We expect an error (can't reach the OCI registry), but it should NOT be
	// an error from our HTTP server
	if err == nil {
		t.Error("expected error when trying to reach OCI registry")
	}

	// The error should be related to OCI/registry operations, not HTTP
	errStr := err.Error()
	if bytes.Contains([]byte(errStr), []byte("should not reach here")) {
		t.Error("OCI request was incorrectly routed to HTTP handler")
	}
}

// TestChartFetcher_HTTPSUpgrade tests that the HTTP client handles HTTPS properly
func TestChartFetcher_HTTPSUpgrade(t *testing.T) {
	chartName := "test-chart"
	chartVersion := "1.0.0"

	chartData, err := createTestChart(chartName, chartVersion)
	if err != nil {
		t.Fatalf("failed to create test chart: %v", err)
	}

	// Create TLS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify TLS is being used
		if r.TLS == nil {
			t.Error("expected TLS connection")
		}

		switch r.URL.Path {
		case "/index.yaml":
			indexData, _ := createIndexYAML(chartName, []string{chartVersion}, "")
			w.Write(indexData)
		case fmt.Sprintf("/%s-%s.tgz", chartName, chartVersion):
			w.Write(chartData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Get the server's TLS config for client
	fetcher := NewChartFetcher()
	source := createHelmRepoSource("test-repo", "flux-system", server.URL, "")

	// Use insecure mode since it's a self-signed cert
	_, err = fetcher.Fetch(context.Background(), &FetchOptions{
		ChartName:           chartName,
		ChartVersion:        chartVersion,
		Source:              source,
		RegistryCredentials: &RegistryCredentials{Insecure: true},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestChartFetcher_ContextCancellation tests that operations respect context cancellation
func TestChartFetcher_ContextCancellation(t *testing.T) {
	// Create a server that blocks
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until context is cancelled
		<-r.Context().Done()
	}))
	defer server.Close()

	fetcher := NewChartFetcher()
	source := createHelmRepoSource("test-repo", "flux-system", server.URL, "")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := fetcher.Fetch(ctx, &FetchOptions{
		ChartName:    "test-chart",
		ChartVersion: "1.0.0",
		Source:       source,
	})

	if err == nil {
		t.Error("expected error due to cancelled context")
	}
}

// TestChartFetcher_InvalidChartArchive tests handling of corrupted chart archives
func TestChartFetcher_InvalidChartArchive(t *testing.T) {
	chartName := "test-chart"
	chartVersion := "1.0.0"

	tests := []struct {
		name        string
		chartData   []byte
		expectError string
	}{
		{
			name:        "empty archive",
			chartData:   []byte{},
			expectError: "failed",
		},
		{
			name:        "invalid gzip",
			chartData:   []byte("not a gzip file"),
			expectError: "failed",
		},
		{
			name:        "random bytes",
			chartData:   []byte{0x1f, 0x8b, 0x00, 0x00, 0x00, 0x00},
			expectError: "failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/index.yaml":
					indexData, _ := createIndexYAML(chartName, []string{chartVersion}, "")
					w.Write(indexData)
				case fmt.Sprintf("/%s-%s.tgz", chartName, chartVersion):
					w.Write(tt.chartData)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			fetcher := NewChartFetcher()
			source := createHelmRepoSource("test-repo", "flux-system", server.URL, "")

			_, err := fetcher.Fetch(context.Background(), &FetchOptions{
				ChartName:    chartName,
				ChartVersion: chartVersion,
				Source:       source,
			})

			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// Suppress unused import warning - tls is used in commented test case patterns
var _ = tls.Config{}
