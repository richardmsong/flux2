//go:build unit
// +build unit

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

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAllResources(t *testing.T) {
	// Create a temp file with multi-document YAML
	tmpDir := t.TempDir()
	multiDocPath := filepath.Join(tmpDir, "multi-doc.yaml")

	multiDocYAML := `---
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager
  labels:
    toolkit.fluxcd.io/tenant: infrastructure
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: jetstack
  namespace: flux-system
spec:
  type: oci
  interval: 1h
  url: oci://quay.io/jetstack/charts
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: trust-manager
  namespace: flux-system
spec:
  interval: 30m
  targetNamespace: cert-manager
  chart:
    spec:
      chart: trust-manager
      version: "0.*"
      sourceRef:
        kind: HelmRepository
        name: jetstack
        namespace: flux-system
      reconcileStrategy: ChartVersion
  install:
    crds: Create
    remediation:
      retries: 3
  upgrade:
    crds: CreateReplace
    remediation:
      retries: 3
  values:
    app:
      trust:
        namespace: cert-manager
---
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: GitRepository
metadata:
  name: jfrog-token-exchanger
  namespace: flux-system
spec:
  interval: 10m
  url: https://github.com/richardmsong/jfrog-token-exchanger
  ref:
    branch: main
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: jfrog-token-exchanger
  namespace: flux-system
spec:
  interval: 10m
  path: "./config/default"
  sourceRef:
    kind: GitRepository
    name: jfrog-token-exchanger
    namespace: flux-system
`

	if err := os.WriteFile(multiDocPath, []byte(multiDocYAML), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Parse the file
	resources, err := parseAllResources(multiDocPath)
	if err != nil {
		t.Fatalf("parseAllResources failed: %v", err)
	}

	// Verify HelmRelease
	if len(resources.helmReleases) != 1 {
		t.Errorf("expected 1 HelmRelease, got %d", len(resources.helmReleases))
	} else if resources.helmReleases[0].Name != "trust-manager" {
		t.Errorf("expected HelmRelease name 'trust-manager', got '%s'", resources.helmReleases[0].Name)
	}

	// Verify Kustomization
	if len(resources.kustomizations) != 1 {
		t.Errorf("expected 1 Kustomization, got %d", len(resources.kustomizations))
	} else if resources.kustomizations[0].Name != "jfrog-token-exchanger" {
		t.Errorf("expected Kustomization name 'jfrog-token-exchanger', got '%s'", resources.kustomizations[0].Name)
	}

	// Verify sources (HelmRepository and GitRepository are now stored in sources map)
	if len(resources.sources) == 0 {
		t.Errorf("expected at least 2 source resources, got 0")
	} else {
		// Check for HelmRepository with Kind/name format
		if _, found := resources.sources["HelmRepository/jetstack"]; !found {
			t.Errorf("expected HelmRepository 'jetstack' to be found in sources")
		}
		// Check for GitRepository with Kind/name format
		if _, found := resources.sources["GitRepository/jfrog-token-exchanger"]; !found {
			t.Errorf("expected GitRepository 'jfrog-token-exchanger' to be found in sources")
		}
	}
}

func TestParseAllResourcesMultipleHelmReleases(t *testing.T) {
	// Create a temp file with multiple HelmReleases
	tmpDir := t.TempDir()
	multiHRPath := filepath.Join(tmpDir, "multi-hr.yaml")

	multiHRYAML := `---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: hr-one
  namespace: default
spec:
  interval: 5m
  chart:
    spec:
      chart: chart-one
      sourceRef:
        kind: HelmRepository
        name: repo-one
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: hr-two
  namespace: default
spec:
  interval: 5m
  chart:
    spec:
      chart: chart-two
      sourceRef:
        kind: HelmRepository
        name: repo-two
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: hr-three
  namespace: default
spec:
  interval: 5m
  chart:
    spec:
      chart: chart-three
      sourceRef:
        kind: HelmRepository
        name: repo-three
`

	if err := os.WriteFile(multiHRPath, []byte(multiHRYAML), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Parse the file
	resources, err := parseAllResources(multiHRPath)
	if err != nil {
		t.Fatalf("parseAllResources failed: %v", err)
	}

	// Verify we got all 3 HelmReleases
	if len(resources.helmReleases) != 3 {
		t.Errorf("expected 3 HelmReleases, got %d", len(resources.helmReleases))
	}

	// Verify the names
	expectedNames := map[string]bool{"hr-one": false, "hr-two": false, "hr-three": false}
	for _, hr := range resources.helmReleases {
		if _, exists := expectedNames[hr.Name]; exists {
			expectedNames[hr.Name] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("expected HelmRelease '%s' not found", name)
		}
	}
}

func TestParseAllResourcesMultipleKustomizations(t *testing.T) {
	// Create a temp file with multiple Kustomizations
	tmpDir := t.TempDir()
	multiKsPath := filepath.Join(tmpDir, "multi-ks.yaml")

	multiKsYAML := `---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: ks-one
  namespace: flux-system
spec:
  interval: 10m
  path: "./path-one"
  sourceRef:
    kind: GitRepository
    name: repo-one
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: ks-two
  namespace: flux-system
spec:
  interval: 10m
  path: "./path-two"
  sourceRef:
    kind: GitRepository
    name: repo-two
`

	if err := os.WriteFile(multiKsPath, []byte(multiKsYAML), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Parse the file
	resources, err := parseAllResources(multiKsPath)
	if err != nil {
		t.Fatalf("parseAllResources failed: %v", err)
	}

	// Verify we got both Kustomizations
	if len(resources.kustomizations) != 2 {
		t.Errorf("expected 2 Kustomizations, got %d", len(resources.kustomizations))
	}

	// Verify the names
	expectedNames := map[string]bool{"ks-one": false, "ks-two": false}
	for _, ks := range resources.kustomizations {
		if _, exists := expectedNames[ks.Name]; exists {
			expectedNames[ks.Name] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("expected Kustomization '%s' not found", name)
		}
	}
}

func TestIsHelmReleaseAPIVersion(t *testing.T) {
	tests := []struct {
		apiVersion string
		expected   bool
	}{
		{"helm.toolkit.fluxcd.io/v2", true},
		{"helm.toolkit.fluxcd.io/v2beta1", true},
		{"helm.toolkit.fluxcd.io/v2beta2", true},
		{"helm.toolkit.fluxcd.io/v1beta1", false},
		{"apps/v1", false},
		{"v1", false},
	}

	for _, tt := range tests {
		t.Run(tt.apiVersion, func(t *testing.T) {
			result := isHelmReleaseAPIVersion(tt.apiVersion)
			if result != tt.expected {
				t.Errorf("isHelmReleaseAPIVersion(%s) = %v, want %v", tt.apiVersion, result, tt.expected)
			}
		})
	}
}

func TestIsKustomizationAPIVersion(t *testing.T) {
	tests := []struct {
		apiVersion string
		expected   bool
	}{
		{"kustomize.toolkit.fluxcd.io/v1", true},
		{"kustomize.toolkit.fluxcd.io/v1beta1", true},
		{"kustomize.toolkit.fluxcd.io/v1beta2", true},
		{"kustomize.config.k8s.io/v1beta1", false}, // Native kustomize, not Flux
		{"apps/v1", false},
		{"v1", false},
	}

	for _, tt := range tests {
		t.Run(tt.apiVersion, func(t *testing.T) {
			result := isKustomizationAPIVersion(tt.apiVersion)
			if result != tt.expected {
				t.Errorf("isKustomizationAPIVersion(%s) = %v, want %v", tt.apiVersion, result, tt.expected)
			}
		})
	}
}

func TestIsSourceAPIVersion(t *testing.T) {
	tests := []struct {
		apiVersion string
		expected   bool
	}{
		{"source.toolkit.fluxcd.io/v1", true},
		{"source.toolkit.fluxcd.io/v1beta1", true},
		{"source.toolkit.fluxcd.io/v1beta2", true},
		{"apps/v1", false},
		{"v1", false},
	}

	for _, tt := range tests {
		t.Run(tt.apiVersion, func(t *testing.T) {
			result := isSourceAPIVersion(tt.apiVersion)
			if result != tt.expected {
				t.Errorf("isSourceAPIVersion(%s) = %v, want %v", tt.apiVersion, result, tt.expected)
			}
		})
	}
}
