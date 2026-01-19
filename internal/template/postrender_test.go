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
	"strings"
	"testing"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
	kustomize "github.com/fluxcd/pkg/apis/kustomize"
)

func TestKustomizePostRenderer_Run_NilSpec(t *testing.T) {
	pr := NewKustomizePostRenderer(nil)
	input := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n")

	result, err := pr.Run(input)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if string(result) != string(input) {
		t.Errorf("Run() with nil spec should return input unchanged, got %s", string(result))
	}
}

func TestKustomizePostRenderer_Run_EmptySpec(t *testing.T) {
	pr := NewKustomizePostRenderer(&helmv2.Kustomize{})
	input := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\ndata:\n  key: value\n")

	result, err := pr.Run(input)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// Should contain the ConfigMap
	if !strings.Contains(string(result), "kind: ConfigMap") {
		t.Errorf("Run() should contain ConfigMap, got %s", string(result))
	}
}

func TestKustomizePostRenderer_Run_WithPatches(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		patches        []kustomize.Patch
		expectedString string
		notExpected    string
	}{
		{
			name: "strategic merge patch",
			input: `apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
data:
  key1: value1
`,
			patches: []kustomize.Patch{
				{
					Patch: `apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
data:
  key2: value2
`,
				},
			},
			expectedString: "key2: value2",
		},
		{
			name: "json patch with target",
			input: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  replicas: 1
`,
			patches: []kustomize.Patch{
				{
					Target: &kustomize.Selector{
						Kind: "Deployment",
						Name: "my-deployment",
					},
					Patch: `- op: replace
  path: /spec/replicas
  value: 3
`,
				},
			},
			expectedString: "replicas: 3",
			notExpected:    "replicas: 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &helmv2.Kustomize{
				Patches: tt.patches,
			}
			pr := NewKustomizePostRenderer(spec)

			result, err := pr.Run([]byte(tt.input))
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}

			if !strings.Contains(string(result), tt.expectedString) {
				t.Errorf("Run() result should contain %q, got %s", tt.expectedString, string(result))
			}

			if tt.notExpected != "" && strings.Contains(string(result), tt.notExpected) {
				t.Errorf("Run() result should not contain %q, got %s", tt.notExpected, string(result))
			}
		})
	}
}

func TestKustomizePostRenderer_Run_WithImages(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.16
`
	spec := &helmv2.Kustomize{
		Images: []kustomize.Image{
			{
				Name:    "nginx",
				NewName: "my-registry/nginx",
				NewTag:  "1.20",
			},
		},
	}
	pr := NewKustomizePostRenderer(spec)

	result, err := pr.Run([]byte(input))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !strings.Contains(string(result), "my-registry/nginx:1.20") {
		t.Errorf("Run() should transform image, got %s", string(result))
	}
}

func TestKustomizePostRenderer_Run_WithImageDigest(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:latest
`
	spec := &helmv2.Kustomize{
		Images: []kustomize.Image{
			{
				Name:   "nginx",
				Digest: "sha256:abc123",
			},
		},
	}
	pr := NewKustomizePostRenderer(spec)

	result, err := pr.Run([]byte(input))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !strings.Contains(string(result), "nginx@sha256:abc123") {
		t.Errorf("Run() should use digest, got %s", string(result))
	}
}

func TestKustomizePostRenderer_Run_WithPatchesAndImages(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
  labels:
    app: test
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.16
`
	spec := &helmv2.Kustomize{
		Patches: []kustomize.Patch{
			{
				Target: &kustomize.Selector{
					Kind: "Deployment",
					Name: "my-deployment",
				},
				Patch: `- op: replace
  path: /spec/replicas
  value: 5
`,
			},
		},
		Images: []kustomize.Image{
			{
				Name:   "nginx",
				NewTag: "1.21",
			},
		},
	}
	pr := NewKustomizePostRenderer(spec)

	result, err := pr.Run([]byte(input))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	resultStr := string(result)
	if !strings.Contains(resultStr, "replicas: 5") {
		t.Errorf("Run() should have replicas: 5, got %s", resultStr)
	}
	if !strings.Contains(resultStr, "nginx:1.21") {
		t.Errorf("Run() should have nginx:1.21, got %s", resultStr)
	}
}

func TestKustomizePostRenderer_Run_MultipleResources(t *testing.T) {
	input := `apiVersion: v1
kind: ConfigMap
metadata:
  name: config1
data:
  key: value1
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config2
data:
  key: value2
`
	spec := &helmv2.Kustomize{
		Patches: []kustomize.Patch{
			{
				Target: &kustomize.Selector{
					Kind: "ConfigMap",
					Name: "config1",
				},
				Patch: `- op: add
  path: /data/extra
  value: patched
`,
			},
		},
	}
	pr := NewKustomizePostRenderer(spec)

	result, err := pr.Run([]byte(input))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	resultStr := string(result)
	// Should contain both ConfigMaps
	if !strings.Contains(resultStr, "name: config1") {
		t.Errorf("Run() should contain config1")
	}
	if !strings.Contains(resultStr, "name: config2") {
		t.Errorf("Run() should contain config2")
	}
	// config1 should have the patch applied
	if !strings.Contains(resultStr, "extra: patched") {
		t.Errorf("Run() should have patch applied, got %s", resultStr)
	}
}

func TestConvertSelector(t *testing.T) {
	tests := []struct {
		name     string
		input    *kustomize.Selector
		expected bool // whether result should be non-nil
	}{
		{
			name:     "nil selector",
			input:    nil,
			expected: false,
		},
		{
			name: "full selector",
			input: &kustomize.Selector{
				Group:              "apps",
				Version:            "v1",
				Kind:               "Deployment",
				Name:               "my-deploy",
				Namespace:          "default",
				LabelSelector:      "app=test",
				AnnotationSelector: "env=prod",
			},
			expected: true,
		},
		{
			name: "partial selector",
			input: &kustomize.Selector{
				Kind: "ConfigMap",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertSelector(tt.input)
			if tt.expected && result == nil {
				t.Errorf("convertSelector() returned nil, expected non-nil")
			}
			if !tt.expected && result != nil {
				t.Errorf("convertSelector() returned non-nil, expected nil")
			}

			if result != nil && tt.input != nil {
				if result.Gvk.Group != tt.input.Group {
					t.Errorf("Group mismatch: got %s, want %s", result.Gvk.Group, tt.input.Group)
				}
				if result.Gvk.Version != tt.input.Version {
					t.Errorf("Version mismatch: got %s, want %s", result.Gvk.Version, tt.input.Version)
				}
				if result.Gvk.Kind != tt.input.Kind {
					t.Errorf("Kind mismatch: got %s, want %s", result.Gvk.Kind, tt.input.Kind)
				}
				if result.Name != tt.input.Name {
					t.Errorf("Name mismatch: got %s, want %s", result.Name, tt.input.Name)
				}
				if result.Namespace != tt.input.Namespace {
					t.Errorf("Namespace mismatch: got %s, want %s", result.Namespace, tt.input.Namespace)
				}
				if result.LabelSelector != tt.input.LabelSelector {
					t.Errorf("LabelSelector mismatch: got %s, want %s", result.LabelSelector, tt.input.LabelSelector)
				}
				if result.AnnotationSelector != tt.input.AnnotationSelector {
					t.Errorf("AnnotationSelector mismatch: got %s, want %s", result.AnnotationSelector, tt.input.AnnotationSelector)
				}
			}
		})
	}
}

func TestTempDirPostRenderer(t *testing.T) {
	pr, err := NewTempDirPostRenderer()
	if err != nil {
		t.Fatalf("NewTempDirPostRenderer() error = %v", err)
	}

	if pr.dir == "" {
		t.Error("TempDirPostRenderer.dir should not be empty")
	}

	// Cleanup should not error
	if err := pr.Cleanup(); err != nil {
		t.Errorf("Cleanup() error = %v", err)
	}

	// Cleanup again should not error (directory already removed)
	if err := pr.Cleanup(); err != nil {
		t.Errorf("Second Cleanup() error = %v", err)
	}
}

func TestTempDirPostRenderer_EmptyDir(t *testing.T) {
	pr := &TempDirPostRenderer{dir: ""}
	if err := pr.Cleanup(); err != nil {
		t.Errorf("Cleanup() with empty dir should not error, got %v", err)
	}
}
