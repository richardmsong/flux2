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
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestValuesMerger_MergeValues_InlineValues(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: helmv2.HelmReleaseSpec{
			Values: &apiextensionsv1.JSON{
				Raw: []byte(`{"replicaCount": 3, "image": {"tag": "v1.0.0"}}`),
			},
		},
	}

	result, err := merger.MergeValues(ctx, hr, nil, nil, nil)
	if err != nil {
		t.Fatalf("MergeValues() error = %v", err)
	}

	if result["replicaCount"] != float64(3) {
		t.Errorf("replicaCount = %v, want 3", result["replicaCount"])
	}

	image, ok := result["image"].(map[string]interface{})
	if !ok {
		t.Fatalf("image is not a map")
	}
	if image["tag"] != "v1.0.0" {
		t.Errorf("image.tag = %v, want v1.0.0", image["tag"])
	}
}

func TestValuesMerger_MergeValues_ValuesFromConfigMap(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: helmv2.HelmReleaseSpec{
			ValuesFrom: []helmv2.ValuesReference{
				{
					Kind: "ConfigMap",
					Name: "my-values",
				},
			},
		},
	}

	resources := map[string]*unstructured.Unstructured{
		"ConfigMap/default/my-values": {
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"metadata": map[string]interface{}{
					"name":      "my-values",
					"namespace": "default",
				},
				"data": map[string]interface{}{
					"values.yaml": "replicaCount: 5\nservice:\n  port: 8080\n",
				},
			},
		},
	}

	result, err := merger.MergeValues(ctx, hr, resources, nil, nil)
	if err != nil {
		t.Fatalf("MergeValues() error = %v", err)
	}

	// Values can be int, int64, or float64 depending on source
	if !compareNumeric(result["replicaCount"], 5) {
		t.Errorf("replicaCount = %v, want 5", result["replicaCount"])
	}

	service, ok := result["service"].(map[string]interface{})
	if !ok {
		t.Fatalf("service is not a map")
	}
	if !compareNumeric(service["port"], 8080) {
		t.Errorf("service.port = %v, want 8080", service["port"])
	}
}

// compareNumeric compares numeric values regardless of their exact type (int, int64, float64)
func compareNumeric(got interface{}, want int) bool {
	switch v := got.(type) {
	case int:
		return v == want
	case int64:
		return v == int64(want)
	case float64:
		return v == float64(want)
	default:
		return false
	}
}

func TestValuesMerger_MergeValues_ValuesFromSecret(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: helmv2.HelmReleaseSpec{
			ValuesFrom: []helmv2.ValuesReference{
				{
					Kind: "Secret",
					Name: "my-secret",
				},
			},
		},
	}

	// Secret data is base64 encoded
	secretValues := "database:\n  password: secret123\n"
	encodedValues := base64.StdEncoding.EncodeToString([]byte(secretValues))

	resources := map[string]*unstructured.Unstructured{
		"Secret/default/my-secret": {
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Secret",
				"metadata": map[string]interface{}{
					"name":      "my-secret",
					"namespace": "default",
				},
				"data": map[string]interface{}{
					"values.yaml": encodedValues,
				},
			},
		},
	}

	result, err := merger.MergeValues(ctx, hr, resources, nil, nil)
	if err != nil {
		t.Fatalf("MergeValues() error = %v", err)
	}

	database, ok := result["database"].(map[string]interface{})
	if !ok {
		t.Fatalf("database is not a map")
	}
	if database["password"] != "secret123" {
		t.Errorf("database.password = %v, want secret123", database["password"])
	}
}

func TestValuesMerger_MergeValues_ValuesFromCustomKey(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: helmv2.HelmReleaseSpec{
			ValuesFrom: []helmv2.ValuesReference{
				{
					Kind:      "ConfigMap",
					Name:      "my-values",
					ValuesKey: "custom-key.yaml",
				},
			},
		},
	}

	resources := map[string]*unstructured.Unstructured{
		"ConfigMap/default/my-values": {
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"metadata": map[string]interface{}{
					"name":      "my-values",
					"namespace": "default",
				},
				"data": map[string]interface{}{
					"custom-key.yaml": "customValue: test\n",
				},
			},
		},
	}

	result, err := merger.MergeValues(ctx, hr, resources, nil, nil)
	if err != nil {
		t.Fatalf("MergeValues() error = %v", err)
	}

	if result["customValue"] != "test" {
		t.Errorf("customValue = %v, want test", result["customValue"])
	}
}

func TestValuesMerger_MergeValues_ValuesFromTargetPath(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: helmv2.HelmReleaseSpec{
			ValuesFrom: []helmv2.ValuesReference{
				{
					Kind:       "ConfigMap",
					Name:       "my-values",
					TargetPath: "global.config",
				},
			},
		},
	}

	resources := map[string]*unstructured.Unstructured{
		"ConfigMap/default/my-values": {
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"metadata": map[string]interface{}{
					"name":      "my-values",
					"namespace": "default",
				},
				"data": map[string]interface{}{
					"values.yaml": "key: value\n",
				},
			},
		},
	}

	result, err := merger.MergeValues(ctx, hr, resources, nil, nil)
	if err != nil {
		t.Fatalf("MergeValues() error = %v", err)
	}

	global, ok := result["global"].(map[string]interface{})
	if !ok {
		t.Fatalf("global is not a map")
	}
	config, ok := global["config"].(map[string]interface{})
	if !ok {
		t.Fatalf("global.config is not a map")
	}
	if config["key"] != "value" {
		t.Errorf("global.config.key = %v, want value", config["key"])
	}
}

func TestValuesMerger_MergeValues_ValuesFromOptional(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: helmv2.HelmReleaseSpec{
			ValuesFrom: []helmv2.ValuesReference{
				{
					Kind:     "ConfigMap",
					Name:     "missing-values",
					Optional: true,
				},
			},
		},
	}

	// Empty resources - the ConfigMap doesn't exist
	resources := map[string]*unstructured.Unstructured{}

	result, err := merger.MergeValues(ctx, hr, resources, nil, nil)
	if err != nil {
		t.Fatalf("MergeValues() error = %v, should not error for optional missing reference", err)
	}

	if len(result) != 0 {
		t.Errorf("result should be empty, got %v", result)
	}
}

func TestValuesMerger_MergeValues_ValuesFromMissingRequired(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: helmv2.HelmReleaseSpec{
			ValuesFrom: []helmv2.ValuesReference{
				{
					Kind: "ConfigMap",
					Name: "missing-values",
					// Optional defaults to false
				},
			},
		},
	}

	resources := map[string]*unstructured.Unstructured{}

	_, err := merger.MergeValues(ctx, hr, resources, nil, nil)
	if err == nil {
		t.Fatal("MergeValues() should error for missing required reference")
	}
}

func TestValuesMerger_MergeValues_ValuesFiles(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	// Create a temp values file
	tmpDir := t.TempDir()
	valuesFile := filepath.Join(tmpDir, "values.yaml")
	if err := os.WriteFile(valuesFile, []byte("fromFile: true\nnested:\n  key: fileValue\n"), 0644); err != nil {
		t.Fatalf("Failed to write values file: %v", err)
	}

	result, err := merger.MergeValues(ctx, hr, nil, []string{valuesFile}, nil)
	if err != nil {
		t.Fatalf("MergeValues() error = %v", err)
	}

	if result["fromFile"] != true {
		t.Errorf("fromFile = %v, want true", result["fromFile"])
	}

	nested, ok := result["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("nested is not a map")
	}
	if nested["key"] != "fileValue" {
		t.Errorf("nested.key = %v, want fileValue", nested["key"])
	}
}

func TestValuesMerger_MergeValues_SetValues(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	setValues := map[string]string{
		"image.tag":    "v2.0.0",
		"replicaCount": "5",
		"debug":        "true",
	}

	result, err := merger.MergeValues(ctx, hr, nil, nil, setValues)
	if err != nil {
		t.Fatalf("MergeValues() error = %v", err)
	}

	image, ok := result["image"].(map[string]interface{})
	if !ok {
		t.Fatalf("image is not a map")
	}
	if image["tag"] != "v2.0.0" {
		t.Errorf("image.tag = %v, want v2.0.0", image["tag"])
	}

	if result["replicaCount"] != int64(5) {
		t.Errorf("replicaCount = %v (%T), want 5", result["replicaCount"], result["replicaCount"])
	}

	if result["debug"] != true {
		t.Errorf("debug = %v, want true", result["debug"])
	}
}

func TestValuesMerger_MergeValues_MergePrecedence(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	// Create a temp values file
	tmpDir := t.TempDir()
	valuesFile := filepath.Join(tmpDir, "values.yaml")
	if err := os.WriteFile(valuesFile, []byte("replicaCount: 10\nfromFile: true\n"), 0644); err != nil {
		t.Fatalf("Failed to write values file: %v", err)
	}

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: helmv2.HelmReleaseSpec{
			Values: &apiextensionsv1.JSON{
				Raw: []byte(`{"replicaCount": 1, "inline": true}`),
			},
			ValuesFrom: []helmv2.ValuesReference{
				{
					Kind: "ConfigMap",
					Name: "my-values",
				},
			},
		},
	}

	resources := map[string]*unstructured.Unstructured{
		"ConfigMap/default/my-values": {
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"data": map[string]interface{}{
					"values.yaml": "replicaCount: 5\nfromConfigMap: true\n",
				},
			},
		},
	}

	setValues := map[string]string{
		"replicaCount": "20",
		"fromSet":      "true",
	}

	result, err := merger.MergeValues(ctx, hr, resources, []string{valuesFile}, setValues)
	if err != nil {
		t.Fatalf("MergeValues() error = %v", err)
	}

	// --set values should have highest precedence
	if result["replicaCount"] != int64(20) {
		t.Errorf("replicaCount = %v, want 20 (from --set)", result["replicaCount"])
	}

	// All sources should be present
	if result["inline"] != true {
		t.Errorf("inline = %v, want true", result["inline"])
	}
	if result["fromConfigMap"] != true {
		t.Errorf("fromConfigMap = %v, want true", result["fromConfigMap"])
	}
	if result["fromFile"] != true {
		t.Errorf("fromFile = %v, want true", result["fromFile"])
	}
	if result["fromSet"] != true {
		t.Errorf("fromSet = %v, want true", result["fromSet"])
	}
}

func TestValuesMerger_MergeValues_UnsupportedKind(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: helmv2.HelmReleaseSpec{
			ValuesFrom: []helmv2.ValuesReference{
				{
					Kind: "UnsupportedKind",
					Name: "my-values",
				},
			},
		},
	}

	resources := map[string]*unstructured.Unstructured{
		"UnsupportedKind/default/my-values": {
			Object: map[string]interface{}{
				"data": map[string]interface{}{
					"values.yaml": "key: value\n",
				},
			},
		},
	}

	_, err := merger.MergeValues(ctx, hr, resources, nil, nil)
	if err == nil {
		t.Fatal("MergeValues() should error for unsupported kind")
	}
}

func TestValuesMerger_MergeValues_MissingValuesKey(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: helmv2.HelmReleaseSpec{
			ValuesFrom: []helmv2.ValuesReference{
				{
					Kind:      "ConfigMap",
					Name:      "my-values",
					ValuesKey: "missing-key.yaml",
				},
			},
		},
	}

	resources := map[string]*unstructured.Unstructured{
		"ConfigMap/default/my-values": {
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"data": map[string]interface{}{
					"values.yaml": "key: value\n",
				},
			},
		},
	}

	_, err := merger.MergeValues(ctx, hr, resources, nil, nil)
	if err == nil {
		t.Fatal("MergeValues() should error for missing values key")
	}
}

func TestValuesMerger_MergeValues_OptionalMissingKey(t *testing.T) {
	merger := NewValuesMerger()
	ctx := context.Background()

	hr := &helmv2.HelmRelease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: helmv2.HelmReleaseSpec{
			ValuesFrom: []helmv2.ValuesReference{
				{
					Kind:      "ConfigMap",
					Name:      "my-values",
					ValuesKey: "missing-key.yaml",
					Optional:  true,
				},
			},
		},
	}

	resources := map[string]*unstructured.Unstructured{
		"ConfigMap/default/my-values": {
			Object: map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "ConfigMap",
				"data": map[string]interface{}{
					"values.yaml": "key: value\n",
				},
			},
		},
	}

	result, err := merger.MergeValues(ctx, hr, resources, nil, nil)
	if err != nil {
		t.Fatalf("MergeValues() error = %v, should not error for optional missing key", err)
	}

	if len(result) != 0 {
		t.Errorf("result should be empty, got %v", result)
	}
}

func TestSetNestedMap(t *testing.T) {
	tests := []struct {
		name     string
		initial  map[string]interface{}
		path     string
		value    map[string]interface{}
		expected map[string]interface{}
		wantErr  bool
	}{
		{
			name:    "simple path",
			initial: map[string]interface{}{},
			path:    "key",
			value:   map[string]interface{}{"nested": "value"},
			expected: map[string]interface{}{
				"key": map[string]interface{}{"nested": "value"},
			},
		},
		{
			name:    "nested path",
			initial: map[string]interface{}{},
			path:    "a.b.c",
			value:   map[string]interface{}{"leaf": "value"},
			expected: map[string]interface{}{
				"a": map[string]interface{}{
					"b": map[string]interface{}{
						"c": map[string]interface{}{"leaf": "value"},
					},
				},
			},
		},
		{
			name: "path conflict with non-map",
			initial: map[string]interface{}{
				"a": "string",
			},
			path:    "a.b",
			value:   map[string]interface{}{"key": "value"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := setNestedMap(tt.initial, tt.path, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("setNestedMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !mapsEqual(tt.initial, tt.expected) {
				t.Errorf("setNestedMap() result = %v, expected %v", tt.initial, tt.expected)
			}
		})
	}
}

func TestLoadValuesFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Valid YAML file
	validFile := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(validFile, []byte("key: value\nnested:\n  inner: data\n"), 0644); err != nil {
		t.Fatalf("Failed to write valid file: %v", err)
	}

	values, err := loadValuesFile(validFile)
	if err != nil {
		t.Fatalf("loadValuesFile() error = %v", err)
	}
	if values["key"] != "value" {
		t.Errorf("key = %v, want value", values["key"])
	}

	// Non-existent file
	_, err = loadValuesFile(filepath.Join(tmpDir, "nonexistent.yaml"))
	if err == nil {
		t.Error("loadValuesFile() should error for non-existent file")
	}

	// Invalid YAML
	invalidFile := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidFile, []byte("invalid: yaml: content: ["), 0644); err != nil {
		t.Fatalf("Failed to write invalid file: %v", err)
	}

	_, err = loadValuesFile(invalidFile)
	if err == nil {
		t.Error("loadValuesFile() should error for invalid YAML")
	}
}
