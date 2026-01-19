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
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
	"github.com/fluxcd/pkg/chartutil"
)

// ValuesMerger handles merging of Helm values from various sources
type ValuesMerger struct {
	kubeClient client.Client
	dryRun     bool
}

// NewValuesMerger creates a new ValuesMerger
func NewValuesMerger(kubeClient client.Client, dryRun bool) *ValuesMerger {
	return &ValuesMerger{
		kubeClient: kubeClient,
		dryRun:     dryRun,
	}
}

// MergeValues merges values from HelmRelease spec, valuesFrom references, values files, and set values
func (m *ValuesMerger) MergeValues(ctx context.Context, hr *helmv2.HelmRelease, valuesFiles []string, setValues map[string]string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// 1. Get values from HelmRelease spec (inline values)
	if hr.Spec.Values != nil {
		var inlineValues map[string]interface{}
		if err := json.Unmarshal(hr.Spec.Values.Raw, &inlineValues); err != nil {
			return nil, fmt.Errorf("failed to unmarshal inline values: %w", err)
		}
		result = mergeMaps(result, inlineValues)
	}

	// 2. Get values from valuesFrom references (ConfigMaps/Secrets)
	if !m.dryRun && m.kubeClient != nil && len(hr.Spec.ValuesFrom) > 0 {
		refValues, err := chartutil.ChartValuesFromReferences(ctx,
			logr.Discard(),
			m.kubeClient,
			hr.GetNamespace(),
			hr.GetValues(),
			hr.Spec.ValuesFrom...)
		if err != nil {
			return nil, fmt.Errorf("failed to get values from references: %w", err)
		}
		result = mergeMaps(result, refValues)
	}

	// 3. Merge additional values files
	for _, file := range valuesFiles {
		fileValues, err := loadValuesFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to load values file %s: %w", file, err)
		}
		result = mergeMaps(result, fileValues)
	}

	// 4. Apply --set values
	for key, value := range setValues {
		if err := setNestedValue(result, key, value); err != nil {
			return nil, fmt.Errorf("failed to set value %s=%s: %w", key, value, err)
		}
	}

	return result, nil
}

// loadValuesFile loads values from a YAML file
func loadValuesFile(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var values map[string]interface{}
	if err := yaml.Unmarshal(data, &values); err != nil {
		return nil, err
	}

	return values, nil
}

// setNestedValue sets a value in a nested map using dot notation
// e.g., "image.tag" = "v1.0.0" sets result["image"]["tag"] = "v1.0.0"
func setNestedValue(m map[string]interface{}, key, value string) error {
	keys := strings.Split(key, ".")
	current := m

	for i, k := range keys {
		if i == len(keys)-1 {
			// Last key - set the value
			current[k] = parseValue(value)
		} else {
			// Not the last key - navigate or create nested map
			if _, ok := current[k]; !ok {
				current[k] = make(map[string]interface{})
			}
			if nested, ok := current[k].(map[string]interface{}); ok {
				current = nested
			} else {
				return fmt.Errorf("key %s is not a map", strings.Join(keys[:i+1], "."))
			}
		}
	}

	return nil
}

// parseValue attempts to parse a string value into its appropriate type
func parseValue(s string) interface{} {
	// Try to parse as bool
	if s == "true" {
		return true
	}
	if s == "false" {
		return false
	}

	// Try to parse as int
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}

	// Try to parse as float
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}

	// Return as string
	return s
}

// mergeMaps recursively merges src into dst
func mergeMaps(dst, src map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = make(map[string]interface{})
	}

	for key, srcVal := range src {
		if dstVal, ok := dst[key]; ok {
			// Both have the key - check if both are maps
			srcMap, srcIsMap := srcVal.(map[string]interface{})
			dstMap, dstIsMap := dstVal.(map[string]interface{})
			if srcIsMap && dstIsMap {
				dst[key] = mergeMaps(dstMap, srcMap)
				continue
			}
		}
		// Either key doesn't exist in dst, or one/both values aren't maps
		dst[key] = srcVal
	}

	return dst
}
