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
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
)

// ValuesMerger handles merging of Helm values from various sources
type ValuesMerger struct{}

// NewValuesMerger creates a new ValuesMerger
func NewValuesMerger() *ValuesMerger {
	return &ValuesMerger{}
}

// MergeValues merges values from HelmRelease spec, valuesFrom references, values files, and set values.
// Resources map should contain any ConfigMaps or Secrets referenced in valuesFrom, keyed by "Kind/namespace/name".
// If a valuesFrom reference is not found in resources, an error is returned.
func (m *ValuesMerger) MergeValues(ctx context.Context, hr *helmv2.HelmRelease, resources map[string]*unstructured.Unstructured, valuesFiles []string, setValues map[string]string) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// 1. Get values from HelmRelease spec (inline values)
	if hr.Spec.Values != nil {
		var inlineValues map[string]interface{}
		if err := json.Unmarshal(hr.Spec.Values.Raw, &inlineValues); err != nil {
			return nil, fmt.Errorf("failed to unmarshal inline values: %w", err)
		}
		result = mergeMaps(result, inlineValues)
	}

	// 2. Process valuesFrom references (ConfigMaps/Secrets from manifest)
	if len(hr.Spec.ValuesFrom) > 0 {
		namespace := hr.Namespace
		if namespace == "" {
			namespace = "default"
		}

		for _, vf := range hr.Spec.ValuesFrom {
			valuesFromData, err := m.getValuesFromReference(vf, namespace, resources)
			if err != nil {
				return nil, err
			}
			result = mergeMaps(result, valuesFromData)
		}
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

// getValuesFromReference retrieves values from a ConfigMap or Secret reference
func (m *ValuesMerger) getValuesFromReference(vf helmv2.ValuesReference, namespace string, resources map[string]*unstructured.Unstructured) (map[string]interface{}, error) {
	// Determine the namespace for the reference
	refNamespace := namespace
	if vf.TargetPath != "" {
		// TargetPath is handled after getting the values
	}

	// Build the resource key
	resourceKey := fmt.Sprintf("%s/%s/%s", vf.Kind, refNamespace, vf.Name)
	resource, found := resources[resourceKey]
	if !found {
		// Try without namespace
		resourceKey = fmt.Sprintf("%s/%s", vf.Kind, vf.Name)
		resource, found = resources[resourceKey]
	}

	if !found {
		if vf.Optional {
			return make(map[string]interface{}), nil
		}
		return nil, fmt.Errorf("valuesFrom references %s %q which was not found in the provided manifest files; "+
			"include the %s in your manifest or use --values flag to provide values directly",
			vf.Kind, vf.Name, vf.Kind)
	}

	// Get the data from the resource
	var data map[string]string
	var err error

	switch vf.Kind {
	case "ConfigMap":
		data, _, err = unstructured.NestedStringMap(resource.Object, "data")
		if err != nil {
			return nil, fmt.Errorf("failed to get data from ConfigMap %q: %w", vf.Name, err)
		}
	case "Secret":
		// Secrets have base64-encoded data
		secretData, found, err := unstructured.NestedStringMap(resource.Object, "data")
		if err != nil {
			return nil, fmt.Errorf("failed to get data from Secret %q: %w", vf.Name, err)
		}
		if found {
			data = make(map[string]string)
			for k, v := range secretData {
				decoded, err := base64.StdEncoding.DecodeString(v)
				if err != nil {
					return nil, fmt.Errorf("failed to decode Secret %q key %q: %w", vf.Name, k, err)
				}
				data[k] = string(decoded)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported valuesFrom kind: %s (only ConfigMap and Secret are supported)", vf.Kind)
	}

	if data == nil {
		return make(map[string]interface{}), nil
	}

	// Determine the key to use
	valuesKey := vf.ValuesKey
	if valuesKey == "" {
		valuesKey = "values.yaml"
	}

	// Get the values content
	valuesContent, found := data[valuesKey]
	if !found {
		if vf.Optional {
			return make(map[string]interface{}), nil
		}
		return nil, fmt.Errorf("%s %q does not contain key %q", vf.Kind, vf.Name, valuesKey)
	}

	// Parse the values content as YAML
	var values map[string]interface{}
	if err := yaml.Unmarshal([]byte(valuesContent), &values); err != nil {
		return nil, fmt.Errorf("failed to parse values from %s %q key %q: %w", vf.Kind, vf.Name, valuesKey, err)
	}

	// If targetPath is specified, nest the values under that path
	if vf.TargetPath != "" {
		nested := make(map[string]interface{})
		if err := setNestedMap(nested, vf.TargetPath, values); err != nil {
			return nil, fmt.Errorf("failed to set targetPath %q: %w", vf.TargetPath, err)
		}
		return nested, nil
	}

	return values, nil
}

// setNestedMap sets a nested map value using dot notation
func setNestedMap(m map[string]interface{}, path string, value map[string]interface{}) error {
	keys := strings.Split(path, ".")
	current := m

	for i, k := range keys {
		if i == len(keys)-1 {
			current[k] = value
		} else {
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
