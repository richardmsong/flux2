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
	"testing"
)

func TestMergeMaps(t *testing.T) {
	tests := []struct {
		name     string
		dst      map[string]interface{}
		src      map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name:     "nil dst",
			dst:      nil,
			src:      map[string]interface{}{"key": "value"},
			expected: map[string]interface{}{"key": "value"},
		},
		{
			name:     "empty maps",
			dst:      map[string]interface{}{},
			src:      map[string]interface{}{},
			expected: map[string]interface{}{},
		},
		{
			name:     "simple merge",
			dst:      map[string]interface{}{"a": "1"},
			src:      map[string]interface{}{"b": "2"},
			expected: map[string]interface{}{"a": "1", "b": "2"},
		},
		{
			name:     "override value",
			dst:      map[string]interface{}{"a": "1"},
			src:      map[string]interface{}{"a": "2"},
			expected: map[string]interface{}{"a": "2"},
		},
		{
			name: "nested merge",
			dst: map[string]interface{}{
				"outer": map[string]interface{}{
					"inner1": "value1",
				},
			},
			src: map[string]interface{}{
				"outer": map[string]interface{}{
					"inner2": "value2",
				},
			},
			expected: map[string]interface{}{
				"outer": map[string]interface{}{
					"inner1": "value1",
					"inner2": "value2",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeMaps(tt.dst, tt.src)
			if !mapsEqual(result, tt.expected) {
				t.Errorf("mergeMaps() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestSetNestedValue(t *testing.T) {
	tests := []struct {
		name     string
		initial  map[string]interface{}
		key      string
		value    string
		expected map[string]interface{}
		wantErr  bool
	}{
		{
			name:     "simple key",
			initial:  map[string]interface{}{},
			key:      "key",
			value:    "value",
			expected: map[string]interface{}{"key": "value"},
		},
		{
			name:     "nested key",
			initial:  map[string]interface{}{},
			key:      "outer.inner",
			value:    "value",
			expected: map[string]interface{}{"outer": map[string]interface{}{"inner": "value"}},
		},
		{
			name:     "deeply nested key",
			initial:  map[string]interface{}{},
			key:      "a.b.c",
			value:    "value",
			expected: map[string]interface{}{"a": map[string]interface{}{"b": map[string]interface{}{"c": "value"}}},
		},
		{
			name:     "boolean true",
			initial:  map[string]interface{}{},
			key:      "enabled",
			value:    "true",
			expected: map[string]interface{}{"enabled": true},
		},
		{
			name:     "boolean false",
			initial:  map[string]interface{}{},
			key:      "enabled",
			value:    "false",
			expected: map[string]interface{}{"enabled": false},
		},
		{
			name:     "integer value",
			initial:  map[string]interface{}{},
			key:      "count",
			value:    "42",
			expected: map[string]interface{}{"count": int64(42)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := setNestedValue(tt.initial, tt.key, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("setNestedValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !mapsEqual(tt.initial, tt.expected) {
				t.Errorf("setNestedValue() result = %v, expected %v", tt.initial, tt.expected)
			}
		})
	}
}

func TestParseValue(t *testing.T) {
	tests := []struct {
		input    string
		expected interface{}
	}{
		{"true", true},
		{"false", false},
		{"42", int64(42)},
		{"3.14", 3.14},
		{"hello", "hello"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseValue(tt.input)
			if result != tt.expected {
				t.Errorf("parseValue(%q) = %v (%T), expected %v (%T)", tt.input, result, result, tt.expected, tt.expected)
			}
		})
	}
}

// Helper function to compare maps
func mapsEqual(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		aMap, aIsMap := v.(map[string]interface{})
		bMap, bIsMap := bv.(map[string]interface{})
		if aIsMap && bIsMap {
			if !mapsEqual(aMap, bMap) {
				return false
			}
		} else if v != bv {
			return false
		}
	}
	return true
}
