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
