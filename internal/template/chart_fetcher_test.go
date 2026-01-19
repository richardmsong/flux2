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

func TestIsVersionConstraint(t *testing.T) {
	tests := []struct {
		version    string
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
