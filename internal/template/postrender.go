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
	"bytes"
	"fmt"
	"os"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
	kustomize "github.com/fluxcd/pkg/apis/kustomize"
	"sigs.k8s.io/kustomize/api/krusty"
	kustypes "sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	"sigs.k8s.io/kustomize/kyaml/resid"
	"sigs.k8s.io/yaml"
)

// KustomizePostRenderer applies Kustomize patches as a post-renderer
type KustomizePostRenderer struct {
	spec *helmv2.Kustomize
}

// NewKustomizePostRenderer creates a new KustomizePostRenderer from HelmRelease PostBuild spec
func NewKustomizePostRenderer(spec *helmv2.Kustomize) *KustomizePostRenderer {
	return &KustomizePostRenderer{
		spec: spec,
	}
}

// Run applies Kustomize patches to the rendered manifests
func (r *KustomizePostRenderer) Run(renderedManifests []byte) ([]byte, error) {
	if r.spec == nil {
		return renderedManifests, nil
	}

	// Create an in-memory filesystem
	fs := filesys.MakeFsInMemory()

	// Write the rendered manifests as resources
	const resourcesFile = "resources.yaml"
	if err := fs.WriteFile(resourcesFile, renderedManifests); err != nil {
		return nil, fmt.Errorf("failed to write resources to in-memory filesystem: %w", err)
	}

	// Build the kustomization
	kustomization := kustypes.Kustomization{
		TypeMeta: kustypes.TypeMeta{
			APIVersion: kustypes.KustomizationVersion,
			Kind:       kustypes.KustomizationKind,
		},
		Resources: []string{resourcesFile},
	}

	// Add patches if specified
	if len(r.spec.Patches) > 0 {
		for _, p := range r.spec.Patches {
			patch := kustypes.Patch{
				Patch: p.Patch,
			}

			if p.Target != nil {
				patch.Target = convertSelector(p.Target)
			}

			kustomization.Patches = append(kustomization.Patches, patch)
		}
	}

	// Add images if specified
	if len(r.spec.Images) > 0 {
		for _, img := range r.spec.Images {
			kustomization.Images = append(kustomization.Images, kustypes.Image{
				Name:    img.Name,
				NewName: img.NewName,
				NewTag:  img.NewTag,
				Digest:  img.Digest,
			})
		}
	}

	// Write the kustomization file
	kustomizationYAML, err := yaml.Marshal(kustomization)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal kustomization: %w", err)
	}

	if err := fs.WriteFile("kustomization.yaml", kustomizationYAML); err != nil {
		return nil, fmt.Errorf("failed to write kustomization.yaml: %w", err)
	}

	// Build with kustomize
	opts := krusty.MakeDefaultOptions()
	k := krusty.MakeKustomizer(opts)

	resMap, err := k.Run(fs, ".")
	if err != nil {
		return nil, fmt.Errorf("kustomize build failed: %w", err)
	}

	// Convert result to YAML
	var buf bytes.Buffer
	for _, res := range resMap.Resources() {
		yaml, err := res.AsYAML()
		if err != nil {
			return nil, fmt.Errorf("failed to convert resource to YAML: %w", err)
		}
		buf.WriteString("---\n")
		buf.Write(yaml)
	}

	return buf.Bytes(), nil
}

// convertSelector converts a Flux Kustomize Selector to a Kustomize API Selector
func convertSelector(s *kustomize.Selector) *kustypes.Selector {
	if s == nil {
		return nil
	}

	return &kustypes.Selector{
		ResId: resid.ResId{
			Gvk: resid.Gvk{
				Group:   s.Group,
				Version: s.Version,
				Kind:    s.Kind,
			},
			Name:      s.Name,
			Namespace: s.Namespace,
		},
		LabelSelector:      s.LabelSelector,
		AnnotationSelector: s.AnnotationSelector,
	}
}

// TempDirPostRenderer creates a temporary directory for kustomize operations
type TempDirPostRenderer struct {
	dir string
}

// NewTempDirPostRenderer creates a new TempDirPostRenderer
func NewTempDirPostRenderer() (*TempDirPostRenderer, error) {
	dir, err := os.MkdirTemp("", "flux-template-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	return &TempDirPostRenderer{dir: dir}, nil
}

// Cleanup removes the temporary directory
func (r *TempDirPostRenderer) Cleanup() error {
	if r.dir != "" {
		return os.RemoveAll(r.dir)
	}
	return nil
}
