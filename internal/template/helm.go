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
	"context"
	"fmt"
	"strings"

	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
)

// HelmRenderer renders HelmRelease resources into Kubernetes manifests
type HelmRenderer struct {
	chartFetcher ChartFetcher
	valuesMerger *ValuesMerger
}

// NewHelmRenderer creates a new HelmRenderer
func NewHelmRenderer() *HelmRenderer {
	return &HelmRenderer{
		chartFetcher: NewChartFetcher(),
		valuesMerger: NewValuesMerger(),
	}
}

// Render renders a HelmRelease into Kubernetes manifests
func (r *HelmRenderer) Render(ctx context.Context, opts *HelmTemplateOptions) ([]byte, error) {
	// Determine chart source
	var chartName, chartVersion string
	var repositorySource *unstructured.Unstructured

	if opts.HelmRelease.Spec.Chart != nil {
		chartName = opts.HelmRelease.Spec.Chart.Spec.Chart
		chartVersion = opts.HelmRelease.Spec.Chart.Spec.Version

		// Find the referenced repository from generic sources
		sourceRef := opts.HelmRelease.Spec.Chart.Spec.SourceRef
		namespace := sourceRef.Namespace
		if namespace == "" {
			namespace = opts.HelmRelease.Namespace
		}

		// Look up using Kind/namespace/name format
		repoKey := fmt.Sprintf("%s/%s/%s", sourceRef.Kind, namespace, sourceRef.Name)
		var found bool
		repositorySource, found = opts.Sources[repoKey]
		if !found {
			// Try Kind/name format
			repoKey = fmt.Sprintf("%s/%s", sourceRef.Kind, sourceRef.Name)
			repositorySource, found = opts.Sources[repoKey]
			if !found {
				return nil, fmt.Errorf("%s %q not found in provided sources", sourceRef.Kind, sourceRef.Name)
			}
		}
	}

	// Fetch the chart
	fetchOpts := &FetchOptions{
		ChartName:    chartName,
		ChartVersion: chartVersion,
		Source:       repositorySource,
	}

	chrt, err := r.chartFetcher.Fetch(ctx, fetchOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch chart: %w", err)
	}

	// Merge values (pass Sources which may contain ConfigMaps/Secrets for valuesFrom)
	values, err := r.valuesMerger.MergeValues(ctx, opts.HelmRelease, opts.Sources)
	if err != nil {
		return nil, fmt.Errorf("failed to merge values: %w", err)
	}

	// Determine release name and namespace from the HelmRelease spec
	releaseName := opts.HelmRelease.Spec.ReleaseName
	if releaseName == "" {
		releaseName = opts.HelmRelease.Name
	}

	namespace := opts.HelmRelease.Spec.TargetNamespace
	if namespace == "" {
		namespace = opts.HelmRelease.Namespace
	}
	if namespace == "" {
		namespace = "default"
	}

	// Render the chart
	rendered, err := r.renderChart(chrt, releaseName, namespace, values)
	if err != nil {
		return nil, fmt.Errorf("failed to render chart: %w", err)
	}

	// Apply post-renderers if specified
	if opts.HelmRelease.Spec.PostRenderers != nil {
		for i, pr := range opts.HelmRelease.Spec.PostRenderers {
			if pr.Kustomize != nil {
				postRenderer := NewKustomizePostRenderer(pr.Kustomize)
				rendered, err = postRenderer.Run(rendered)
				if err != nil {
					return nil, fmt.Errorf("post-renderer %d failed: %w", i, err)
				}
			}
		}
	}

	return rendered, nil
}

// renderChart renders a Helm chart with the given values
func (r *HelmRenderer) renderChart(chrt *chart.Chart, releaseName, namespace string, values map[string]interface{}) ([]byte, error) {
	// Create release options
	releaseOpts := chartutil.ReleaseOptions{
		Name:      releaseName,
		Namespace: namespace,
		Revision:  1,
		IsInstall: true,
		IsUpgrade: false,
	}

	// Create capabilities with defaults
	caps := chartutil.DefaultCapabilities.Copy()

	// Coalesce values
	valuesToRender, err := chartutil.ToRenderValues(chrt, values, releaseOpts, caps)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare values for rendering: %w", err)
	}

	// Render templates
	eng := engine.Engine{
		Strict:   false,
		LintMode: false,
	}

	rendered, err := eng.Render(chrt, valuesToRender)
	if err != nil {
		return nil, fmt.Errorf("failed to render templates: %w", err)
	}

	// Combine rendered templates into a single YAML document
	var buf bytes.Buffer
	for name, content := range rendered {
		// Skip empty files and notes
		if strings.TrimSpace(content) == "" {
			continue
		}
		if strings.HasSuffix(name, "NOTES.txt") {
			continue
		}
		// Skip test files
		if strings.Contains(name, "/tests/") {
			continue
		}

		buf.WriteString("---\n")
		buf.WriteString(fmt.Sprintf("# Source: %s\n", name))
		buf.WriteString(content)
		if !strings.HasSuffix(content, "\n") {
			buf.WriteString("\n")
		}
	}

	return buf.Bytes(), nil
}

// RenderMultipleHelmReleases renders multiple HelmReleases and combines the output
func RenderMultipleHelmReleases(ctx context.Context, releases []*helmv2.HelmRelease, sources map[string]*unstructured.Unstructured) ([]byte, error) {
	renderer := NewHelmRenderer()

	var buf bytes.Buffer
	for _, hr := range releases {
		opts := &HelmTemplateOptions{
			HelmRelease: hr,
			Sources:     sources,
		}

		rendered, err := renderer.Render(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to render HelmRelease %s/%s: %w", hr.Namespace, hr.Name, err)
		}

		buf.Write(rendered)
	}

	return buf.Bytes(), nil
}
