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
	"sigs.k8s.io/controller-runtime/pkg/client"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"
)

// HelmRenderer renders HelmRelease resources into Kubernetes manifests
type HelmRenderer struct {
	chartFetcher ChartFetcher
	valuesMerger *ValuesMerger
}

// NewHelmRenderer creates a new HelmRenderer
func NewHelmRenderer(kubeClient client.Client, dryRun bool) *HelmRenderer {
	return &HelmRenderer{
		chartFetcher: NewChartFetcher(),
		valuesMerger: NewValuesMerger(kubeClient, dryRun),
	}
}

// Render renders a HelmRelease into Kubernetes manifests
func (r *HelmRenderer) Render(ctx context.Context, opts *HelmTemplateOptions) ([]byte, error) {
	// Determine chart source
	var chartName, chartVersion string
	var repository *sourcev1.HelmRepository

	if opts.HelmRelease.Spec.Chart != nil {
		chartName = opts.HelmRelease.Spec.Chart.Spec.Chart
		chartVersion = opts.HelmRelease.Spec.Chart.Spec.Version

		// Find the referenced repository
		sourceRef := opts.HelmRelease.Spec.Chart.Spec.SourceRef
		repoKey := fmt.Sprintf("%s/%s", sourceRef.Namespace, sourceRef.Name)
		if sourceRef.Namespace == "" {
			repoKey = fmt.Sprintf("%s/%s", opts.HelmRelease.Namespace, sourceRef.Name)
		}

		var ok bool
		repository, ok = opts.HelmRepositories[repoKey]
		if !ok && opts.ChartPath == "" {
			// Try without namespace
			repository, ok = opts.HelmRepositories[sourceRef.Name]
			if !ok {
				return nil, fmt.Errorf("HelmRepository %q not found in provided sources", repoKey)
			}
		}
	}

	// Fetch the chart
	fetchOpts := &FetchOptions{
		ChartName:    chartName,
		ChartVersion: chartVersion,
		Repository:   repository,
		LocalPath:    opts.ChartPath,
		KubeClient:   opts.KubeClient,
		Namespace:    opts.Namespace,
	}

	chrt, err := r.chartFetcher.Fetch(ctx, fetchOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch chart: %w", err)
	}

	// Merge values
	values, err := r.valuesMerger.MergeValues(ctx, opts.HelmRelease, opts.ValuesFiles, opts.SetValues)
	if err != nil {
		return nil, fmt.Errorf("failed to merge values: %w", err)
	}

	// Determine release name and namespace
	releaseName := opts.ReleaseName
	if releaseName == "" {
		releaseName = opts.HelmRelease.Spec.ReleaseName
	}
	if releaseName == "" {
		releaseName = opts.HelmRelease.Name
	}

	namespace := opts.Namespace
	if namespace == "" {
		namespace = opts.HelmRelease.Spec.TargetNamespace
	}
	if namespace == "" {
		namespace = opts.HelmRelease.Namespace
	}
	if namespace == "" {
		namespace = "default"
	}

	// Render the chart
	rendered, err := r.renderChart(chrt, releaseName, namespace, values, opts)
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
func (r *HelmRenderer) renderChart(chrt *chart.Chart, releaseName, namespace string, values map[string]interface{}, opts *HelmTemplateOptions) ([]byte, error) {
	// Create release options
	releaseOpts := chartutil.ReleaseOptions{
		Name:      releaseName,
		Namespace: namespace,
		Revision:  1,
		IsInstall: true,
		IsUpgrade: false,
	}

	// Create capabilities
	caps := chartutil.DefaultCapabilities.Copy()
	if opts.KubeVersion != "" {
		kubeVersion, err := chartutil.ParseKubeVersion(opts.KubeVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to parse kube version %q: %w", opts.KubeVersion, err)
		}
		caps.KubeVersion = *kubeVersion
	}

	if len(opts.APIVersions) > 0 {
		caps.APIVersions = append(caps.APIVersions, opts.APIVersions...)
	}

	// Coalesce values
	valuesToRender, err := chartutil.ToRenderValues(chrt, values, releaseOpts, caps)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare values for rendering: %w", err)
	}

	// Render templates
	eng := engine.Engine{
		Strict:   true,
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
func RenderMultipleHelmReleases(ctx context.Context, kubeClient client.Client, dryRun bool, releases []*helmv2.HelmRelease, repositories map[string]*sourcev1.HelmRepository) ([]byte, error) {
	renderer := NewHelmRenderer(kubeClient, dryRun)

	var buf bytes.Buffer
	for _, hr := range releases {
		opts := &HelmTemplateOptions{
			HelmRelease:      hr,
			HelmRepositories: repositories,
			KubeClient:       kubeClient,
			DryRun:           dryRun,
		}

		rendered, err := renderer.Render(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to render HelmRelease %s/%s: %w", hr.Namespace, hr.Name, err)
		}

		buf.Write(rendered)
	}

	return buf.Bytes(), nil
}
