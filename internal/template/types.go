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

	"helm.sh/helm/v3/pkg/chart"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
)

// HelmTemplateOptions contains options for templating a HelmRelease
type HelmTemplateOptions struct {
	// HelmRelease is the HelmRelease resource to template
	HelmRelease *helmv2.HelmRelease

	// Sources are source resources (HelmRepository, GitRepository, etc.) keyed by "Kind/namespace/name" or "Kind/name"
	Sources map[string]*unstructured.Unstructured
}

// ChartFetcher fetches Helm charts from various sources
type ChartFetcher interface {
	// Fetch fetches a chart from the given source
	Fetch(ctx context.Context, opts *FetchOptions) (*chart.Chart, error)
}

// FetchOptions contains options for fetching a chart
type FetchOptions struct {
	// ChartName is the name of the chart to fetch
	ChartName string

	// ChartVersion is the version of the chart to fetch
	ChartVersion string

	// Source is the source resource (HelmRepository, etc.) as an unstructured object
	Source *unstructured.Unstructured

	// RegistryCredentials contains credentials for OCI registries (provided directly, not fetched from cluster)
	RegistryCredentials *RegistryCredentials
}

// RegistryCredentials contains credentials for accessing OCI registries
type RegistryCredentials struct {
	// Username for basic auth
	Username string

	// Password for basic auth
	Password string

	// CAFile is the path to a CA certificate file
	CAFile string

	// CertFile is the path to a client certificate file
	CertFile string

	// KeyFile is the path to a client key file
	KeyFile string

	// Insecure allows insecure connections
	Insecure bool
}

// PostRenderer applies post-rendering transformations to rendered manifests
type PostRenderer interface {
	// Run applies post-rendering to the given manifests
	Run(renderedManifests []byte) ([]byte, error)
}
