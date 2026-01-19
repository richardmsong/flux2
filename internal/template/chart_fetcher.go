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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/repo"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
)

// DefaultChartFetcher is the default implementation of ChartFetcher
type DefaultChartFetcher struct{}

// NewChartFetcher creates a new DefaultChartFetcher
func NewChartFetcher() *DefaultChartFetcher {
	return &DefaultChartFetcher{}
}

// Fetch fetches a chart from the given source
func (f *DefaultChartFetcher) Fetch(ctx context.Context, opts *FetchOptions) (*chart.Chart, error) {
	// If local path is provided, load from there
	if opts.LocalPath != "" {
		return f.fetchFromLocal(opts.LocalPath)
	}

	if opts.Repository == nil {
		return nil, fmt.Errorf("repository is required when local path is not provided")
	}

	// Determine if this is an OCI repository
	if opts.Repository.Spec.Type == sourcev1.HelmRepositoryTypeOCI {
		return f.fetchFromOCI(ctx, opts)
	}

	// Otherwise, fetch from HTTP(S) repository
	return f.fetchFromHTTP(ctx, opts)
}

// fetchFromLocal loads a chart from a local directory or archive
func (f *DefaultChartFetcher) fetchFromLocal(path string) (*chart.Chart, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	return loader.Load(absPath)
}

// fetchFromHTTP fetches a chart from an HTTP(S) Helm repository
func (f *DefaultChartFetcher) fetchFromHTTP(ctx context.Context, opts *FetchOptions) (*chart.Chart, error) {
	repoURL := opts.Repository.Spec.URL

	// Fetch credentials if secretRef is provided
	creds, err := f.getCredentials(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	// Create HTTP client with TLS config
	httpClient, err := f.createHTTPClient(creds)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Fetch repository index
	indexURL, err := url.JoinPath(repoURL, "index.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to build index URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, indexURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if creds != nil && creds.Username != "" {
		req.SetBasicAuth(creds.Username, creds.Password)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch repository index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch repository index: HTTP %d", resp.StatusCode)
	}

	indexData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read repository index: %w", err)
	}

	// Parse repository index
	var indexFile repo.IndexFile
	if err := yaml.Unmarshal(indexData, &indexFile); err != nil {
		return nil, fmt.Errorf("failed to parse repository index: %w", err)
	}

	// Find the chart version
	chartVersions, ok := indexFile.Entries[opts.ChartName]
	if !ok || len(chartVersions) == 0 {
		return nil, fmt.Errorf("chart %q not found in repository", opts.ChartName)
	}

	var targetVersion *repo.ChartVersion
	if opts.ChartVersion != "" {
		for _, cv := range chartVersions {
			if cv.Version == opts.ChartVersion {
				targetVersion = cv
				break
			}
		}
		if targetVersion == nil {
			return nil, fmt.Errorf("chart %q version %q not found in repository", opts.ChartName, opts.ChartVersion)
		}
	} else {
		// Use the first (latest) version
		targetVersion = chartVersions[0]
	}

	if len(targetVersion.URLs) == 0 {
		return nil, fmt.Errorf("no download URL found for chart %q version %q", opts.ChartName, targetVersion.Version)
	}

	// Download the chart
	chartURL := targetVersion.URLs[0]
	if !strings.HasPrefix(chartURL, "http://") && !strings.HasPrefix(chartURL, "https://") {
		chartURL, err = url.JoinPath(repoURL, chartURL)
		if err != nil {
			return nil, fmt.Errorf("failed to build chart URL: %w", err)
		}
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, chartURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create chart request: %w", err)
	}

	if creds != nil && creds.Username != "" {
		req.SetBasicAuth(creds.Username, creds.Password)
	}

	resp, err = httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download chart: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download chart: HTTP %d", resp.StatusCode)
	}

	chartData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read chart data: %w", err)
	}

	return loader.LoadArchive(bytes.NewReader(chartData))
}

// fetchFromOCI fetches a chart from an OCI registry
func (f *DefaultChartFetcher) fetchFromOCI(ctx context.Context, opts *FetchOptions) (*chart.Chart, error) {
	repoURL := strings.TrimPrefix(opts.Repository.Spec.URL, "oci://")

	// Build the full image reference
	ref := fmt.Sprintf("%s/%s", repoURL, opts.ChartName)
	if opts.ChartVersion != "" {
		ref = fmt.Sprintf("%s:%s", ref, opts.ChartVersion)
	}

	// Parse the reference
	imgRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCI reference %q: %w", ref, err)
	}

	// Get credentials
	creds, err := f.getCredentials(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	// Set up crane options
	craneOpts := []crane.Option{
		crane.WithContext(ctx),
	}

	if creds != nil && creds.Username != "" {
		craneOpts = append(craneOpts, crane.WithAuth(&authn.Basic{
			Username: creds.Username,
			Password: creds.Password,
		}))
	}

	if creds != nil && creds.Insecure {
		craneOpts = append(craneOpts, crane.Insecure)
	}

	// Pull the chart as a blob
	img, err := crane.Pull(imgRef.String(), craneOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to pull OCI artifact: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to get layers: %w", err)
	}

	// Find the chart layer (typically the first layer with media type application/vnd.cncf.helm.chart.content.v1.tar+gzip)
	for _, layer := range layers {
		mediaType, err := layer.MediaType()
		if err != nil {
			continue
		}

		// Check for Helm chart media type or generic tar+gzip
		if strings.Contains(string(mediaType), "helm.chart") || strings.Contains(string(mediaType), "tar+gzip") {
			rc, err := layer.Compressed()
			if err != nil {
				return nil, fmt.Errorf("failed to get layer content: %w", err)
			}
			defer rc.Close()

			chartData, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("failed to read layer content: %w", err)
			}

			return loader.LoadArchive(bytes.NewReader(chartData))
		}
	}

	return nil, fmt.Errorf("no chart layer found in OCI artifact")
}

// getCredentials fetches credentials from a Kubernetes Secret
func (f *DefaultChartFetcher) getCredentials(ctx context.Context, opts *FetchOptions) (*RegistryCredentials, error) {
	if opts.RegistryCredentials != nil {
		return opts.RegistryCredentials, nil
	}

	if opts.Repository == nil || opts.Repository.Spec.SecretRef == nil {
		return nil, nil
	}

	if opts.KubeClient == nil {
		return nil, nil
	}

	secretName := opts.Repository.Spec.SecretRef.Name
	namespace := opts.Namespace
	if namespace == "" {
		namespace = opts.Repository.Namespace
	}

	secret := &corev1.Secret{}
	if err := opts.KubeClient.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: namespace,
	}, secret); err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", namespace, secretName, err)
	}

	creds := &RegistryCredentials{}
	if username, ok := secret.Data["username"]; ok {
		creds.Username = string(username)
	}
	if password, ok := secret.Data["password"]; ok {
		creds.Password = string(password)
	}

	return creds, nil
}

// createHTTPClient creates an HTTP client with TLS configuration
func (f *DefaultChartFetcher) createHTTPClient(creds *RegistryCredentials) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if creds != nil {
		if creds.CAFile != "" {
			caCert, err := os.ReadFile(creds.CAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA file: %w", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to append CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}

		if creds.CertFile != "" && creds.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(creds.CertFile, creds.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}

		if creds.Insecure {
			tlsConfig.InsecureSkipVerify = true
		}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}
