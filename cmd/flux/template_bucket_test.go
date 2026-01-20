//go:build unit
// +build unit

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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestDownloadBucketFromUnstructured_MissingSpec(t *testing.T) {
	u := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "source.toolkit.fluxcd.io/v1",
			"kind":       "Bucket",
			"metadata": map[string]interface{}{
				"name":      "test-bucket",
				"namespace": "flux-system",
			},
			// No spec
		},
	}

	clonedRepos := make(map[string]string)
	_, err := downloadBucketFromUnstructured(u, clonedRepos)
	if err == nil {
		t.Error("expected error for missing spec, got nil")
	}
	if err != nil && err.Error() != "failed to get spec from Bucket" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDownloadBucketFromUnstructured_MissingBucketName(t *testing.T) {
	u := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "source.toolkit.fluxcd.io/v1",
			"kind":       "Bucket",
			"metadata": map[string]interface{}{
				"name":      "test-bucket",
				"namespace": "flux-system",
			},
			"spec": map[string]interface{}{
				"endpoint": "s3.amazonaws.com",
				// No bucketName
			},
		},
	}

	clonedRepos := make(map[string]string)
	_, err := downloadBucketFromUnstructured(u, clonedRepos)
	if err == nil {
		t.Error("expected error for missing bucketName, got nil")
	}
	if err != nil && err.Error() != "failed to get spec.bucketName from Bucket" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDownloadBucketFromUnstructured_MissingEndpoint(t *testing.T) {
	u := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "source.toolkit.fluxcd.io/v1",
			"kind":       "Bucket",
			"metadata": map[string]interface{}{
				"name":      "test-bucket",
				"namespace": "flux-system",
			},
			"spec": map[string]interface{}{
				"bucketName": "my-bucket",
				// No endpoint
			},
		},
	}

	clonedRepos := make(map[string]string)
	_, err := downloadBucketFromUnstructured(u, clonedRepos)
	if err == nil {
		t.Error("expected error for missing endpoint, got nil")
	}
	if err != nil && err.Error() != "failed to get spec.endpoint from Bucket" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDownloadBucketFromUnstructured_EmptyBucketName(t *testing.T) {
	u := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "source.toolkit.fluxcd.io/v1",
			"kind":       "Bucket",
			"metadata": map[string]interface{}{
				"name":      "test-bucket",
				"namespace": "flux-system",
			},
			"spec": map[string]interface{}{
				"bucketName": "",
				"endpoint":   "s3.amazonaws.com",
			},
		},
	}

	clonedRepos := make(map[string]string)
	_, err := downloadBucketFromUnstructured(u, clonedRepos)
	if err == nil {
		t.Error("expected error for empty bucketName, got nil")
	}
	if err != nil && err.Error() != "failed to get spec.bucketName from Bucket" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDownloadBucketFromUnstructured_EmptyEndpoint(t *testing.T) {
	u := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "source.toolkit.fluxcd.io/v1",
			"kind":       "Bucket",
			"metadata": map[string]interface{}{
				"name":      "test-bucket",
				"namespace": "flux-system",
			},
			"spec": map[string]interface{}{
				"bucketName": "my-bucket",
				"endpoint":   "",
			},
		},
	}

	clonedRepos := make(map[string]string)
	_, err := downloadBucketFromUnstructured(u, clonedRepos)
	if err == nil {
		t.Error("expected error for empty endpoint, got nil")
	}
	if err != nil && err.Error() != "failed to get spec.endpoint from Bucket" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDownloadBucketFromUnstructured_UnsupportedProvider(t *testing.T) {
	u := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "source.toolkit.fluxcd.io/v1",
			"kind":       "Bucket",
			"metadata": map[string]interface{}{
				"name":      "test-bucket",
				"namespace": "flux-system",
			},
			"spec": map[string]interface{}{
				"bucketName": "my-bucket",
				"endpoint":   "s3.amazonaws.com",
				"provider":   "unsupported-provider",
			},
		},
	}

	clonedRepos := make(map[string]string)
	_, err := downloadBucketFromUnstructured(u, clonedRepos)
	if err == nil {
		t.Error("expected error for unsupported provider, got nil")
	}
	expectedErr := "unsupported bucket provider: unsupported-provider"
	if err != nil && err.Error() != expectedErr {
		t.Errorf("unexpected error message: got %v, want %v", err, expectedErr)
	}
}

func TestDownloadBucketFromUnstructured_Caching(t *testing.T) {
	// Create a temp directory to simulate a previously downloaded bucket
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(testFile, []byte("test: data"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	u := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "source.toolkit.fluxcd.io/v1",
			"kind":       "Bucket",
			"metadata": map[string]interface{}{
				"name":      "test-bucket",
				"namespace": "flux-system",
			},
			"spec": map[string]interface{}{
				"bucketName": "my-bucket",
				"endpoint":   "s3.amazonaws.com",
			},
		},
	}

	// Pre-populate the cache
	clonedRepos := map[string]string{
		"bucket/flux-system/test-bucket": tmpDir,
	}

	// Should return cached result without trying to download
	result, err := downloadBucketFromUnstructured(u, clonedRepos)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != tmpDir {
		t.Errorf("expected cached path %s, got %s", tmpDir, result)
	}
}

func TestDownloadBucketFromUnstructured_CacheKeyFormat(t *testing.T) {
	// Test that cache key is correctly formatted as "bucket/namespace/name"
	tests := []struct {
		namespace   string
		name        string
		expectedKey string
	}{
		{"flux-system", "my-bucket", "bucket/flux-system/my-bucket"},
		{"default", "test", "bucket/default/test"},
		{"production", "data-bucket", "bucket/production/data-bucket"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedKey, func(t *testing.T) {
			tmpDir := t.TempDir()

			u := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "source.toolkit.fluxcd.io/v1",
					"kind":       "Bucket",
					"metadata": map[string]interface{}{
						"name":      tt.name,
						"namespace": tt.namespace,
					},
					"spec": map[string]interface{}{
						"bucketName": "bucket-name",
						"endpoint":   "s3.amazonaws.com",
					},
				},
			}

			// Pre-populate cache with expected key
			clonedRepos := map[string]string{
				tt.expectedKey: tmpDir,
			}

			// If the cache key is correct, this should return without error
			result, err := downloadBucketFromUnstructured(u, clonedRepos)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tmpDir {
				t.Errorf("cache key mismatch: expected %s to be cached", tt.expectedKey)
			}
		})
	}
}

func TestParseBucketSourceFromManifest(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "bucket.yaml")

	manifestYAML := `---
apiVersion: source.toolkit.fluxcd.io/v1
kind: Bucket
metadata:
  name: my-s3-bucket
  namespace: flux-system
spec:
  provider: aws
  bucketName: manifests-bucket
  endpoint: s3.us-east-1.amazonaws.com
  region: us-east-1
  prefix: kustomize/
  interval: 10m
`

	if err := os.WriteFile(manifestPath, []byte(manifestYAML), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	resources, err := parseAllResources(manifestPath)
	if err != nil {
		t.Fatalf("parseAllResources failed: %v", err)
	}

	// Verify Bucket is stored in sources
	bucketKey := "Bucket/my-s3-bucket"
	source, found := resources.sources[bucketKey]
	if !found {
		t.Errorf("Bucket 'my-s3-bucket' not found in sources")
	}

	if source != nil {
		// Verify the source has correct metadata
		if source.GetName() != "my-s3-bucket" {
			t.Errorf("expected name 'my-s3-bucket', got '%s'", source.GetName())
		}
		if source.GetNamespace() != "flux-system" {
			t.Errorf("expected namespace 'flux-system', got '%s'", source.GetNamespace())
		}
		if source.GetKind() != "Bucket" {
			t.Errorf("expected kind 'Bucket', got '%s'", source.GetKind())
		}
	}
}

func TestParseBucketSourceWithKustomization(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "ks-with-bucket.yaml")

	manifestYAML := `---
apiVersion: source.toolkit.fluxcd.io/v1
kind: Bucket
metadata:
  name: configs-bucket
  namespace: flux-system
spec:
  provider: gcp
  bucketName: my-gcp-bucket
  endpoint: storage.googleapis.com
  prefix: configs/
---
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: my-app
  namespace: flux-system
spec:
  interval: 10m
  path: "./overlays/production"
  sourceRef:
    kind: Bucket
    name: configs-bucket
`

	if err := os.WriteFile(manifestPath, []byte(manifestYAML), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	resources, err := parseAllResources(manifestPath)
	if err != nil {
		t.Fatalf("parseAllResources failed: %v", err)
	}

	// Verify Bucket source is found
	if _, found := resources.sources["Bucket/configs-bucket"]; !found {
		t.Error("Bucket 'configs-bucket' not found in sources")
	}

	// Verify Kustomization is found
	if len(resources.kustomizations) != 1 {
		t.Errorf("expected 1 Kustomization, got %d", len(resources.kustomizations))
	}

	if len(resources.kustomizations) > 0 {
		ks := resources.kustomizations[0]
		if ks.Spec.SourceRef.Kind != "Bucket" {
			t.Errorf("expected sourceRef.kind 'Bucket', got '%s'", ks.Spec.SourceRef.Kind)
		}
		if ks.Spec.SourceRef.Name != "configs-bucket" {
			t.Errorf("expected sourceRef.name 'configs-bucket', got '%s'", ks.Spec.SourceRef.Name)
		}
	}
}

func TestParseMultipleBucketProviders(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "multi-bucket.yaml")

	manifestYAML := `---
apiVersion: source.toolkit.fluxcd.io/v1
kind: Bucket
metadata:
  name: aws-bucket
  namespace: flux-system
spec:
  provider: aws
  bucketName: aws-manifests
  endpoint: s3.us-west-2.amazonaws.com
  region: us-west-2
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: Bucket
metadata:
  name: gcp-bucket
  namespace: flux-system
spec:
  provider: gcp
  bucketName: gcp-manifests
  endpoint: storage.googleapis.com
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: Bucket
metadata:
  name: azure-bucket
  namespace: flux-system
spec:
  provider: azure
  bucketName: azure-manifests
  endpoint: myaccount.blob.core.windows.net
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: Bucket
metadata:
  name: minio-bucket
  namespace: flux-system
spec:
  provider: generic
  bucketName: minio-manifests
  endpoint: minio.local:9000
  insecure: true
`

	if err := os.WriteFile(manifestPath, []byte(manifestYAML), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	resources, err := parseAllResources(manifestPath)
	if err != nil {
		t.Fatalf("parseAllResources failed: %v", err)
	}

	// Verify all 4 buckets are found
	expectedBuckets := []string{"aws-bucket", "gcp-bucket", "azure-bucket", "minio-bucket"}
	for _, name := range expectedBuckets {
		key := "Bucket/" + name
		if _, found := resources.sources[key]; !found {
			t.Errorf("Bucket '%s' not found in sources", name)
		}
	}
}

func TestBucketSourceLookupFormats(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "bucket-lookup.yaml")

	manifestYAML := `---
apiVersion: source.toolkit.fluxcd.io/v1
kind: Bucket
metadata:
  name: test-bucket
  namespace: custom-namespace
spec:
  provider: aws
  bucketName: test
  endpoint: s3.amazonaws.com
`

	if err := os.WriteFile(manifestPath, []byte(manifestYAML), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	resources, err := parseAllResources(manifestPath)
	if err != nil {
		t.Fatalf("parseAllResources failed: %v", err)
	}

	// Test both lookup formats (Kind/name and Kind/namespace/name)
	lookupFormats := []string{
		"Bucket/test-bucket",
		"Bucket/custom-namespace/test-bucket",
	}

	for _, format := range lookupFormats {
		if _, found := resources.sources[format]; !found {
			t.Errorf("Bucket not found with key format: %s", format)
		}
	}
}

func TestBucketWithAllOptionalFields(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "bucket-full.yaml")

	manifestYAML := `---
apiVersion: source.toolkit.fluxcd.io/v1
kind: Bucket
metadata:
  name: full-bucket
  namespace: flux-system
spec:
  provider: aws
  bucketName: my-bucket
  endpoint: s3.us-east-1.amazonaws.com
  region: us-east-1
  prefix: path/to/files/
  insecure: false
  interval: 5m
  timeout: 60s
`

	if err := os.WriteFile(manifestPath, []byte(manifestYAML), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	resources, err := parseAllResources(manifestPath)
	if err != nil {
		t.Fatalf("parseAllResources failed: %v", err)
	}

	source, found := resources.sources["Bucket/full-bucket"]
	if !found {
		t.Fatal("Bucket 'full-bucket' not found in sources")
	}

	// Verify spec fields can be extracted
	spec, _, _ := unstructured.NestedMap(source.Object, "spec")
	if spec == nil {
		t.Fatal("failed to get spec from Bucket")
	}

	// Check provider
	provider, _, _ := unstructured.NestedString(spec, "provider")
	if provider != "aws" {
		t.Errorf("expected provider 'aws', got '%s'", provider)
	}

	// Check bucketName
	bucketName, _, _ := unstructured.NestedString(spec, "bucketName")
	if bucketName != "my-bucket" {
		t.Errorf("expected bucketName 'my-bucket', got '%s'", bucketName)
	}

	// Check endpoint
	endpoint, _, _ := unstructured.NestedString(spec, "endpoint")
	if endpoint != "s3.us-east-1.amazonaws.com" {
		t.Errorf("expected endpoint 's3.us-east-1.amazonaws.com', got '%s'", endpoint)
	}

	// Check region
	region, _, _ := unstructured.NestedString(spec, "region")
	if region != "us-east-1" {
		t.Errorf("expected region 'us-east-1', got '%s'", region)
	}

	// Check prefix
	prefix, _, _ := unstructured.NestedString(spec, "prefix")
	if prefix != "path/to/files/" {
		t.Errorf("expected prefix 'path/to/files/', got '%s'", prefix)
	}

	// Check insecure
	insecure, _, _ := unstructured.NestedBool(spec, "insecure")
	if insecure != false {
		t.Errorf("expected insecure 'false', got '%v'", insecure)
	}
}
