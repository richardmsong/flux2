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
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/spf13/cobra"
	"google.golang.org/api/iterator"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1"
	"github.com/fluxcd/pkg/oci"
	ssautil "github.com/fluxcd/pkg/ssa/utils"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"

	"github.com/fluxcd/flux2/v2/internal/build"
	"github.com/fluxcd/flux2/v2/internal/template"
)

type templateFlags struct {
	file      string
	recursive bool
}

var templateArgs templateFlags

var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "Template a flux resource",
	Long: `The template command renders Flux resources (HelmRelease, Kustomization) into their
final Kubernetes manifests locally, similar to how 'helm template' works for Helm charts
or 'kustomize build' for Kustomize overlays.

This command interprets Flux resources through source-controller, helm-controller, and
kustomize-controller logic to render out the final manifests to stdout.

The command never connects to the cluster. All resources (HelmRepository, GitRepository,
ConfigMaps, Secrets for valuesFrom) must be provided in the manifest file.

The command automatically detects the resource type from the manifest and renders it
appropriately. If the file contains multiple HelmRelease or Kustomization resources,
all of them will be rendered.

For Kustomization resources that reference a GitRepository source, the git repository
will be cloned to a temporary directory and used as the source path.

When --recursive is enabled, the command will continue to render any Flux resources
(HelmRelease, Kustomization) found in the rendered output until no more Flux resources
remain. This is useful for nested deployments where a Kustomization might produce
HelmReleases or other Kustomizations.`,
	Example: `  # Template a resource (auto-detects type from manifest)
  flux template -f ./manifest.yaml

  # Template multiple resources from a single multi-document YAML file
  flux template -f ./multi-doc.yaml

  # Template from stdin (pipe from other commands)
  kustomize build ./overlay | flux template -f -
  cat manifest.yaml | flux template -f -

  # Recursively render nested Flux resources
  flux template -f ./manifest.yaml --recursive`,
	RunE: templateCmdRun,
}

func init() {
	templateCmd.Flags().StringVarP(&templateArgs.file, "file", "f", "", "path to the Flux resource manifest file (auto-detects HelmRelease or Kustomization); use '-' to read from stdin")
	templateCmd.Flags().BoolVarP(&templateArgs.recursive, "recursive", "r", false, "recursively render Flux resources found in the output")

	rootCmd.AddCommand(templateCmd)
}

// parsedResources holds all parsed resources from the manifest files
type parsedResources struct {
	helmReleases   []*helmv2.HelmRelease
	kustomizations []*kustomizev1.Kustomization
	// sources holds all source resources (HelmRepository, GitRepository, OCIRepository, Bucket, etc.)
	// keyed by "Kind/namespace/name" and "Kind/name" for lookup
	sources map[string]*unstructured.Unstructured
}

// parseAllResources parses all supported resources from a file
func parseAllResources(path string) (*parsedResources, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	result := &parsedResources{
		sources: make(map[string]*unstructured.Unstructured),
	}

	// Split by YAML document separator
	docs := bytes.Split(data, []byte("\n---"))
	for _, doc := range docs {
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}

		// First, determine the kind
		decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc))
		var raw map[string]interface{}
		if err := decoder.Decode(&raw); err != nil {
			continue
		}

		kind, _ := raw["kind"].(string)
		apiVersion, _ := raw["apiVersion"].(string)

		// Re-create decoder for actual parsing
		decoder = k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc))

		switch {
		case kind == helmv2.HelmReleaseKind && isHelmReleaseAPIVersion(apiVersion):
			var hr helmv2.HelmRelease
			if err := decoder.Decode(&hr); err == nil && hr.Kind == helmv2.HelmReleaseKind {
				result.helmReleases = append(result.helmReleases, &hr)
			}

		case kind == kustomizev1.KustomizationKind && isKustomizationAPIVersion(apiVersion):
			var ks kustomizev1.Kustomization
			if err := decoder.Decode(&ks); err == nil && ks.Kind == kustomizev1.KustomizationKind {
				result.kustomizations = append(result.kustomizations, &ks)
			}

		case isSourceAPIVersion(apiVersion):
			// Store all source resources generically (HelmRepository, GitRepository, OCIRepository, Bucket, etc.)
			var u unstructured.Unstructured
			u.SetUnstructuredContent(raw)
			namespace := u.GetNamespace()
			if namespace == "" {
				namespace = "default"
			}
			name := u.GetName()
			// Store with multiple keys for flexible lookup
			result.sources[fmt.Sprintf("%s/%s/%s", kind, namespace, name)] = &u
			result.sources[fmt.Sprintf("%s/%s", kind, name)] = &u

		case isCoreResource(apiVersion, kind):
			// Store core resources (ConfigMap, Secret) for valuesFrom references
			var u unstructured.Unstructured
			u.SetUnstructuredContent(raw)
			namespace := u.GetNamespace()
			if namespace == "" {
				namespace = "default"
			}
			name := u.GetName()
			// Store with multiple keys for flexible lookup
			result.sources[fmt.Sprintf("%s/%s/%s", kind, namespace, name)] = &u
			result.sources[fmt.Sprintf("%s/%s", kind, name)] = &u
		}
	}

	return result, nil
}

func isHelmReleaseAPIVersion(apiVersion string) bool {
	return apiVersion == helmv2.GroupVersion.String() ||
		apiVersion == "helm.toolkit.fluxcd.io/v2beta1" ||
		apiVersion == "helm.toolkit.fluxcd.io/v2beta2"
}

func isKustomizationAPIVersion(apiVersion string) bool {
	return apiVersion == kustomizev1.GroupVersion.String() ||
		apiVersion == "kustomize.toolkit.fluxcd.io/v1beta1" ||
		apiVersion == "kustomize.toolkit.fluxcd.io/v1beta2" ||
		apiVersion == "kustomize.toolkit.fluxcd.io/v1"
}

func isSourceAPIVersion(apiVersion string) bool {
	return strings.HasPrefix(apiVersion, "source.toolkit.fluxcd.io/")
}

func isCoreResource(apiVersion, kind string) bool {
	// Match ConfigMap and Secret from core API
	if apiVersion == "v1" && (kind == "ConfigMap" || kind == "Secret") {
		return true
	}
	return false
}

func templateCmdRun(cmd *cobra.Command, args []string) error {
	if templateArgs.file == "" {
		return fmt.Errorf("--file/-f is required")
	}

	// Handle stdin: write to temp file so it can be read multiple times
	filePath := templateArgs.file
	if templateArgs.file == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}

		tmpFile, err := os.CreateTemp("", "flux-template-stdin-*.yaml")
		if err != nil {
			return fmt.Errorf("failed to create temp file for stdin: %w", err)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(data); err != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to write stdin to temp file: %w", err)
		}
		tmpFile.Close()

		filePath = tmpFile.Name()
	}

	// Parse all resources from the main file
	resources, err := parseAllResources(filePath)
	if err != nil {
		return fmt.Errorf("failed to parse resources: %w", err)
	}

	// Check if we have any resources to render
	if len(resources.helmReleases) == 0 && len(resources.kustomizations) == 0 {
		if templateArgs.file == "-" {
			return fmt.Errorf("no supported Flux resource (HelmRelease or Kustomization) found in stdin")
		}
		return fmt.Errorf("no supported Flux resource (HelmRelease or Kustomization) found in file %s", templateArgs.file)
	}

	var output bytes.Buffer

	// Render all HelmReleases
	if len(resources.helmReleases) > 0 {
		rendered, err := renderHelmReleases(cmd, resources.helmReleases, resources.sources)
		if err != nil {
			return err
		}
		output.Write(rendered)
	}

	// Render all Kustomizations
	if len(resources.kustomizations) > 0 {
		rendered, err := renderKustomizations(cmd, resources.kustomizations, resources.sources, filePath)
		if err != nil {
			return err
		}
		// Add separator between HelmReleases and Kustomizations output if needed
		if output.Len() > 0 && len(rendered) > 0 && !bytes.HasPrefix(rendered, []byte("---")) {
			output.WriteString("---\n")
		}
		output.Write(rendered)
	}

	// If recursive mode is enabled, continue rendering any Flux resources found in the output
	if templateArgs.recursive {
		rendered, err := renderRecursively(cmd, output.Bytes(), resources.sources, filePath)
		if err != nil {
			return err
		}
		output.Reset()
		output.Write(rendered)
	}

	cmd.Print(output.String())
	return nil
}

// renderRecursively continues to render Flux resources found in the output until none remain
func renderRecursively(cmd *cobra.Command, input []byte, sources map[string]*unstructured.Unstructured, manifestFile string) ([]byte, error) {
	// Track rendered resources to avoid infinite loops
	renderedHRs := make(map[string]bool)
	renderedKSs := make(map[string]bool)

	// Track cloned git repos for cleanup
	clonedRepos := make(map[string]string)
	defer func() {
		for _, dir := range clonedRepos {
			os.RemoveAll(dir)
		}
	}()

	currentOutput := input

	for {
		// Parse the current output to find any Flux resources
		nestedResources, err := parseResourcesFromBytes(currentOutput)
		if err != nil {
			return nil, fmt.Errorf("failed to parse rendered output for nested resources: %w", err)
		}

		// Merge any sources found in the output with our existing sources
		for k, v := range nestedResources.sources {
			if _, exists := sources[k]; !exists {
				sources[k] = v
			}
		}

		// Filter to only new (unrendered) resources
		var newHRs []*helmv2.HelmRelease
		for _, hr := range nestedResources.helmReleases {
			key := fmt.Sprintf("%s/%s", hr.Namespace, hr.Name)
			if hr.Namespace == "" {
				key = fmt.Sprintf("default/%s", hr.Name)
			}
			if !renderedHRs[key] {
				newHRs = append(newHRs, hr)
				renderedHRs[key] = true
			}
		}

		var newKSs []*kustomizev1.Kustomization
		for _, ks := range nestedResources.kustomizations {
			key := fmt.Sprintf("%s/%s", ks.Namespace, ks.Name)
			if ks.Namespace == "" {
				key = fmt.Sprintf("default/%s", ks.Name)
			}
			if !renderedKSs[key] {
				newKSs = append(newKSs, ks)
				renderedKSs[key] = true
			}
		}

		// If no new resources, we're done
		if len(newHRs) == 0 && len(newKSs) == 0 {
			break
		}

		// Render the new resources
		var newOutput bytes.Buffer

		// First, add all non-Flux resources from current output
		nonFluxManifests := extractNonFluxManifests(currentOutput)
		newOutput.Write(nonFluxManifests)

		// Render new HelmReleases
		if len(newHRs) > 0 {
			rendered, err := renderHelmReleases(cmd, newHRs, sources)
			if err != nil {
				return nil, err
			}
			newOutput.Write(rendered)
		}

		// Render new Kustomizations
		if len(newKSs) > 0 {
			rendered, err := renderKustomizationsWithRepos(cmd, newKSs, sources, clonedRepos, manifestFile)
			if err != nil {
				return nil, err
			}
			newOutput.Write(rendered)
		}

		currentOutput = newOutput.Bytes()
	}

	return currentOutput, nil
}

// parseResourcesFromBytes parses resources from a byte slice (for recursive rendering)
func parseResourcesFromBytes(data []byte) (*parsedResources, error) {
	result := &parsedResources{
		sources: make(map[string]*unstructured.Unstructured),
	}

	// Split by YAML document separator
	docs := bytes.Split(data, []byte("\n---"))
	for _, doc := range docs {
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}

		// First, determine the kind
		decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc))
		var raw map[string]interface{}
		if err := decoder.Decode(&raw); err != nil {
			continue
		}

		kind, _ := raw["kind"].(string)
		apiVersion, _ := raw["apiVersion"].(string)

		// Re-create decoder for actual parsing
		decoder = k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc))

		switch {
		case kind == helmv2.HelmReleaseKind && isHelmReleaseAPIVersion(apiVersion):
			var hr helmv2.HelmRelease
			if err := decoder.Decode(&hr); err == nil && hr.Kind == helmv2.HelmReleaseKind {
				result.helmReleases = append(result.helmReleases, &hr)
			}

		case kind == kustomizev1.KustomizationKind && isKustomizationAPIVersion(apiVersion):
			var ks kustomizev1.Kustomization
			if err := decoder.Decode(&ks); err == nil && ks.Kind == kustomizev1.KustomizationKind {
				result.kustomizations = append(result.kustomizations, &ks)
			}

		case isSourceAPIVersion(apiVersion):
			// Store all source resources generically
			var u unstructured.Unstructured
			u.SetUnstructuredContent(raw)
			namespace := u.GetNamespace()
			if namespace == "" {
				namespace = "default"
			}
			name := u.GetName()
			result.sources[fmt.Sprintf("%s/%s/%s", kind, namespace, name)] = &u
			result.sources[fmt.Sprintf("%s/%s", kind, name)] = &u

		case isCoreResource(apiVersion, kind):
			// Store core resources (ConfigMap, Secret) for valuesFrom references
			var u unstructured.Unstructured
			u.SetUnstructuredContent(raw)
			namespace := u.GetNamespace()
			if namespace == "" {
				namespace = "default"
			}
			name := u.GetName()
			result.sources[fmt.Sprintf("%s/%s/%s", kind, namespace, name)] = &u
			result.sources[fmt.Sprintf("%s/%s", kind, name)] = &u
		}
	}

	return result, nil
}

// extractNonFluxManifests extracts manifests that are not Flux resources (HelmRelease, Kustomization)
func extractNonFluxManifests(data []byte) []byte {
	var result bytes.Buffer

	docs := bytes.Split(data, []byte("\n---"))
	for _, doc := range docs {
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}

		// Parse to check kind
		decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc))
		var raw map[string]interface{}
		if err := decoder.Decode(&raw); err != nil {
			// If we can't parse it, include it anyway
			if result.Len() > 0 {
				result.WriteString("---\n")
			}
			result.Write(doc)
			result.WriteString("\n")
			continue
		}

		kind, _ := raw["kind"].(string)
		apiVersion, _ := raw["apiVersion"].(string)

		// Skip Flux resources
		if (kind == helmv2.HelmReleaseKind && isHelmReleaseAPIVersion(apiVersion)) ||
			(kind == kustomizev1.KustomizationKind && isKustomizationAPIVersion(apiVersion)) {
			continue
		}

		// Include non-Flux resources
		if result.Len() > 0 {
			result.WriteString("---\n")
		}
		result.Write(doc)
		result.WriteString("\n")
	}

	return result.Bytes()
}

// renderKustomizationsWithRepos renders Kustomizations using a shared clonedRepos map
func renderKustomizationsWithRepos(cmd *cobra.Command, kustomizations []*kustomizev1.Kustomization, sources map[string]*unstructured.Unstructured, clonedRepos map[string]string, manifestFile string) ([]byte, error) {
	var output bytes.Buffer

	for _, ks := range kustomizations {
		rendered, err := renderSingleKustomization(cmd, ks, sources, clonedRepos, manifestFile)
		if err != nil {
			return nil, err
		}
		output.Write(rendered)
	}

	return output.Bytes(), nil
}

// renderHelmReleases renders all HelmRelease resources
func renderHelmReleases(cmd *cobra.Command, helmReleases []*helmv2.HelmRelease, sources map[string]*unstructured.Unstructured) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rootArgs.timeout)
	defer cancel()

	// Create renderer (never connects to cluster)
	renderer := template.NewHelmRenderer()

	// Render each HelmRelease
	var output bytes.Buffer
	for _, hr := range helmReleases {
		opts := &template.HelmTemplateOptions{
			HelmRelease: hr,
			Sources:     sources,
		}

		rendered, err := renderer.Render(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to render HelmRelease %s: %w", hr.Name, err)
		}

		// Ensure proper YAML document separation between releases
		if output.Len() > 0 && len(rendered) > 0 && !bytes.HasPrefix(rendered, []byte("---")) {
			output.WriteString("---\n")
		}
		output.Write(rendered)
	}

	return output.Bytes(), nil
}

// renderKustomizations renders all Kustomization resources
func renderKustomizations(cmd *cobra.Command, kustomizations []*kustomizev1.Kustomization, sources map[string]*unstructured.Unstructured, manifestFile string) ([]byte, error) {
	var output bytes.Buffer

	// Track cloned git repos for cleanup
	clonedRepos := make(map[string]string)
	defer func() {
		for _, dir := range clonedRepos {
			os.RemoveAll(dir)
		}
	}()

	for _, ks := range kustomizations {
		rendered, err := renderSingleKustomization(cmd, ks, sources, clonedRepos, manifestFile)
		if err != nil {
			return nil, err
		}
		// Ensure proper YAML document separation
		if output.Len() > 0 && len(rendered) > 0 && !bytes.HasPrefix(rendered, []byte("---")) {
			output.WriteString("---\n")
		}
		output.Write(rendered)
	}

	return output.Bytes(), nil
}

// renderSingleKustomization renders a single Kustomization resource
func renderSingleKustomization(cmd *cobra.Command, ks *kustomizev1.Kustomization, sources map[string]*unstructured.Unstructured, clonedRepos map[string]string, manifestFile string) ([]byte, error) {
	name := ks.Name

	// Determine the path based on the source
	var path string
	sourceKind := ks.Spec.SourceRef.Kind

	// Handle supported source types
	switch sourceKind {
	case sourcev1.GitRepositoryKind, sourcev1.OCIRepositoryKind, sourcev1.BucketKind:
		// Look up the source from generic sources
		namespace := ks.Spec.SourceRef.Namespace
		if namespace == "" {
			namespace = ks.Namespace
			if namespace == "" {
				namespace = "flux-system"
			}
		}

		sourceKey := fmt.Sprintf("%s/%s/%s", sourceKind, namespace, ks.Spec.SourceRef.Name)
		source, found := sources[sourceKey]
		if !found {
			sourceKey = fmt.Sprintf("%s/%s", sourceKind, ks.Spec.SourceRef.Name)
			source, found = sources[sourceKey]
		}

		if !found {
			return nil, fmt.Errorf("%s %s not found in manifest; include the %s resource in the manifest file", sourceKind, ks.Spec.SourceRef.Name, sourceKind)
		}

		// Fetch the source content based on its kind
		var sourcePath string
		var err error

		switch sourceKind {
		case sourcev1.GitRepositoryKind:
			sourcePath, err = cloneGitRepositoryFromUnstructured(source, clonedRepos)
			if err != nil {
				return nil, fmt.Errorf("failed to clone GitRepository %s: %w", ks.Spec.SourceRef.Name, err)
			}

		case sourcev1.OCIRepositoryKind:
			sourcePath, err = pullOCIRepositoryFromUnstructured(source, clonedRepos)
			if err != nil {
				return nil, fmt.Errorf("failed to pull OCIRepository %s: %w", ks.Spec.SourceRef.Name, err)
			}

		case sourcev1.BucketKind:
			sourcePath, err = downloadBucketFromUnstructured(source, clonedRepos)
			if err != nil {
				return nil, fmt.Errorf("failed to download Bucket %s: %w", ks.Spec.SourceRef.Name, err)
			}
		}

		// Use the spec.path relative to the fetched source
		if ks.Spec.Path != "" {
			path = filepath.Join(sourcePath, ks.Spec.Path)
		} else {
			path = sourcePath
		}

	default:
		return nil, fmt.Errorf("unsupported source type %q for Kustomization %s; supported source types are GitRepository, OCIRepository, and Bucket", sourceKind, name)
	}

	// Normalize the path
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
	}
	path = filepath.Clean(path)

	if fs, err := os.Stat(path); err != nil || !fs.IsDir() {
		return nil, fmt.Errorf("invalid resource path %q for Kustomization %s", path, name)
	}

	// Determine the namespace for the builder lookup
	ksNamespace := ks.Namespace
	if ksNamespace == "" {
		ksNamespace = *kubeconfigArgs.Namespace
	}

	// Build in dry-run mode (never connects to cluster)
	builder, err := build.NewBuilder(name, path,
		build.WithTimeout(rootArgs.timeout),
		build.WithKustomizationFile(manifestFile),
		build.WithDryRun(true),
		build.WithNamespace(ksNamespace),
	)

	if err != nil {
		return nil, err
	}

	// Create a signal channel
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)

	var output bytes.Buffer
	errChan := make(chan error)
	go func() {
		objects, err := builder.Build()
		if err != nil {
			errChan <- err
			return
		}

		manifests, err := ssautil.ObjectsToYAML(objects)
		if err != nil {
			errChan <- err
			return
		}

		output.WriteString(manifests)
		errChan <- nil
	}()

	select {
	case <-sigc:
		fmt.Println("Template cancelled... exiting.")
		return nil, builder.Cancel()
	case err := <-errChan:
		if err != nil {
			return nil, err
		}
	}

	return output.Bytes(), nil
}

// cloneGitRepositoryFromUnstructured clones a GitRepository (from unstructured) to a temporary directory
func cloneGitRepositoryFromUnstructured(u *unstructured.Unstructured, clonedRepos map[string]string) (string, error) {
	namespace := u.GetNamespace()
	name := u.GetName()

	// Check if already cloned
	repoKey := fmt.Sprintf("%s/%s", namespace, name)
	if dir, exists := clonedRepos[repoKey]; exists {
		return dir, nil
	}

	// Extract spec.url
	spec, found, err := unstructured.NestedMap(u.Object, "spec")
	if err != nil || !found {
		return "", fmt.Errorf("failed to get spec from GitRepository")
	}

	repoURL, found, err := unstructured.NestedString(spec, "url")
	if err != nil || !found {
		return "", fmt.Errorf("failed to get spec.url from GitRepository")
	}

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("flux-template-%s-", name))
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Determine the reference to checkout
	cloneOpts := &git.CloneOptions{
		URL:      repoURL,
		Progress: nil,
	}

	// Extract reference settings
	ref, refFound, _ := unstructured.NestedMap(spec, "ref")
	var commitRef string
	if refFound {
		if branch, ok, _ := unstructured.NestedString(ref, "branch"); ok && branch != "" {
			cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(branch)
		} else if tag, ok, _ := unstructured.NestedString(ref, "tag"); ok && tag != "" {
			cloneOpts.ReferenceName = plumbing.NewTagReferenceName(tag)
		} else if commit, ok, _ := unstructured.NestedString(ref, "commit"); ok && commit != "" {
			commitRef = commit
		}
	}

	// Clone the repository
	repo, err := git.PlainClone(tmpDir, false, cloneOpts)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to clone repository %s: %w", repoURL, err)
	}

	// If a specific commit was requested, checkout that commit
	if commitRef != "" {
		worktree, err := repo.Worktree()
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("failed to get worktree: %w", err)
		}

		err = worktree.Checkout(&git.CheckoutOptions{
			Hash: plumbing.NewHash(commitRef),
		})
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("failed to checkout commit %s: %w", commitRef, err)
		}
	}

	clonedRepos[repoKey] = tmpDir
	return tmpDir, nil
}

// downloadBucketFromUnstructured downloads files from a Bucket source to a temporary directory
// It supports AWS S3, GCP Cloud Storage, and Azure Blob Storage using local credentials
func downloadBucketFromUnstructured(u *unstructured.Unstructured, clonedRepos map[string]string) (string, error) {
	namespace := u.GetNamespace()
	name := u.GetName()

	// Check if already downloaded
	repoKey := fmt.Sprintf("bucket/%s/%s", namespace, name)
	if dir, exists := clonedRepos[repoKey]; exists {
		return dir, nil
	}

	// Extract spec
	spec, found, err := unstructured.NestedMap(u.Object, "spec")
	if err != nil || !found {
		return "", fmt.Errorf("failed to get spec from Bucket")
	}

	// Get required fields
	bucketName, found, err := unstructured.NestedString(spec, "bucketName")
	if err != nil || !found || bucketName == "" {
		return "", fmt.Errorf("failed to get spec.bucketName from Bucket")
	}

	endpoint, found, err := unstructured.NestedString(spec, "endpoint")
	if err != nil || !found || endpoint == "" {
		return "", fmt.Errorf("failed to get spec.endpoint from Bucket")
	}

	// Get optional fields
	provider, _, _ := unstructured.NestedString(spec, "provider")
	if provider == "" {
		provider = sourcev1.BucketProviderGeneric
	}

	region, _, _ := unstructured.NestedString(spec, "region")
	prefix, _, _ := unstructured.NestedString(spec, "prefix")
	insecure, _, _ := unstructured.NestedBool(spec, "insecure")

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("flux-template-bucket-%s-", name))
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), rootArgs.timeout)
	defer cancel()

	// Download based on provider
	switch provider {
	case sourcev1.BucketProviderAmazon:
		err = downloadFromS3(ctx, bucketName, endpoint, region, prefix, insecure, tmpDir)
	case sourcev1.BucketProviderGoogle:
		err = downloadFromGCS(ctx, bucketName, prefix, tmpDir)
	case sourcev1.BucketProviderAzure:
		err = downloadFromAzureBlob(ctx, bucketName, endpoint, prefix, tmpDir)
	case sourcev1.BucketProviderGeneric:
		// Generic provider uses S3-compatible API
		err = downloadFromS3(ctx, bucketName, endpoint, region, prefix, insecure, tmpDir)
	default:
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("unsupported bucket provider: %s", provider)
	}

	if err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to download from bucket: %w", err)
	}

	clonedRepos[repoKey] = tmpDir
	return tmpDir, nil
}

// downloadFromS3 downloads files from an S3 or S3-compatible bucket using local credentials
func downloadFromS3(ctx context.Context, bucketName, endpoint, region, prefix string, insecure bool, destDir string) error {
	// AWS SDK v2 automatically loads credentials from:
	// - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
	// - Shared credentials file (~/.aws/credentials)
	// - IAM roles (when running on AWS infrastructure)
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Configure custom endpoint for S3-compatible storage
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, resolvedRegion string, options ...interface{}) (aws.Endpoint, error) {
		if service == s3.ServiceID {
			scheme := "https"
			if insecure {
				scheme = "http"
			}
			return aws.Endpoint{
				URL:               fmt.Sprintf("%s://%s", scheme, endpoint),
				HostnameImmutable: true,
			}, nil
		}
		return aws.Endpoint{}, &aws.EndpointNotFoundError{}
	})

	cfg.EndpointResolverWithOptions = customResolver

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	// List objects in the bucket
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("failed to list objects: %w", err)
		}

		for _, obj := range output.Contents {
			if obj.Key == nil {
				continue
			}
			key := *obj.Key

			// Skip directories
			if strings.HasSuffix(key, "/") {
				continue
			}

			// Get the object
			result, err := client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(bucketName),
				Key:    obj.Key,
			})
			if err != nil {
				return fmt.Errorf("failed to get object %s: %w", key, err)
			}

			// Determine destination path (remove prefix if present)
			relPath := key
			if prefix != "" {
				relPath = strings.TrimPrefix(key, prefix)
				relPath = strings.TrimPrefix(relPath, "/")
			}
			destPath := filepath.Join(destDir, relPath)

			// Create parent directories
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				result.Body.Close()
				return fmt.Errorf("failed to create directory for %s: %w", destPath, err)
			}

			// Write file
			f, err := os.Create(destPath)
			if err != nil {
				result.Body.Close()
				return fmt.Errorf("failed to create file %s: %w", destPath, err)
			}

			_, err = io.Copy(f, result.Body)
			result.Body.Close()
			f.Close()
			if err != nil {
				return fmt.Errorf("failed to write file %s: %w", destPath, err)
			}
		}
	}

	return nil
}

// downloadFromGCS downloads files from a GCS bucket using local credentials
func downloadFromGCS(ctx context.Context, bucketName, prefix string, destDir string) error {
	// GCS client automatically loads credentials from:
	// - GOOGLE_APPLICATION_CREDENTIALS environment variable
	// - Default application credentials (gcloud auth application-default login)
	// - Metadata server (when running on GCP infrastructure)
	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer client.Close()

	bucket := client.Bucket(bucketName)
	query := &storage.Query{Prefix: prefix}

	it := bucket.Objects(ctx, query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to list objects: %w", err)
		}

		// Skip directories
		if strings.HasSuffix(attrs.Name, "/") {
			continue
		}

		// Get the object
		rc, err := bucket.Object(attrs.Name).NewReader(ctx)
		if err != nil {
			return fmt.Errorf("failed to read object %s: %w", attrs.Name, err)
		}

		// Determine destination path (remove prefix if present)
		relPath := attrs.Name
		if prefix != "" {
			relPath = strings.TrimPrefix(attrs.Name, prefix)
			relPath = strings.TrimPrefix(relPath, "/")
		}
		destPath := filepath.Join(destDir, relPath)

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			rc.Close()
			return fmt.Errorf("failed to create directory for %s: %w", destPath, err)
		}

		// Write file
		f, err := os.Create(destPath)
		if err != nil {
			rc.Close()
			return fmt.Errorf("failed to create file %s: %w", destPath, err)
		}

		_, err = io.Copy(f, rc)
		rc.Close()
		f.Close()
		if err != nil {
			return fmt.Errorf("failed to write file %s: %w", destPath, err)
		}
	}

	return nil
}

// downloadFromAzureBlob downloads files from Azure Blob Storage using local credentials
func downloadFromAzureBlob(ctx context.Context, containerName, endpoint, prefix string, destDir string) error {
	// Azure SDK automatically loads credentials from:
	// - Environment variables (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
	// - Azure CLI credentials (az login)
	// - Managed Identity (when running on Azure infrastructure)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure credential: %w", err)
	}

	// Build service URL from endpoint
	serviceURL := endpoint
	if !strings.HasPrefix(serviceURL, "https://") && !strings.HasPrefix(serviceURL, "http://") {
		serviceURL = "https://" + endpoint
	}

	client, err := azblob.NewClient(serviceURL, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure Blob client: %w", err)
	}

	// List blobs in the container
	pager := client.NewListBlobsFlatPager(containerName, &azblob.ListBlobsFlatOptions{
		Prefix: &prefix,
	})

	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("failed to list blobs: %w", err)
		}

		for _, blob := range resp.Segment.BlobItems {
			if blob.Name == nil {
				continue
			}
			blobName := *blob.Name

			// Skip directories (blobs ending with /)
			if strings.HasSuffix(blobName, "/") {
				continue
			}

			// Download the blob
			downloadResp, err := client.DownloadStream(ctx, containerName, blobName, nil)
			if err != nil {
				return fmt.Errorf("failed to download blob %s: %w", blobName, err)
			}

			// Determine destination path (remove prefix if present)
			relPath := blobName
			if prefix != "" {
				relPath = strings.TrimPrefix(blobName, prefix)
				relPath = strings.TrimPrefix(relPath, "/")
			}
			destPath := filepath.Join(destDir, relPath)

			// Create parent directories
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				downloadResp.Body.Close()
				return fmt.Errorf("failed to create directory for %s: %w", destPath, err)
			}

			// Write file
			f, err := os.Create(destPath)
			if err != nil {
				downloadResp.Body.Close()
				return fmt.Errorf("failed to create file %s: %w", destPath, err)
			}

			_, err = io.Copy(f, downloadResp.Body)
			downloadResp.Body.Close()
			f.Close()
			if err != nil {
				return fmt.Errorf("failed to write file %s: %w", destPath, err)
			}
		}
	}

	return nil
}

// pullOCIRepositoryFromUnstructured pulls an OCIRepository artifact to a temporary directory
func pullOCIRepositoryFromUnstructured(u *unstructured.Unstructured, clonedRepos map[string]string) (string, error) {
	namespace := u.GetNamespace()
	name := u.GetName()

	// Check if already pulled
	repoKey := fmt.Sprintf("oci/%s/%s", namespace, name)
	if dir, exists := clonedRepos[repoKey]; exists {
		return dir, nil
	}

	// Extract spec.url
	spec, found, err := unstructured.NestedMap(u.Object, "spec")
	if err != nil || !found {
		return "", fmt.Errorf("failed to get spec from OCIRepository")
	}

	ociURL, found, err := unstructured.NestedString(spec, "url")
	if err != nil || !found {
		return "", fmt.Errorf("failed to get spec.url from OCIRepository")
	}

	// Parse the OCI URL
	url, err := oci.ParseArtifactURL(ociURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse OCI URL %s: %w", ociURL, err)
	}

	// Extract reference settings (tag, digest, semver)
	ref, refFound, _ := unstructured.NestedMap(spec, "ref")
	if refFound {
		if tag, ok, _ := unstructured.NestedString(ref, "tag"); ok && tag != "" {
			url = fmt.Sprintf("%s:%s", url, tag)
		} else if digest, ok, _ := unstructured.NestedString(ref, "digest"); ok && digest != "" {
			url = fmt.Sprintf("%s@%s", url, digest)
		} else if semver, ok, _ := unstructured.NestedString(ref, "semver"); ok && semver != "" {
			// For semver constraints, we need to resolve the latest matching version
			// This is a simplified approach - we use the constraint as-is and let the registry resolve it
			url = fmt.Sprintf("%s:%s", url, semver)
		}
	}

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("flux-template-oci-%s-", name))
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Configure OCI client options
	opts := oci.DefaultOptions()

	// Check for insecure flag
	insecure, _, _ := unstructured.NestedBool(spec, "insecure")
	if insecure {
		opts = append(opts, crane.Insecure)
	}

	ociClient := oci.NewClient(opts)

	// Pull the artifact
	ctx, cancel := context.WithTimeout(context.Background(), rootArgs.timeout)
	defer cancel()

	_, err = ociClient.Pull(ctx, url, tmpDir)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to pull OCI artifact %s: %w", url, err)
	}

	clonedRepos[repoKey] = tmpDir
	return tmpDir, nil
}
