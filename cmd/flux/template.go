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
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1"
	ssautil "github.com/fluxcd/pkg/ssa/utils"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"

	"github.com/fluxcd/flux2/v2/internal/build"
	"github.com/fluxcd/flux2/v2/internal/template"
)

type templateFlags struct {
	file string
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
will be cloned to a temporary directory and used as the source path.`,
	Example: `  # Template a resource (auto-detects type from manifest)
  flux template -f ./manifest.yaml

  # Template multiple resources from a single multi-document YAML file
  flux template -f ./multi-doc.yaml`,
	RunE: templateCmdRun,
}

func init() {
	templateCmd.Flags().StringVarP(&templateArgs.file, "file", "f", "", "path to the Flux resource manifest file (auto-detects HelmRelease or Kustomization)")

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

	// Parse all resources from the main file
	resources, err := parseAllResources(templateArgs.file)
	if err != nil {
		return fmt.Errorf("failed to parse resources: %w", err)
	}

	// Parse additional source files
	for _, f := range templateArgs.sourceFiles {
		additionalResources, err := parseAllResources(f)
		if err != nil {
			return fmt.Errorf("failed to parse source file %s: %w", f, err)
		}
		// Merge all sources
		for k, v := range additionalResources.sources {
			resources.sources[k] = v
		}
	}

	// Check if we have any resources to render
	if len(resources.helmReleases) == 0 && len(resources.kustomizations) == 0 {
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
		rendered, err := renderKustomizations(cmd, resources.kustomizations, resources.sources)
		if err != nil {
			return err
		}
		output.Write(rendered)
	}

	cmd.Print(output.String())
	return nil
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

		output.Write(rendered)
	}

	return output.Bytes(), nil
}

// renderKustomizations renders all Kustomization resources
func renderKustomizations(cmd *cobra.Command, kustomizations []*kustomizev1.Kustomization, sources map[string]*unstructured.Unstructured) ([]byte, error) {
	var output bytes.Buffer

	// Track cloned git repos for cleanup
	clonedRepos := make(map[string]string)
	defer func() {
		for _, dir := range clonedRepos {
			os.RemoveAll(dir)
		}
	}()

	for _, ks := range kustomizations {
		rendered, err := renderSingleKustomization(cmd, ks, sources, clonedRepos)
		if err != nil {
			return nil, err
		}
		output.Write(rendered)
	}

	return output.Bytes(), nil
}

// renderSingleKustomization renders a single Kustomization resource
func renderSingleKustomization(cmd *cobra.Command, ks *kustomizev1.Kustomization, sources map[string]*unstructured.Unstructured, clonedRepos map[string]string) ([]byte, error) {
	name := ks.Name

	// Determine the path based on the source
	var path string
	if ks.Spec.SourceRef.Kind == sourcev1.GitRepositoryKind {
		// Look up the GitRepository from generic sources
		namespace := ks.Spec.SourceRef.Namespace
		if namespace == "" {
			namespace = ks.Namespace
			if namespace == "" {
				namespace = "flux-system"
			}
		}

		sourceKey := fmt.Sprintf("%s/%s/%s", sourcev1.GitRepositoryKind, namespace, ks.Spec.SourceRef.Name)
		source, found := sources[sourceKey]
		if !found {
			sourceKey = fmt.Sprintf("%s/%s", sourcev1.GitRepositoryKind, ks.Spec.SourceRef.Name)
			source, found = sources[sourceKey]
		}

		if found {
			// Clone the git repository if not already cloned
			repoPath, err := cloneGitRepositoryFromUnstructured(source, clonedRepos)
			if err != nil {
				return nil, fmt.Errorf("failed to clone GitRepository %s: %w", ks.Spec.SourceRef.Name, err)
			}

			// Use the spec.path relative to the cloned repo
			if ks.Spec.Path != "" {
				path = filepath.Join(repoPath, ks.Spec.Path)
			} else {
				path = repoPath
			}
		} else {
			return nil, fmt.Errorf("GitRepository %s not found in manifest; include the GitRepository resource in the manifest file", ks.Spec.SourceRef.Name)
		}
	} else if ks.Spec.Path != "" {
		path = ks.Spec.Path
	} else {
		path = filepath.Dir(templateArgs.file)
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

	// Build in dry-run mode (never connects to cluster)
	builder, err := build.NewBuilder(name, path,
		build.WithTimeout(rootArgs.timeout),
		build.WithKustomizationFile(templateArgs.file),
		build.WithDryRun(true),
		build.WithNamespace(*kubeconfigArgs.Namespace),
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

