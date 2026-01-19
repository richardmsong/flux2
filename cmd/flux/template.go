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
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1"
	ssautil "github.com/fluxcd/pkg/ssa/utils"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"

	"github.com/fluxcd/flux2/v2/internal/build"
	"github.com/fluxcd/flux2/v2/internal/template"
	"github.com/fluxcd/flux2/v2/internal/utils"
)

type templateFlags struct {
	file        string
	sourceFiles []string
	valuesFiles []string
	setValues   map[string]string
	chartPath   string
	kubeVersion string
	apiVersions []string
	namespace   string
	releaseName string
	dryRun      bool
	// Kustomization-specific flags
	path         string
	ignorePaths  []string
	strictSubst  bool
	recursive    bool
	localSources map[string]string
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

When using -f/--file, the command automatically detects the resource type from the
manifest and renders it appropriately. If the file contains multiple HelmRelease or
Kustomization resources, all of them will be rendered.

For Kustomization resources that reference a GitRepository source, the git repository
will be cloned to a temporary directory and used as the source path.`,
	Example: `  # Template a resource (auto-detects type from manifest)
  flux template -f ./manifest.yaml

  # Template multiple resources from a single file
  flux template -f ./multi-doc.yaml

  # Template a HelmRelease with additional values
  flux template -f ./helmrelease.yaml \
    --source-file ./helmrepository.yaml \
    --values ./production-values.yaml \
    --set image.tag=v1.0.0

  # Template a Kustomization with path
  flux template -f ./kustomization.yaml --path ./manifests

  # Template in dry-run mode (no cluster connection)
  flux template -f ./manifest.yaml --dry-run`,
	RunE: templateCmdRun,
}

func init() {
	templateCmd.Flags().StringVarP(&templateArgs.file, "file", "f", "", "path to the Flux resource manifest file (auto-detects HelmRelease or Kustomization)")
	templateCmd.Flags().StringSliceVar(&templateArgs.sourceFiles, "source-file", nil, "path to files containing source resources (e.g., HelmRepository)")
	templateCmd.Flags().StringSliceVar(&templateArgs.valuesFiles, "values", nil, "path to additional values files (HelmRelease only)")
	templateCmd.Flags().StringToStringVar(&templateArgs.setValues, "set", nil, "set individual values (key=value, HelmRelease only)")
	templateCmd.Flags().StringVar(&templateArgs.chartPath, "chart-path", "", "path to local chart directory (HelmRelease only)")
	templateCmd.Flags().StringVar(&templateArgs.kubeVersion, "kube-version", "", "Kubernetes version for template rendering")
	templateCmd.Flags().StringSliceVar(&templateArgs.apiVersions, "api-versions", nil, "available API versions for Capabilities (HelmRelease only)")
	templateCmd.Flags().StringVar(&templateArgs.namespace, "template-namespace", "", "namespace to use for rendering (overrides resource spec)")
	templateCmd.Flags().StringVar(&templateArgs.releaseName, "release-name", "", "release name to use for rendering (HelmRelease only)")
	templateCmd.Flags().BoolVar(&templateArgs.dryRun, "dry-run", false, "dry-run mode (no cluster connection)")
	// Kustomization-specific flags
	templateCmd.Flags().StringVar(&templateArgs.path, "path", "", "path to the manifests location (Kustomization only)")
	templateCmd.Flags().StringSliceVar(&templateArgs.ignorePaths, "ignore-paths", nil, "set paths to ignore in .gitignore format (Kustomization only)")
	templateCmd.Flags().BoolVar(&templateArgs.strictSubst, "strict-substitute", false, "fail if a var without a default is missing from input vars (Kustomization only)")
	templateCmd.Flags().BoolVarP(&templateArgs.recursive, "recursive", "r", false, "recursively template Kustomizations")
	templateCmd.Flags().StringToStringVar(&templateArgs.localSources, "local-sources", nil, "local sources mapping: Kind/namespace/name=path (Kustomization only)")

	rootCmd.AddCommand(templateCmd)
}

// parsedResources holds all parsed resources from the manifest files
type parsedResources struct {
	helmReleases     []*helmv2.HelmRelease
	kustomizations   []*kustomizev1.Kustomization
	helmRepositories map[string]*sourcev1.HelmRepository
	gitRepositories  map[string]*sourcev1.GitRepository
}

// parseAllResources parses all supported resources from a file
func parseAllResources(path string) (*parsedResources, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	result := &parsedResources{
		helmRepositories: make(map[string]*sourcev1.HelmRepository),
		gitRepositories:  make(map[string]*sourcev1.GitRepository),
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

		case kind == sourcev1.HelmRepositoryKind && isSourceAPIVersion(apiVersion):
			var repo sourcev1.HelmRepository
			if err := decoder.Decode(&repo); err == nil && repo.Kind == sourcev1.HelmRepositoryKind {
				namespace := repo.Namespace
				if namespace == "" {
					namespace = "default"
				}
				result.helmRepositories[fmt.Sprintf("%s/%s", namespace, repo.Name)] = &repo
				result.helmRepositories[repo.Name] = &repo
			}

		case kind == sourcev1.GitRepositoryKind && isSourceAPIVersion(apiVersion):
			var repo sourcev1.GitRepository
			if err := decoder.Decode(&repo); err == nil && repo.Kind == sourcev1.GitRepositoryKind {
				namespace := repo.Namespace
				if namespace == "" {
					namespace = "default"
				}
				result.gitRepositories[fmt.Sprintf("%s/%s", namespace, repo.Name)] = &repo
				result.gitRepositories[repo.Name] = &repo
			}
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

func templateCmdRun(cmd *cobra.Command, args []string) error {
	// If no file flag is provided, show help (subcommands can still be used)
	if templateArgs.file == "" {
		return cmd.Help()
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
		// Merge HelmRepositories
		for k, v := range additionalResources.helmRepositories {
			resources.helmRepositories[k] = v
		}
		// Merge GitRepositories
		for k, v := range additionalResources.gitRepositories {
			resources.gitRepositories[k] = v
		}
	}

	// Check if we have any resources to render
	if len(resources.helmReleases) == 0 && len(resources.kustomizations) == 0 {
		return fmt.Errorf("no supported Flux resource (HelmRelease or Kustomization) found in file %s", templateArgs.file)
	}

	var output bytes.Buffer

	// Render all HelmReleases
	if len(resources.helmReleases) > 0 {
		rendered, err := renderHelmReleases(cmd, resources.helmReleases, resources.helmRepositories)
		if err != nil {
			return err
		}
		output.Write(rendered)
	}

	// Render all Kustomizations
	if len(resources.kustomizations) > 0 {
		rendered, err := renderKustomizations(cmd, resources.kustomizations, resources.gitRepositories)
		if err != nil {
			return err
		}
		output.Write(rendered)
	}

	cmd.Print(output.String())
	return nil
}

// renderHelmReleases renders all HelmRelease resources
func renderHelmReleases(cmd *cobra.Command, helmReleases []*helmv2.HelmRelease, helmRepositories map[string]*sourcev1.HelmRepository) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), rootArgs.timeout)
	defer cancel()

	// Get Kubernetes client if not in dry-run mode
	var kubeClient client.Client
	var err error
	if !templateArgs.dryRun {
		kubeClient, err = utils.KubeClient(kubeconfigArgs, kubeclientOptions)
		if err != nil {
			if templateArgs.chartPath == "" {
				logger.Warningf("failed to create Kubernetes client, continuing in dry-run mode: %v", err)
			}
			kubeClient = nil
		}
	}

	// Create renderer
	renderer := template.NewHelmRenderer(kubeClient, templateArgs.dryRun || kubeClient == nil)

	// Render each HelmRelease
	var output bytes.Buffer
	for _, hr := range helmReleases {
		opts := &template.HelmTemplateOptions{
			HelmRelease:      hr,
			HelmRepositories: helmRepositories,
			ValuesFiles:      templateArgs.valuesFiles,
			SetValues:        templateArgs.setValues,
			ChartPath:        templateArgs.chartPath,
			KubeVersion:      templateArgs.kubeVersion,
			APIVersions:      templateArgs.apiVersions,
			Namespace:        templateArgs.namespace,
			ReleaseName:      templateArgs.releaseName,
			DryRun:           templateArgs.dryRun || kubeClient == nil,
			KubeClient:       kubeClient,
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
func renderKustomizations(cmd *cobra.Command, kustomizations []*kustomizev1.Kustomization, gitRepositories map[string]*sourcev1.GitRepository) ([]byte, error) {
	var output bytes.Buffer

	// Track cloned git repos for cleanup
	clonedRepos := make(map[string]string)
	defer func() {
		for _, dir := range clonedRepos {
			os.RemoveAll(dir)
		}
	}()

	for _, ks := range kustomizations {
		rendered, err := renderSingleKustomization(cmd, ks, gitRepositories, clonedRepos)
		if err != nil {
			return nil, err
		}
		output.Write(rendered)
	}

	return output.Bytes(), nil
}

// renderSingleKustomization renders a single Kustomization resource
func renderSingleKustomization(cmd *cobra.Command, ks *kustomizev1.Kustomization, gitRepositories map[string]*sourcev1.GitRepository, clonedRepos map[string]string) ([]byte, error) {
	name := ks.Name

	// Determine the path
	path := templateArgs.path
	if path == "" {
		// If no path provided, need to resolve it based on the source
		if ks.Spec.SourceRef.Kind == sourcev1.GitRepositoryKind {
			// Look up the GitRepository
			sourceKey := fmt.Sprintf("%s/%s", ks.Spec.SourceRef.Namespace, ks.Spec.SourceRef.Name)
			if ks.Spec.SourceRef.Namespace == "" {
				namespace := ks.Namespace
				if namespace == "" {
					namespace = "flux-system"
				}
				sourceKey = fmt.Sprintf("%s/%s", namespace, ks.Spec.SourceRef.Name)
			}

			gitRepo, found := gitRepositories[sourceKey]
			if !found {
				gitRepo, found = gitRepositories[ks.Spec.SourceRef.Name]
			}

			if found {
				// Clone the git repository if not already cloned
				repoPath, err := cloneGitRepository(gitRepo, clonedRepos)
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
				return nil, fmt.Errorf("GitRepository %s not found in manifest; use --local-sources to provide a local path mapping", ks.Spec.SourceRef.Name)
			}
		} else if ks.Spec.Path != "" {
			path = ks.Spec.Path
		} else {
			path = filepath.Dir(templateArgs.file)
		}
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

	var builder *build.Builder
	if templateArgs.dryRun {
		builder, err = build.NewBuilder(name, path,
			build.WithTimeout(rootArgs.timeout),
			build.WithKustomizationFile(templateArgs.file),
			build.WithDryRun(templateArgs.dryRun),
			build.WithNamespace(*kubeconfigArgs.Namespace),
			build.WithIgnore(templateArgs.ignorePaths),
			build.WithStrictSubstitute(templateArgs.strictSubst),
			build.WithRecursive(templateArgs.recursive),
			build.WithLocalSources(templateArgs.localSources),
		)
	} else {
		builder, err = build.NewBuilder(name, path,
			build.WithClientConfig(kubeconfigArgs, kubeclientOptions),
			build.WithTimeout(rootArgs.timeout),
			build.WithKustomizationFile(templateArgs.file),
			build.WithIgnore(templateArgs.ignorePaths),
			build.WithStrictSubstitute(templateArgs.strictSubst),
			build.WithRecursive(templateArgs.recursive),
			build.WithLocalSources(templateArgs.localSources),
		)
	}

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

// cloneGitRepository clones a GitRepository to a temporary directory
func cloneGitRepository(gitRepo *sourcev1.GitRepository, clonedRepos map[string]string) (string, error) {
	// Check if already cloned
	repoKey := fmt.Sprintf("%s/%s", gitRepo.Namespace, gitRepo.Name)
	if dir, exists := clonedRepos[repoKey]; exists {
		return dir, nil
	}

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("flux-template-%s-", gitRepo.Name))
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Determine the reference to checkout
	cloneOpts := &git.CloneOptions{
		URL:      gitRepo.Spec.URL,
		Progress: nil,
	}

	// Set the reference based on gitRepo.Spec.Reference
	if gitRepo.Spec.Reference != nil {
		if gitRepo.Spec.Reference.Branch != "" {
			cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(gitRepo.Spec.Reference.Branch)
		} else if gitRepo.Spec.Reference.Tag != "" {
			cloneOpts.ReferenceName = plumbing.NewTagReferenceName(gitRepo.Spec.Reference.Tag)
		} else if gitRepo.Spec.Reference.Commit != "" {
			// For specific commit, we need to clone first then checkout
			cloneOpts.ReferenceName = ""
		}
	}

	// Clone the repository
	repo, err := git.PlainClone(tmpDir, false, cloneOpts)
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to clone repository %s: %w", gitRepo.Spec.URL, err)
	}

	// If a specific commit was requested, checkout that commit
	if gitRepo.Spec.Reference != nil && gitRepo.Spec.Reference.Commit != "" {
		worktree, err := repo.Worktree()
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("failed to get worktree: %w", err)
		}

		err = worktree.Checkout(&git.CheckoutOptions{
			Hash: plumbing.NewHash(gitRepo.Spec.Reference.Commit),
		})
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("failed to checkout commit %s: %w", gitRepo.Spec.Reference.Commit, err)
		}
	}

	clonedRepos[repoKey] = tmpDir
	return tmpDir, nil
}

// templateHelmReleaseFromFile templates a HelmRelease from the given file (used by subcommand)
func templateHelmReleaseFromFile(cmd *cobra.Command, file string) error {
	ctx, cancel := context.WithTimeout(context.Background(), rootArgs.timeout)
	defer cancel()

	// Parse HelmRelease from file
	helmReleases, err := parseHelmReleasesFromFile(file)
	if err != nil {
		return fmt.Errorf("failed to parse HelmRelease from file: %w", err)
	}

	if len(helmReleases) == 0 {
		return fmt.Errorf("no HelmRelease resources found in file %s", file)
	}

	// Parse HelmRepositories from source files and main file
	helmRepositories := make(map[string]*sourcev1.HelmRepository)

	allFiles := append([]string{file}, templateArgs.sourceFiles...)
	for _, f := range allFiles {
		repos, err := parseHelmRepositoriesFromFile(f)
		if err != nil {
			return fmt.Errorf("failed to parse HelmRepository from file %s: %w", f, err)
		}
		for k, v := range repos {
			helmRepositories[k] = v
		}
	}

	// Get Kubernetes client if not in dry-run mode
	var kubeClient client.Client
	if !templateArgs.dryRun {
		kubeClient, err = utils.KubeClient(kubeconfigArgs, kubeclientOptions)
		if err != nil {
			if templateArgs.chartPath == "" {
				logger.Warningf("failed to create Kubernetes client, continuing in dry-run mode: %v", err)
			}
			kubeClient = nil
		}
	}

	// Create renderer
	renderer := template.NewHelmRenderer(kubeClient, templateArgs.dryRun || kubeClient == nil)

	// Render each HelmRelease
	var output bytes.Buffer
	for _, hr := range helmReleases {
		opts := &template.HelmTemplateOptions{
			HelmRelease:      hr,
			HelmRepositories: helmRepositories,
			ValuesFiles:      templateArgs.valuesFiles,
			SetValues:        templateArgs.setValues,
			ChartPath:        templateArgs.chartPath,
			KubeVersion:      templateArgs.kubeVersion,
			APIVersions:      templateArgs.apiVersions,
			Namespace:        templateArgs.namespace,
			ReleaseName:      templateArgs.releaseName,
			DryRun:           templateArgs.dryRun || kubeClient == nil,
			KubeClient:       kubeClient,
		}

		rendered, err := renderer.Render(ctx, opts)
		if err != nil {
			return fmt.Errorf("failed to render HelmRelease %s: %w", hr.Name, err)
		}

		output.Write(rendered)
	}

	cmd.Print(output.String())
	return nil
}

// templateKustomizationFromFile templates a Kustomization from the given file (used by subcommand)
func templateKustomizationFromFile(cmd *cobra.Command, file string) error {
	// Parse all resources from the file
	resources, err := parseAllResources(file)
	if err != nil {
		return fmt.Errorf("failed to parse resources: %w", err)
	}

	// Parse additional source files for GitRepositories
	for _, f := range templateArgs.sourceFiles {
		additionalResources, err := parseAllResources(f)
		if err != nil {
			return fmt.Errorf("failed to parse source file %s: %w", f, err)
		}
		for k, v := range additionalResources.gitRepositories {
			resources.gitRepositories[k] = v
		}
	}

	if len(resources.kustomizations) == 0 {
		return fmt.Errorf("no Kustomization resource found in file %s", file)
	}

	ks := resources.kustomizations[0]
	name := ks.Name

	// Track cloned git repos for cleanup
	clonedRepos := make(map[string]string)
	defer func() {
		for _, dir := range clonedRepos {
			os.RemoveAll(dir)
		}
	}()

	// Determine the path
	path := templateArgs.path
	if path == "" {
		// If no path provided, need to resolve it based on the source
		if ks.Spec.SourceRef.Kind == sourcev1.GitRepositoryKind {
			// Look up the GitRepository
			sourceKey := fmt.Sprintf("%s/%s", ks.Spec.SourceRef.Namespace, ks.Spec.SourceRef.Name)
			if ks.Spec.SourceRef.Namespace == "" {
				namespace := ks.Namespace
				if namespace == "" {
					namespace = "flux-system"
				}
				sourceKey = fmt.Sprintf("%s/%s", namespace, ks.Spec.SourceRef.Name)
			}

			gitRepo, found := resources.gitRepositories[sourceKey]
			if !found {
				gitRepo, found = resources.gitRepositories[ks.Spec.SourceRef.Name]
			}

			if found {
				// Clone the git repository
				repoPath, err := cloneGitRepository(gitRepo, clonedRepos)
				if err != nil {
					return fmt.Errorf("failed to clone GitRepository %s: %w", ks.Spec.SourceRef.Name, err)
				}

				// Use the spec.path relative to the cloned repo
				if ks.Spec.Path != "" {
					path = filepath.Join(repoPath, ks.Spec.Path)
				} else {
					path = repoPath
				}
			} else {
				return fmt.Errorf("GitRepository %s not found in manifest; use --local-sources to provide a local path mapping", ks.Spec.SourceRef.Name)
			}
		} else if ks.Spec.Path != "" {
			path = ks.Spec.Path
		} else {
			path = filepath.Dir(file)
		}
	}

	// Normalize the path
	path, err = filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path: %w", err)
	}
	path = filepath.Clean(path)

	if fs, err := os.Stat(path); err != nil || !fs.IsDir() {
		return fmt.Errorf("invalid resource path %q", path)
	}

	var builder *build.Builder
	if templateArgs.dryRun {
		builder, err = build.NewBuilder(name, path,
			build.WithTimeout(rootArgs.timeout),
			build.WithKustomizationFile(file),
			build.WithDryRun(templateArgs.dryRun),
			build.WithNamespace(*kubeconfigArgs.Namespace),
			build.WithIgnore(templateArgs.ignorePaths),
			build.WithStrictSubstitute(templateArgs.strictSubst),
			build.WithRecursive(templateArgs.recursive),
			build.WithLocalSources(templateArgs.localSources),
		)
	} else {
		builder, err = build.NewBuilder(name, path,
			build.WithClientConfig(kubeconfigArgs, kubeclientOptions),
			build.WithTimeout(rootArgs.timeout),
			build.WithKustomizationFile(file),
			build.WithIgnore(templateArgs.ignorePaths),
			build.WithStrictSubstitute(templateArgs.strictSubst),
			build.WithRecursive(templateArgs.recursive),
			build.WithLocalSources(templateArgs.localSources),
		)
	}

	if err != nil {
		return err
	}

	// Create a signal channel
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)

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

		cmd.Print(manifests)
		errChan <- nil
	}()

	select {
	case <-sigc:
		fmt.Println("Template cancelled... exiting.")
		return builder.Cancel()
	case err := <-errChan:
		if err != nil {
			return err
		}
	}

	return nil
}

// parseKustomizationFromFile parses the first Kustomization resource from a YAML file
func parseKustomizationFromFile(path string) (*kustomizev1.Kustomization, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Split by YAML document separator
	docs := bytes.Split(data, []byte("\n---"))
	for _, doc := range docs {
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}

		decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc))
		var ks kustomizev1.Kustomization
		if err := decoder.Decode(&ks); err != nil {
			continue
		}

		if ks.Kind == kustomizev1.KustomizationKind && ks.APIVersion != "" {
			return &ks, nil
		}
	}

	return nil, nil
}
