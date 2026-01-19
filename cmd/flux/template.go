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
manifest and renders it appropriately.`,
	Example: `  # Template a resource (auto-detects type from manifest)
  flux template -f ./manifest.yaml

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

// resourceType represents the detected Flux resource type
type resourceType string

const (
	resourceTypeHelmRelease   resourceType = "HelmRelease"
	resourceTypeKustomization resourceType = "Kustomization"
	resourceTypeUnknown       resourceType = "Unknown"
)

// detectResourceType detects the Flux resource type from a manifest file
func detectResourceType(path string) (resourceType, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return resourceTypeUnknown, fmt.Errorf("failed to read file: %w", err)
	}

	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)

	for {
		var raw map[string]interface{}
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		kind, ok := raw["kind"].(string)
		if !ok {
			continue
		}

		apiVersion, ok := raw["apiVersion"].(string)
		if !ok {
			continue
		}

		// Check for HelmRelease
		if kind == helmv2.HelmReleaseKind {
			if apiVersion == helmv2.GroupVersion.String() ||
				apiVersion == "helm.toolkit.fluxcd.io/v2beta1" ||
				apiVersion == "helm.toolkit.fluxcd.io/v2beta2" {
				return resourceTypeHelmRelease, nil
			}
		}

		// Check for Kustomization
		if kind == kustomizev1.KustomizationKind {
			if apiVersion == kustomizev1.GroupVersion.String() ||
				apiVersion == "kustomize.toolkit.fluxcd.io/v1beta1" ||
				apiVersion == "kustomize.toolkit.fluxcd.io/v1beta2" {
				return resourceTypeKustomization, nil
			}
		}
	}

	return resourceTypeUnknown, nil
}

func templateCmdRun(cmd *cobra.Command, args []string) error {
	// If no file flag is provided, show help (subcommands can still be used)
	if templateArgs.file == "" {
		return cmd.Help()
	}

	// Detect the resource type from the file
	resType, err := detectResourceType(templateArgs.file)
	if err != nil {
		return fmt.Errorf("failed to detect resource type: %w", err)
	}

	switch resType {
	case resourceTypeHelmRelease:
		return templateHelmReleaseFromFile(cmd, templateArgs.file)
	case resourceTypeKustomization:
		return templateKustomizationFromFile(cmd, templateArgs.file)
	default:
		return fmt.Errorf("no supported Flux resource (HelmRelease or Kustomization) found in file %s", templateArgs.file)
	}
}

// templateHelmReleaseFromFile templates a HelmRelease from the given file
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

// templateKustomizationFromFile templates a Kustomization from the given file
func templateKustomizationFromFile(cmd *cobra.Command, file string) error {
	// Parse the Kustomization to get name and spec
	ks, err := parseKustomizationFromFile(file)
	if err != nil {
		return fmt.Errorf("failed to parse Kustomization from file: %w", err)
	}

	if ks == nil {
		return fmt.Errorf("no Kustomization resource found in file %s", file)
	}

	name := ks.Name

	// Determine the path
	path := templateArgs.path
	if path == "" {
		// If no path provided, use the spec.path if available or the directory of the file
		if ks.Spec.Path != "" {
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
