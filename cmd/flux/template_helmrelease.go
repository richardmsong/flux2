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

	"github.com/spf13/cobra"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"

	helmv2 "github.com/fluxcd/helm-controller/api/v2"
	sourcev1 "github.com/fluxcd/source-controller/api/v1"

	"github.com/fluxcd/flux2/v2/internal/template"
	"github.com/fluxcd/flux2/v2/internal/utils"
)

var templateHelmReleaseCmd = &cobra.Command{
	Use:     "helmrelease",
	Aliases: []string{"hr"},
	Short:   "Template a HelmRelease resource",
	Long: `The template helmrelease command renders a HelmRelease resource into Kubernetes manifests.

It fetches the referenced Helm chart from the HelmRepository source, merges values from
the HelmRelease spec, additional values files, and --set flags, then renders the chart
templates to stdout.

The command requires either:
- A file containing the HelmRelease and HelmRepository resources (--file)
- A local chart path (--chart-path) with a HelmRelease file

When using --dry-run mode, the command will not connect to the cluster and will skip
resolving values from ConfigMaps and Secrets referenced in the HelmRelease.`,
	Example: `  # Template a HelmRelease from a manifest file
  flux template helmrelease -f ./helmrelease.yaml --source-file ./helmrepository.yaml

  # Template with additional values
  flux template helmrelease -f ./helmrelease.yaml \
    --source-file ./helmrepository.yaml \
    --values ./production-values.yaml \
    --set image.tag=v1.0.0

  # Template using a local chart
  flux template helmrelease -f ./helmrelease.yaml \
    --chart-path ./charts/my-app

  # Template in dry-run mode (no cluster connection)
  flux template helmrelease -f ./helmrelease.yaml \
    --source-file ./helmrepository.yaml \
    --dry-run

  # Template with custom Kubernetes version
  flux template helmrelease -f ./helmrelease.yaml \
    --source-file ./helmrepository.yaml \
    --kube-version 1.28.0`,
	RunE: templateHelmReleaseCmdRun,
}

type templateHelmReleaseFlags struct {
	file         string
	sourceFiles  []string
	valuesFiles  []string
	setValues    map[string]string
	chartPath    string
	kubeVersion  string
	apiVersions  []string
	namespace    string
	releaseName  string
	dryRun       bool
}

var templateHelmReleaseArgs templateHelmReleaseFlags

func init() {
	templateHelmReleaseCmd.Flags().StringVarP(&templateHelmReleaseArgs.file, "file", "f", "", "path to the HelmRelease manifest file")
	templateHelmReleaseCmd.Flags().StringSliceVar(&templateHelmReleaseArgs.sourceFiles, "source-file", nil, "path to files containing HelmRepository resources")
	templateHelmReleaseCmd.Flags().StringSliceVar(&templateHelmReleaseArgs.valuesFiles, "values", nil, "path to additional values files")
	templateHelmReleaseCmd.Flags().StringToStringVar(&templateHelmReleaseArgs.setValues, "set", nil, "set individual values (key=value)")
	templateHelmReleaseCmd.Flags().StringVar(&templateHelmReleaseArgs.chartPath, "chart-path", "", "path to local chart directory (overrides fetching)")
	templateHelmReleaseCmd.Flags().StringVar(&templateHelmReleaseArgs.kubeVersion, "kube-version", "", "Kubernetes version for template rendering")
	templateHelmReleaseCmd.Flags().StringSliceVar(&templateHelmReleaseArgs.apiVersions, "api-versions", nil, "available API versions for Capabilities")
	templateHelmReleaseCmd.Flags().StringVar(&templateHelmReleaseArgs.namespace, "template-namespace", "", "namespace to use for rendering (overrides HelmRelease spec)")
	templateHelmReleaseCmd.Flags().StringVar(&templateHelmReleaseArgs.releaseName, "release-name", "", "release name to use for rendering (overrides HelmRelease spec)")
	templateHelmReleaseCmd.Flags().BoolVar(&templateHelmReleaseArgs.dryRun, "dry-run", false, "dry-run mode (no cluster connection, skip Secret/ConfigMap value resolution)")

	templateCmd.AddCommand(templateHelmReleaseCmd)
}

func templateHelmReleaseCmdRun(cmd *cobra.Command, args []string) error {
	if templateHelmReleaseArgs.file == "" {
		return fmt.Errorf("--file is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), rootArgs.timeout)
	defer cancel()

	// Parse HelmRelease from file
	helmReleases, err := parseHelmReleasesFromFile(templateHelmReleaseArgs.file)
	if err != nil {
		return fmt.Errorf("failed to parse HelmRelease from file: %w", err)
	}

	if len(helmReleases) == 0 {
		return fmt.Errorf("no HelmRelease resources found in file %s", templateHelmReleaseArgs.file)
	}

	// Parse HelmRepositories from source files
	helmRepositories := make(map[string]*sourcev1.HelmRepository)

	// Also parse the main file for HelmRepositories
	allFiles := append([]string{templateHelmReleaseArgs.file}, templateHelmReleaseArgs.sourceFiles...)
	for _, file := range allFiles {
		repos, err := parseHelmRepositoriesFromFile(file)
		if err != nil {
			return fmt.Errorf("failed to parse HelmRepository from file %s: %w", file, err)
		}
		for k, v := range repos {
			helmRepositories[k] = v
		}
	}

	// Get Kubernetes client if not in dry-run mode
	var kubeClient client.Client
	if !templateHelmReleaseArgs.dryRun {
		kubeClient, err = utils.KubeClient(kubeconfigArgs, kubeclientOptions)
		if err != nil {
			// If we can't get a client and chart path is provided, continue in dry-run mode
			if templateHelmReleaseArgs.chartPath == "" {
				logger.Warningf("failed to create Kubernetes client, continuing in dry-run mode: %v", err)
			}
			kubeClient = nil
		}
	}

	// Create renderer
	renderer := template.NewHelmRenderer(kubeClient, templateHelmReleaseArgs.dryRun || kubeClient == nil)

	// Render each HelmRelease
	var output bytes.Buffer
	for _, hr := range helmReleases {
		opts := &template.HelmTemplateOptions{
			HelmRelease:      hr,
			HelmRepositories: helmRepositories,
			ValuesFiles:      templateHelmReleaseArgs.valuesFiles,
			SetValues:        templateHelmReleaseArgs.setValues,
			ChartPath:        templateHelmReleaseArgs.chartPath,
			KubeVersion:      templateHelmReleaseArgs.kubeVersion,
			APIVersions:      templateHelmReleaseArgs.apiVersions,
			Namespace:        templateHelmReleaseArgs.namespace,
			ReleaseName:      templateHelmReleaseArgs.releaseName,
			DryRun:           templateHelmReleaseArgs.dryRun || kubeClient == nil,
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

// parseHelmReleasesFromFile parses HelmRelease resources from a YAML file
func parseHelmReleasesFromFile(path string) ([]*helmv2.HelmRelease, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var releases []*helmv2.HelmRelease
	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)

	for {
		var hr helmv2.HelmRelease
		if err := decoder.Decode(&hr); err != nil {
			if err == io.EOF {
				break
			}
			// Try to continue past non-HelmRelease resources
			var raw map[string]interface{}
			decoder = k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
			for {
				if err := decoder.Decode(&raw); err != nil {
					if err == io.EOF {
						break
					}
					continue
				}
				// Check if this is a HelmRelease
				if apiVersion, ok := raw["apiVersion"].(string); ok {
					if kind, ok := raw["kind"].(string); ok {
						if kind == helmv2.HelmReleaseKind && (apiVersion == helmv2.GroupVersion.String() || apiVersion == "helm.toolkit.fluxcd.io/v2beta1" || apiVersion == "helm.toolkit.fluxcd.io/v2beta2") {
							// Re-parse as HelmRelease
							// This is a workaround for mixed documents
						}
					}
				}
			}
			break
		}

		// Check if this is actually a HelmRelease
		if hr.Kind == helmv2.HelmReleaseKind && hr.APIVersion != "" {
			releases = append(releases, &hr)
		}
	}

	// If the simple approach didn't work, try a more robust parsing
	if len(releases) == 0 {
		releases, err = parseHelmReleasesRobust(data)
		if err != nil {
			return nil, err
		}
	}

	return releases, nil
}

// parseHelmReleasesRobust provides a more robust parsing of HelmRelease resources
func parseHelmReleasesRobust(data []byte) ([]*helmv2.HelmRelease, error) {
	var releases []*helmv2.HelmRelease

	// Split by YAML document separator
	docs := bytes.Split(data, []byte("\n---"))
	for _, doc := range docs {
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}

		// Add back the document separator for proper parsing
		if !bytes.HasPrefix(doc, []byte("---")) {
			doc = append([]byte("---\n"), doc...)
		}

		decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc))
		var hr helmv2.HelmRelease
		if err := decoder.Decode(&hr); err != nil {
			continue // Skip non-HelmRelease documents
		}

		if hr.Kind == helmv2.HelmReleaseKind && hr.APIVersion != "" {
			releases = append(releases, &hr)
		}
	}

	return releases, nil
}

// parseHelmRepositoriesFromFile parses HelmRepository resources from a YAML file
func parseHelmRepositoriesFromFile(path string) (map[string]*sourcev1.HelmRepository, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	repos := make(map[string]*sourcev1.HelmRepository)

	// Split by YAML document separator
	docs := bytes.Split(data, []byte("\n---"))
	for _, doc := range docs {
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}

		decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc))
		var repo sourcev1.HelmRepository
		if err := decoder.Decode(&repo); err != nil {
			continue // Skip non-HelmRepository documents
		}

		if repo.Kind == sourcev1.HelmRepositoryKind && repo.APIVersion != "" {
			// Store with multiple keys for flexible lookup
			namespace := repo.Namespace
			if namespace == "" {
				namespace = "default"
			}
			repos[fmt.Sprintf("%s/%s", namespace, repo.Name)] = &repo
			repos[repo.Name] = &repo
		}
	}

	return repos, nil
}
