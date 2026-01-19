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
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/spf13/cobra"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1"
	ssautil "github.com/fluxcd/pkg/ssa/utils"

	"github.com/fluxcd/flux2/v2/internal/build"
)

var templateKsCmd = &cobra.Command{
	Use:     "kustomization",
	Aliases: []string{"ks"},
	Short:   "Template a Kustomization resource",
	Long: `The template kustomization command renders a Flux Kustomization resource into
Kubernetes manifests. It performs the same processing as the kustomize-controller
would do, including:

- Building the kustomization overlay
- Applying variable substitutions from the Kustomization spec
- Processing recursive Kustomizations (with --recursive flag)

This command is similar to 'flux build kustomization' but is designed for templating
workflows where you want to render manifests locally without applying them to a cluster.

Note: You can also use 'flux template -f <file>' which auto-detects the resource type.`,
	Example: `  # Template a Kustomization using a local manifest file
  flux template kustomization my-app \
    --path ./manifests \
    --kustomization-file ./kustomization.yaml

  # Template in dry-run mode (no cluster connection)
  flux template kustomization my-app \
    --path ./manifests \
    --kustomization-file ./kustomization.yaml \
    --dry-run

  # Template recursively with local sources
  flux template kustomization my-app \
    --path ./manifests \
    --kustomization-file ./kustomization.yaml \
    --recursive \
    --local-sources GitRepository/flux-system/my-repo=./path/to/repo

  # Template with specific paths ignored
  flux template kustomization my-app \
    --path ./manifests \
    --kustomization-file ./kustomization.yaml \
    --ignore-paths "/tests/**,/examples/**"`,
	ValidArgsFunction: resourceNamesCompletionFunc(kustomizev1.GroupVersion.WithKind(kustomizev1.KustomizationKind)),
	RunE:              templateKsCmdRun,
}

type templateKsFlags struct {
	kustomizationFile string
	path              string
	ignorePaths       []string
	dryRun            bool
	strictSubst       bool
	recursive         bool
	localSources      map[string]string
}

var templateKsArgs templateKsFlags

func init() {
	templateKsCmd.Flags().StringVar(&templateKsArgs.path, "path", "", "Path to the manifests location.")
	templateKsCmd.Flags().StringVar(&templateKsArgs.kustomizationFile, "kustomization-file", "", "Path to the Flux Kustomization YAML file.")
	templateKsCmd.Flags().StringSliceVar(&templateKsArgs.ignorePaths, "ignore-paths", nil, "set paths to ignore in .gitignore format")
	templateKsCmd.Flags().BoolVar(&templateKsArgs.dryRun, "dry-run", false, "Dry run mode (no cluster connection).")
	templateKsCmd.Flags().BoolVar(&templateKsArgs.strictSubst, "strict-substitute", false,
		"When enabled, the post build substitutions will fail if a var without a default value is declared in files but is missing from the input vars.")
	templateKsCmd.Flags().BoolVarP(&templateKsArgs.recursive, "recursive", "r", false, "Recursively template Kustomizations")
	templateKsCmd.Flags().StringToStringVar(&templateKsArgs.localSources, "local-sources", nil, "Comma-separated list of repositories in format: Kind/namespace/name=path")
	templateCmd.AddCommand(templateKsCmd)
}

func templateKsCmdRun(cmd *cobra.Command, args []string) (err error) {
	if len(args) < 1 {
		return fmt.Errorf("%s name is required", kustomizationType.humanKind)
	}
	name := args[0]

	if templateKsArgs.path == "" {
		return fmt.Errorf("invalid resource path %q", templateKsArgs.path)
	}

	// Normalize the path to handle Windows absolute and relative paths correctly
	templateKsArgs.path, err = filepath.Abs(templateKsArgs.path)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path: %w", err)
	}
	templateKsArgs.path = filepath.Clean(templateKsArgs.path)

	if fs, err := os.Stat(templateKsArgs.path); err != nil || !fs.IsDir() {
		return fmt.Errorf("invalid resource path %q", templateKsArgs.path)
	}

	if templateKsArgs.dryRun && templateKsArgs.kustomizationFile == "" {
		return fmt.Errorf("dry-run mode requires a kustomization file")
	}

	if templateKsArgs.kustomizationFile != "" {
		if fs, err := os.Stat(templateKsArgs.kustomizationFile); os.IsNotExist(err) || fs.IsDir() {
			return fmt.Errorf("invalid kustomization file %q", templateKsArgs.kustomizationFile)
		}
	}

	var builder *build.Builder
	if templateKsArgs.dryRun {
		builder, err = build.NewBuilder(name, templateKsArgs.path,
			build.WithTimeout(rootArgs.timeout),
			build.WithKustomizationFile(templateKsArgs.kustomizationFile),
			build.WithDryRun(templateKsArgs.dryRun),
			build.WithNamespace(*kubeconfigArgs.Namespace),
			build.WithIgnore(templateKsArgs.ignorePaths),
			build.WithStrictSubstitute(templateKsArgs.strictSubst),
			build.WithRecursive(templateKsArgs.recursive),
			build.WithLocalSources(templateKsArgs.localSources),
		)
	} else {
		builder, err = build.NewBuilder(name, templateKsArgs.path,
			build.WithClientConfig(kubeconfigArgs, kubeclientOptions),
			build.WithTimeout(rootArgs.timeout),
			build.WithKustomizationFile(templateKsArgs.kustomizationFile),
			build.WithIgnore(templateKsArgs.ignorePaths),
			build.WithStrictSubstitute(templateKsArgs.strictSubst),
			build.WithRecursive(templateKsArgs.recursive),
			build.WithLocalSources(templateKsArgs.localSources),
		)
	}

	if err != nil {
		return err
	}

	// create a signal channel
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
