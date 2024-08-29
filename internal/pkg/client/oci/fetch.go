// ------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 bomctl a Series of LF Projects, LLC
// SPDX-FileName: internal/pkg/client/oci/fetch.go
// SPDX-FileType: SOURCE
// SPDX-License-Identifier: Apache-2.0
// ------------------------------------------------------------------------
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ------------------------------------------------------------------------
package oci

import (
	"context"
	"fmt"
	"slices"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	"github.com/bomctl/bomctl/internal/pkg/options"
	"github.com/bomctl/bomctl/internal/pkg/url"
)

func (client *Client) Fetch(fetchURL string, opts *options.FetchOptions) ([]byte, error) {
	parsedURL := client.Parse(fetchURL)
	auth := &url.BasicAuth{Username: parsedURL.Username, Password: parsedURL.Password}

	if opts.UseNetRC {
		if err := auth.UseNetRC(parsedURL.Hostname); err != nil {
			return nil, fmt.Errorf("failed to set auth: %w", err)
		}
	}

	err := client.createRepository(parsedURL, auth)
	if err != nil {
		return nil, err
	}

	client.ctx = context.Background()
	client.memStore = memory.New()

	ref := parsedURL.Tag
	if ref == "" {
		ref = parsedURL.Digest
	}

	var manifestDescriptor, sbomDescriptor *ocispec.Descriptor

	if manifestDescriptor, err = client.fetchManifestDescriptor(ref); err != nil {
		return nil, err
	}

	successors, err := client.getManifestChildren(manifestDescriptor)
	if err != nil {
		return nil, err
	}

	if sbomDescriptor, err = client.getSBOMDescriptor(successors); err != nil {
		return nil, err
	}

	sbomData, err := client.pullSBOM(sbomDescriptor)
	if err != nil {
		return nil, err
	}

	return sbomData, nil
}

func (client *Client) fetchManifestDescriptor(tag string) (*ocispec.Descriptor, error) {
	manifestDescriptor, err := oras.Copy(client.ctx, client.repo, tag, client.memStore, tag, oras.CopyOptions{
		CopyGraphOptions: oras.CopyGraphOptions{FindSuccessors: nil},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest descriptor: %w", err)
	}

	return &manifestDescriptor, nil
}

func (client *Client) getManifestChildren(manifestDescriptor *ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	// Get all "children" of the manifest
	successors, err := content.Successors(client.ctx, client.memStore, *manifestDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve manifest layers: %w", err)
	}

	return successors, nil
}

func (*Client) getSBOMDescriptor(successors []ocispec.Descriptor) (*ocispec.Descriptor, error) {
	var (
		sbomDescriptor ocispec.Descriptor
		sbomDigests    []string
	)

	for _, descriptor := range successors {
		if slices.ContainsFunc(
			[]string{"application/vnd.cyclonedx", "application/spdx", "text/spdx"},
			func(s string) bool { return strings.HasPrefix(descriptor.MediaType, s) },
		) {
			sbomDescriptor = descriptor
			sbomDigests = append(sbomDigests, descriptor.Digest.String())
		}
	}

	// Error if more than one SBOM identified
	if len(sbomDigests) > 1 {
		digestString := strings.Join(
			append([]string{"Specify one of the following digests in the fetch URL:"}, sbomDigests...),
			"\n\t\t",
		)

		return nil, fmt.Errorf("%w.\n\t%s", errMultipleSBOMs, digestString)
	}

	return &sbomDescriptor, nil
}

func (client *Client) pullSBOM(sbomDescriptor *ocispec.Descriptor) ([]byte, error) {
	sbomData, err := content.FetchAll(client.ctx, client.memStore, *sbomDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SBOM data: %w", err)
	}

	return sbomData, nil
}
