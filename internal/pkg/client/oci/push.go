// ------------------------------------------------------------------------
// SPDX-FileCopyrightText: Copyright © 2024 bomctl a Series of LF Projects, LLC
// SPDX-FileName: internal/pkg/client/oci/push.go
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
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"github.com/bomctl/bomctl/internal/pkg/db"
	"github.com/bomctl/bomctl/internal/pkg/options"
	"github.com/bomctl/bomctl/internal/pkg/url"
)

type ociClientWriter struct {
	*bytes.Buffer
	*io.PipeReader
}

func (client *Client) packManifest(opts *options.PushOptions, buf *bytes.Buffer) (ocispec.Descriptor, error) {
	checksum := sha256.Sum256(buf.Bytes())

	sbomDescriptor := ocispec.Descriptor{
		MediaType: getMediaType(opts),
		Digest:    digest.NewDigestFromBytes(digest.SHA256, checksum[:]),
		Size:      int64(buf.Len()),
		Data:      buf.Bytes(),
	}

	// Push SBOM descriptor blob to memory store.
	if err := client.memStore.Push(client.ctx, sbomDescriptor, bytes.NewReader(sbomDescriptor.Data)); err != nil {
		return ocispec.DescriptorEmptyJSON, fmt.Errorf("failed to push to memory store: %w", err)
	}

	manifestDescriptor, err := oras.PackManifest(
		client.ctx,
		client.memStore,
		oras.PackManifestVersion1_1,
		ocispec.MediaTypeImageManifest,
		oras.PackManifestOptions{Layers: []ocispec.Descriptor{sbomDescriptor}},
	)
	if err != nil {
		return ocispec.DescriptorEmptyJSON, fmt.Errorf("%w", err)
	}

	return manifestDescriptor, nil
}

func getDocument(id string, opts *options.Options) (*sbom.Document, error) {
	backend, err := db.BackendFromContext(opts.Context())
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	defer backend.CloseClient()

	// Retrieve document from database.
	doc, err := backend.GetDocumentByID(id)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return doc, nil
}

func getMediaType(opts *options.PushOptions) string {
	opts.Logger.Debug("Getting mediaType for descriptor", "format", opts.Format)

	// Only SPDX JSON encoding is currently supported by protobom, and the media type registered with the
	// IANA has no version parameter (https://www.iana.org/assignments/media-types/application/spdx+json).
	if opts.Format.Type() == formats.SPDXFORMAT {
		return "application/spdx+json"
	}

	return string(opts.Format)
}

func (client *Client) Push(sbomID, pushURL string, opts *options.PushOptions) error {
	parsedURL := client.Parse(pushURL)
	auth := &url.BasicAuth{Username: parsedURL.Username, Password: parsedURL.Password}

	if opts.UseNetRC {
		if err := auth.UseNetRC(parsedURL.Hostname); err != nil {
			return fmt.Errorf("failed to set auth: %w", err)
		}
	}

	doc, err := getDocument(sbomID, opts.Options)
	if err != nil {
		return err
	}

	buf := &ociClientWriter{bytes.NewBuffer([]byte{}), &io.PipeReader{}}

	wr := writer.New(writer.WithFormat(opts.Format))
	if err := wr.WriteStream(doc, buf); err != nil {
		return fmt.Errorf("%w", err)
	}

	client.ctx = context.Background()
	client.memStore = memory.New()

	if err := client.createRepository(parsedURL, auth); err != nil {
		return err
	}

	manifestDescriptor, err := client.packManifest(opts, buf.Buffer)
	if err != nil {
		return err
	}

	tag := parsedURL.Tag
	if tag == "" {
		tag = "latest"
	}

	opts.Logger.Debug("Applying tag", "tag", tag, "digest", manifestDescriptor.Digest)

	if err := client.memStore.Tag(client.ctx, manifestDescriptor, tag); err != nil {
		return fmt.Errorf("%w", err)
	}

	opts.Logger.Debug("Packed manifest", "descriptor", manifestDescriptor)

	copied, err := oras.Copy(client.ctx, client.memStore, tag, client.repo, tag, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	opts.Logger.Debug("Pushed manifest", "descriptor", copied)

	return nil
}
