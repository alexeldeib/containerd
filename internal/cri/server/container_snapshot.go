/*
   Copyright The containerd Authors.

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

package server

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	containerstore "github.com/containerd/containerd/v2/internal/cri/store/container"
	"github.com/containerd/log"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// createContainerSnapshot creates a snapshot of the container's filesystem and uploads it to S3
func (c *criService) createContainerSnapshot(ctx context.Context, container containerstore.Container, containerSnapshotKey, version string) error {
	// Validate input parameters
	if containerSnapshotKey == "" {
		return fmt.Errorf("container snapshot key cannot be empty")
	}
	if version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	if container.Container == nil {
		return fmt.Errorf("container.Container is nil")
	}

	// Get container info
	info, err := container.Container.Info(ctx)
	if err != nil {
		return fmt.Errorf("failed to get container info for container %s: %w", container.ID, err)
	}

	// Get the snapshotter
	if info.Snapshotter == "" {
		return fmt.Errorf("container %s has no snapshotter configured", container.ID)
	}
	snapshotter := c.client.SnapshotService(info.Snapshotter)

	// The container's active snapshot key
	activeKey := info.SnapshotKey
	if activeKey == "" {
		return fmt.Errorf("container %s has no snapshot key", container.ID)
	}

	// Create a committed snapshot with timestamp to avoid conflicts
	commitKey := fmt.Sprintf("%s-%s-checkpoint-%d", containerSnapshotKey, version, time.Now().Unix())
	log.G(ctx).Infof("Committing snapshot %s from active snapshot %s", commitKey, activeKey)

	if err := snapshotter.Commit(ctx, commitKey, activeKey,
		snapshots.WithLabels(map[string]string{
			"containerd.io/gc.root":  time.Now().UTC().Format(time.RFC3339),
			"container.snapshot.key": containerSnapshotKey,
			"snapshot.version":       version,
			"snapshot.timestamp":     time.Now().UTC().Format(time.RFC3339),
		}),
	); err != nil {
		return fmt.Errorf("failed to commit snapshot: %w", err)
	}

	// View the committed snapshot to get mounts
	viewKey := fmt.Sprintf("%s-view", commitKey)
	mounts, err := snapshotter.View(ctx, viewKey, commitKey)
	if err != nil {
		return fmt.Errorf("failed to create view of committed snapshot: %w", err)
	}
	defer snapshotter.Remove(ctx, viewKey)

	// Create a diff of the snapshot
	differ := c.client.DiffService()

	// Compare empty lower (to get all files) with our snapshot upper
	desc, err := differ.Compare(ctx,
		[]mount.Mount{}, // empty lower to capture all changes
		mounts,          // upper is our committed snapshot
		diff.WithMediaType(ocispec.MediaTypeImageLayerGzip),
		diff.WithReference(fmt.Sprintf("snapshots/%s/%s", containerSnapshotKey, version)),
	)
	if err != nil {
		return fmt.Errorf("failed to create diff: %w", err)
	}

	log.G(ctx).Infof("Created diff for snapshot: %s (size=%d, digest=%s)", commitKey, desc.Size, desc.Digest)

	// Read the diff from content store
	content := c.client.ContentStore()
	ra, err := content.ReaderAt(ctx, desc)
	if err != nil {
		return fmt.Errorf("failed to get reader for diff: %w", err)
	}
	defer ra.Close()

	// Read all content
	data := make([]byte, desc.Size)
	if _, err := ra.ReadAt(data, 0); err != nil && err != io.EOF {
		return fmt.Errorf("failed to read diff content: %w", err)
	}

	// Upload to S3
	if err := c.uploadSnapshotToS3(ctx, containerSnapshotKey, version, data); err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	log.G(ctx).Infof("Successfully created and uploaded snapshot for container (key=%s, version=%s, size=%d)", containerSnapshotKey, version, len(data))
	return nil
}

// prepareRestoreSnapshot downloads a snapshot from S3 and prepares it for container creation
func (c *criService) prepareRestoreSnapshot(ctx context.Context, containerID, imageRef, containerSnapshotKey, version, snapshotterName string) (string, error) {
	// Validate input parameters
	if containerID == "" {
		return "", fmt.Errorf("container ID cannot be empty")
	}
	if imageRef == "" {
		return "", fmt.Errorf("image reference cannot be empty")
	}
	if containerSnapshotKey == "" {
		return "", fmt.Errorf("container snapshot key cannot be empty")
	}
	if version == "" {
		return "", fmt.Errorf("version cannot be empty")
	}

	log.G(ctx).Infof("Preparing restore snapshot for container %s (key=%s, version=%s)", containerID, containerSnapshotKey, version)

	// Download from S3
	data, err := c.downloadSnapshotFromS3(ctx, containerSnapshotKey, version)
	if err != nil {
		return "", fmt.Errorf("failed to download snapshot for container %s: %w", containerID, err)
	}

	// Import to content store
	cs := c.client.ContentStore()
	ref := fmt.Sprintf("restore-%s-%s-%d", containerSnapshotKey, version, time.Now().Unix())

	// Calculate digest
	dgst := digest.SHA256.FromBytes(data)

	// Write to content store
	writer, err := cs.Writer(ctx,
		content.WithRef(ref),
		content.WithDescriptor(ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageLayerGzip,
			Digest:    dgst,
			Size:      int64(len(data)),
		}))
	if err != nil {
		return "", fmt.Errorf("failed to create content writer for container %s: %w", containerID, err)
	}

	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return "", fmt.Errorf("failed to write content for container %s: %w", containerID, err)
	}

	if err := writer.Commit(ctx, int64(len(data)), dgst); err != nil {
		return "", fmt.Errorf("failed to commit content for container %s: %w", containerID, err)
	}

	// Resolve the image locally
	image, err := c.LocalResolve(imageRef)
	if err != nil {
		return "", fmt.Errorf("failed to resolve image %q for container %s: %w", imageRef, containerID, err)
	}

	// Convert to containerd image to access rootfs
	containerdImage, err := c.toContainerdImage(ctx, image)
	if err != nil {
		return "", fmt.Errorf("failed to get containerd image for container %s: %w", containerID, err)
	}

	// Get the image's root filesystem layers
	diffIDs, err := containerdImage.RootFS(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get image rootfs for container %s: %w", containerID, err)
	}

	// Calculate the chain ID of the top layer
	// This will be the parent for our restored snapshot
	chainID := identity.ChainID(diffIDs).String()

	// Get the snapshotter
	snapshotter := c.client.SnapshotService(snapshotterName) // TODO: make configurable

	// Create a temporary snapshot for applying our downloaded layer
	tempKey := fmt.Sprintf("restore-temp-%s-%d", containerID, time.Now().UnixNano())
	mounts, err := snapshotter.Prepare(ctx, tempKey, chainID)
	if err != nil {
		return "", fmt.Errorf("failed to prepare temp snapshot for container %s: %w", containerID, err)
	}

	// Apply our downloaded layer to the temporary snapshot
	applier := c.client.DiffService()
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    dgst,
		Size:      int64(len(data)),
	}

	if _, err := applier.Apply(ctx, desc, mounts); err != nil {
		// Cleanup temp snapshot on error
		if removeErr := snapshotter.Remove(ctx, tempKey); removeErr != nil {
			log.G(ctx).WithError(removeErr).Errorf("Failed to cleanup temp snapshot %s after apply error", tempKey)
		}
		return "", fmt.Errorf("failed to apply restored layer for container %s: %w", containerID, err)
	}

	// The temporary snapshot is already active and ready to use
	// We don't commit it because containers need active (read-write) snapshots
	log.G(ctx).Infof("Successfully prepared restored snapshot: %s", tempKey)
	return tempKey, nil
}

// uploadSnapshotToS3 uploads snapshot data to S3
func (c *criService) uploadSnapshotToS3(ctx context.Context, containerSnapshotKey, version string, data []byte) error {
	if c.s3Client == nil {
		return fmt.Errorf("S3 client not configured - snapshot functionality is disabled")
	}

	if len(data) == 0 {
		return fmt.Errorf("cannot upload empty snapshot data")
	}

	key := fmt.Sprintf("snapshots/%s/%s/filesystem.tar.gz", containerSnapshotKey, version)

	if err := c.s3Client.Upload(ctx, key, data); err != nil {
		return fmt.Errorf("failed to upload snapshot to S3 (key=%s, size=%d): %w", key, len(data), err)
	}

	log.G(ctx).Infof("Uploaded snapshot to S3: %s (size=%d)", key, len(data))
	return nil
}

// downloadSnapshotFromS3 downloads snapshot data from S3
func (c *criService) downloadSnapshotFromS3(ctx context.Context, containerSnapshotKey, version string) ([]byte, error) {
	if c.s3Client == nil {
		return nil, fmt.Errorf("S3 client not configured - snapshot functionality is disabled")
	}

	key := fmt.Sprintf("snapshots/%s/%s/filesystem.tar.gz", containerSnapshotKey, version)

	data, err := c.s3Client.Download(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to download snapshot from S3 (key=%s): %w", key, err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("downloaded snapshot data is empty (key=%s)", key)
	}

	log.G(ctx).Infof("Downloaded snapshot from S3: %s (size=%d)", key, len(data))
	return data, nil
}
