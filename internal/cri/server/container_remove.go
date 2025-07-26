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
	"errors"
	"fmt"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	containerstore "github.com/containerd/containerd/v2/internal/cri/store/container"
	"github.com/containerd/containerd/v2/pkg/tracing"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// RemoveContainer removes the container.
func (c *criService) RemoveContainer(ctx context.Context, r *runtime.RemoveContainerRequest) (_ *runtime.RemoveContainerResponse, retErr error) {
	span := tracing.SpanFromContext(ctx)
	start := time.Now()
	ctrID := r.GetContainerId()
	log.G(ctx).Infof("RemoveContainer called for container ID: %s", ctrID)
	container, err := c.containerStore.Get(ctrID)
	if err != nil {
		if !errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("an error occurred when try to find container %q: %w", ctrID, err)
		}
		// Do not return error if container metadata doesn't exist.
		log.G(ctx).Tracef("RemoveContainer called for container %q that does not exist", ctrID)
		return &runtime.RemoveContainerResponse{}, nil
	}

	defer c.nri.BlockPluginSync().Unblock()

	id := container.ID
	span.SetAttributes(tracing.Attribute("container.id", id))
	i, err := container.Container.Info(ctx)
	if err != nil {
		if !errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("get container info: %w", err)
		}
		// Since containerd doesn't see the container and criservice's content store does,
		// we should try to recover from this state by removing entry for this container
		// from the container store as well and return successfully.
		log.G(ctx).WithError(err).Warn("get container info failed")
		c.containerStore.Delete(ctrID)
		c.containerNameIndex.ReleaseByKey(ctrID)
		return &runtime.RemoveContainerResponse{}, nil
	}

	// Forcibly stop the containers if they are in running or unknown state
	state := container.Status.Get().State()
	if state == runtime.ContainerState_CONTAINER_RUNNING ||
		state == runtime.ContainerState_CONTAINER_UNKNOWN {
		log.L.Infof("Forcibly stopping container %q", id)
		if err := c.stopContainer(ctx, container, 0); err != nil {
			return nil, fmt.Errorf("failed to forcibly stop container %q: %w", id, err)
		}

	}

	// Set removing state to prevent other start/remove operations against this container
	// while it's being removed.
	if err := setContainerRemoving(container); err != nil {
		return nil, fmt.Errorf("failed to set removing state for container %q: %w", id, err)
	}
	defer func() {
		if retErr != nil {
			// Reset removing if remove failed.
			if err := resetContainerRemoving(container); err != nil {
				log.G(ctx).WithError(err).Errorf("failed to reset removing state for container %q", id)
			}
		}
	}()

	sandbox, err := c.sandboxStore.Get(container.SandboxID)
	if err != nil {
		err = c.nri.RemoveContainer(ctx, nil, &container)
	} else {
		err = c.nri.RemoveContainer(ctx, &sandbox, &container)
	}
	if err != nil {
		log.G(ctx).WithError(err).Error("NRI failed to remove container")
	}

	// NOTE(random-liu): Docker set container to "Dead" state when start removing the
	// container so as to avoid start/restart the container again. However, for current
	// kubelet implementation, we'll never start a container once we decide to remove it,
	// so we don't need the "Dead" state for now.

	// Check if container needs snapshot before removal based on sandbox annotations
	log.G(ctx).Infof("RemoveContainer: checking snapshot policy for container %s", id)

	// Get sandbox to check annotations
	sandbox, sandboxErr := c.sandboxStore.Get(container.SandboxID)
	if sandboxErr != nil {
		log.G(ctx).WithError(sandboxErr).Errorf("Failed to get sandbox for container %s", id)
	} else if sandbox.Config.GetAnnotations() == nil {
		log.G(ctx).Debugf("Container %s sandbox has no annotations", id)
	} else {
		annotations := sandbox.Config.GetAnnotations()
		log.G(ctx).Debugf("Container %s sandbox annotations: %v", id, annotations)

		if annotations["alexeldeib.xyz/snapshot"] == "true" {
			log.G(ctx).Infof("Container %s requests snapshot creation", id)
			// Extract namespace and pod name from sandbox metadata
			sandboxMetadata := sandbox.Config.GetMetadata()
			if sandboxMetadata != nil {
				namespace := sandboxMetadata.GetNamespace()
				podName := sandboxMetadata.GetName()
				containerName := container.Config.GetLabels()["io.kubernetes.container.name"]

				if namespace != "" && podName != "" && containerName != "" {
					// Get snapshot version from annotation, default to "latest" if not specified
					version := annotations["alexeldeib.xyz/snapshot-version"]
					if version == "" {
						version = "latest"
					}

					// Use namespace + pod name to form unique snapshot key
					snapshotKey := fmt.Sprintf("%s/%s", namespace, podName)
					// Use container name for individual container snapshots
					containerSnapshotKey := fmt.Sprintf("%s/%s", snapshotKey, containerName)

					log.G(ctx).Infof("Creating snapshot for container %s (namespace=%s, pod=%s, container=%s, version=%s)", id, namespace, podName, containerName, version)
					if err := c.createContainerSnapshot(ctx, container, containerSnapshotKey, version); err != nil {
						log.G(ctx).WithError(err).Errorf("Failed to create snapshot for container %s (namespace=%s, pod=%s, version=%s)", id, namespace, podName, version)
						// Continue with removal even if snapshot fails
					}
				} else {
					log.G(ctx).Debugf("Container %s missing required metadata for snapshot (namespace=%s, podName=%s, containerName=%s)", id, namespace, podName, containerName)
				}
			} else {
				log.G(ctx).Debugf("Container %s sandbox has no metadata for snapshot", id)
			}
		} else {
			log.G(ctx).Debugf("Container %s snapshot annotation not found or not set to 'true'", id)
		}
	}

	// Delete containerd container.
	if err := container.Container.Delete(ctx, containerd.WithSnapshotCleanup); err != nil {
		if !errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("failed to delete containerd container %q: %w", id, err)
		}
		log.G(ctx).Tracef("Remove called for containerd container %q that does not exist", id)
	}

	// Delete container checkpoint.
	if err := container.Delete(); err != nil {
		return nil, fmt.Errorf("failed to delete container checkpoint for %q: %w", id, err)
	}

	containerRootDir := c.getContainerRootDir(id)
	if err := ensureRemoveAll(ctx, containerRootDir); err != nil {
		return nil, fmt.Errorf("failed to remove container root directory %q: %w",
			containerRootDir, err)
	}
	volatileContainerRootDir := c.getVolatileContainerRootDir(id)
	if err := ensureRemoveAll(ctx, volatileContainerRootDir); err != nil {
		return nil, fmt.Errorf("failed to remove volatile container root directory %q: %w",
			volatileContainerRootDir, err)
	}

	c.containerStore.Delete(id)

	c.containerNameIndex.ReleaseByKey(id)

	c.generateAndSendContainerEvent(ctx, id, container.SandboxID, runtime.ContainerEventType_CONTAINER_DELETED_EVENT)

	containerRemoveTimer.WithValues(i.Runtime.Name).UpdateSince(start)

	span.AddEvent("container removed",
		tracing.Attribute("container.id", container.ID),
		tracing.Attribute("container.remove.duration", time.Since(start).String()),
	)

	return &runtime.RemoveContainerResponse{}, nil
}

// setContainerRemoving sets the container into removing state. In removing state, the
// container will not be started or removed again.
func setContainerRemoving(container containerstore.Container) error {
	return container.Status.Update(func(status containerstore.Status) (containerstore.Status, error) {
		// Do not remove container if it's still running or unknown.
		if status.State() == runtime.ContainerState_CONTAINER_RUNNING {
			return status, errors.New("container is still running, to stop first")
		}
		if status.State() == runtime.ContainerState_CONTAINER_UNKNOWN {
			return status, errors.New("container state is unknown, to stop first")
		}
		if status.Starting {
			return status, errors.New("container is in starting state, can't be removed")
		}
		if status.Removing {
			return status, errors.New("container is already in removing state")
		}
		status.Removing = true
		return status, nil
	})
}

// resetContainerRemoving resets the container removing state on remove failure. So
// that we could remove the container again.
func resetContainerRemoving(container containerstore.Container) error {
	return container.Status.Update(func(status containerstore.Status) (containerstore.Status, error) {
		status.Removing = false
		return status, nil
	})
}
