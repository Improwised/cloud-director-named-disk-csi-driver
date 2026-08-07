/*
   Copyright 2021 VMware, Inc.
   SPDX-License-Identifier: Apache-2.0
*/

package csi

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/akutz/gofsutil"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog"
	mountutils "k8s.io/mount-utils"
	utilexec "k8s.io/utils/exec"

	"github.com/vmware/cloud-director-named-disk-csi-driver/pkg/util"
)

const (
	// The maximum number of volumes that a node can have attached.
	// Since we're using bus 1 only, it allows up-to 16 disks of which one (#7)
	// is pre-allocated for the Host-Bus-Adapter. Hence, we have only 15 disks.
	maxVolumesPerNode = 15

	DevDiskPath          = "/dev/disk/by-path"
	ScsiHostPath         = "/sys/class/scsi_host"
	HostNameRegexPattern = "^host[0-9]+"

	ScsiBlockPathPrefix = "/sys/class/block"
	ScsiBlockPathSuffix = "device/rescan"

	// unmountTimeout is the maximum time to wait for a normal (non-lazy) unmount
	// before falling back to lazy unmount (MNT_DETACH). A normal umount can block
	// indefinitely in uninterruptible sleep (D-state) if the underlying filesystem
	// or block device is wedged; lazy unmount always returns immediately.
	unmountTimeout = 10 * time.Second

	// mountTimeout is the maximum time to wait for a mount/format operation
	// to complete. Mount operations can block indefinitely in D-state if
	// the underlying storage block device is wedged.
	mountTimeout = 20 * time.Second

	// mountinfoRetries is the number of times to retry mount-info operations
	// that depend on /proc/self/mountinfo. Under concurrent mount operations
	// (many pods sharing one volume), the mount table changes faster than a
	// consistent snapshot can be obtained. This retry count gives the table
	// time to stabilize.
	mountinfoRetries     = 10
	mountinfoRetryDelay  = 500 * time.Millisecond
)

type nodeService struct {
	Driver *VCDDriver
	NodeID string
}

// NewNodeService creates and returns a NodeService struct.
func NewNodeService(driver *VCDDriver, nodeID string) csi.NodeServer {
	return &nodeService{
		Driver: driver,
		NodeID: nodeID,
	}
}

// NodeStageVolumeBlockMount 'stages' block mounts. There is really no need to stage block mounts since the device is
// directly exposed to the pod. However, we need to run some scans in order to ensure that disks that are resized are
// correctly reconfigured on the host. Hence, this function does an NOP staging and sends scan signals on scsi buses.
func (ns *nodeService) NodeStageVolumeBlockMount(ctx context.Context, volumeCapability *csi.VolumeCapability,
	publishContext map[string]string, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {

	volumeID := req.GetVolumeId()
	if volumeID == "" {
		return nil, status.Error(codes.InvalidArgument, "NodeStageVolumeBlockMount: Volume Id not provided")
	}

	vmFullName, ok := publishContext[VMFullNameAttribute]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument,
			"NodeStageVolumeBlockMount: PublishContext did not contain full vm name in publish context")
	}

	diskUUID, ok := publishContext[DiskUUIDAttribute]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument,
			"NodeStageVolumeBlockMount: PublishContext did not contain disk UUID in publish context")
	}

	err := ns.rescanDiskInVM(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "NodeStageVolumeBlockMount: unable to scan SCSI bus for vm [%s]: [%v]",
			vmFullName, err)
	}

	devicePath, err := ns.getDiskPath(ctx, vmFullName, diskUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "NodeStageVolumeBlockMount: unable to obtain disk for vm [%s], disk [%s]: [%v]",
			vmFullName, volumeID, err)
	}

	// rescan block devices to get new sizes in case disks were resized
	if err := ns.rescanScsiBlockDiskInVM(ctx, devicePath); err != nil {
		return nil, status.Errorf(codes.Internal, "NodeStageVolumeBlockMount: Unable to rescan disk [%s] in VM: [%v]",
			devicePath, err)
	}
	klog.Infof("NodeStageVolumeBlockMount: Scanned size of disk [%s] on vm [%s] successfully", devicePath, vmFullName)

	klog.Infof("NodeStageVolumeBlockMount: skipping stage of disk [%s] on vm [%s] since this is a block mount",
		devicePath, vmFullName)
	return &csi.NodeStageVolumeResponse{}, nil
}

func (ns *nodeService) NodeStageVolumeFilesystemMount(ctx context.Context, volumeCapability *csi.VolumeCapability,
	publishContext map[string]string, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {

	// parameter fsType is the filesystem type of the storage block to be mounted
	var fsType string
	var ok bool
	volumeContext := req.GetVolumeContext()
	// volumeContext might be optional;
	if volumeContext == nil {
		fsType, ok = publishContext[FileSystemParameter]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument,
				"NodeStageVolumeFilesystemMount: PublishContext does not have [%s] set", FileSystemParameter)
		}
	} else {
		ephemeralVolume, ok := volumeContext[EphemeralVolumeContext]
		if ok {
			if ephemeralVolume == "true" {
				return &csi.NodeStageVolumeResponse{}, status.Errorf(codes.Unimplemented,
					"NodeStageVolumeFilesystemMount: [%s] not supported", EphemeralVolumeContext)
			}
		}
		fsType, ok = volumeContext[FileSystemParameter]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument,
				"NodeStageVolumeFilesystemMount: PublishContext does not have [%s] set", FileSystemParameter)
		}
	}

	vmFullName, ok := publishContext[VMFullNameAttribute]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument,
			"NodeStageVolumeFilesystemMount: PublishContext did not contain full vm name in publish context")
	}

	mountMode := "rw"
	if ns.isVolumeReadOnly(volumeCapability) {
		mountMode = "ro"
	}

	mnt := volumeCapability.GetMount()
	mountFlags := mnt.GetMountFlags()
	if mnt == nil {
		return nil, status.Errorf(codes.InvalidArgument, "volume capability must have mount details")
	}
	if mnt.FsType != fsType {
		// allow fsType passed from the PV or other sources to go through
		klog.Infof("fs type in mount-point [%s] does not match specified fs type [%s]. Using FS [%s] from PV config.",
			mnt.FsType, fsType, fsType)
		mnt.FsType = fsType
	}
	mountFlags = util.CollectMountOptions(mnt.FsType, mountFlags)

	mountFlags = append(mountFlags, mountMode)
	diskUUID, ok := publishContext[DiskUUIDAttribute]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument,
			"NodeStageVolumeFilesystemMount: PublishContext did not contain disk UUID in publish context")
	}

	volumeID := req.GetVolumeId()
	if volumeID == "" {
		return nil, status.Error(codes.InvalidArgument, "NodeStageVolumeFilesystemMount: Volume Id not provided")
	}

	mountDir := req.GetStagingTargetPath()
	if mountDir == "" {
		return nil, status.Error(codes.InvalidArgument, "NodeStageVolumeFilesystemMount: Staging target not provided")
	}

	err := ns.rescanDiskInVM(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "NodeStageVolumeFilesystemMount: unable to scan SCSI bus for vm [%s]: [%v]",
			vmFullName, err)
	}
	devicePath, err := ns.getDiskPath(ctx, vmFullName, diskUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "NodeStageVolumeFilesystemMount: unable to obtain disk for vm [%s], disk [%s]: [%v]",
			vmFullName, volumeID, err)
	}

	// rescan block devices to get new sizes in case disks were resized
	if err := ns.rescanScsiBlockDiskInVM(ctx, devicePath); err != nil {
		return nil, status.Errorf(codes.Internal, "NodeStageVolumeFilesystemMount: Unable to rescan disk [%s] in VM: [%v]",
			devicePath, err)
	}
	klog.Infof("NodeStageVolumeFilesystemMount: Scanned size of disk [%s] on vm [%s] successfully", devicePath, vmFullName)

	// Check if already mounted
	isMounted, isMountedAsExpected, err := ns.isVolumeMountedAsExpected(ctx, devicePath, mountDir, mountMode)
	if err != nil {
		return nil, fmt.Errorf("unable to check if device [%s] is mounted on [%s] and mode [%s]: [%v]",
			devicePath, mountDir, mountMode, err)
	}
	if isMounted {
		if !isMountedAsExpected {
			// Device is already active on the host (e.g. held by running pod subpaths after a CSI
			// daemon restart) but its globalmount staging directory is empty/missing.
			// FormatAndMount would fail on a busy device, so we find the device's current active
			// mount point and bind-mount it to the expected staging directory instead.
			klog.Warningf("Device [%s] is mounted on the host but not at the expected staging dir [%s]. "+
				"Attempting bind-mount recovery.", devicePath, mountDir)

			var activeMounts []gofsutil.Info
			getErr := retryOnMountInfoInconsistency(func() error {
				var innerErr error
				activeMounts, innerErr = gofsutil.GetDevMounts(ctx, devicePath)
				return innerErr
			})
			if getErr != nil || len(activeMounts) == 0 {
				return nil, status.Errorf(codes.Internal,
					"device [%s] reported as mounted but no active mount paths found: [%v]",
					devicePath, getErr)
			}

			// Use the first active mount path as the bind-mount source
			sourcePath := activeMounts[0].Path
			klog.Infof("Bind-mounting device [%s] from active path [%s] to staging dir [%s]",
				devicePath, sourcePath, mountDir)

			// Ensure staging directory exists
			if err := os.MkdirAll(mountDir, 0750); err != nil {
				return nil, status.Errorf(codes.Internal,
					"unable to mkdir staging path [%s]: [%v]", mountDir, err)
			}

			// Bind-mount the active path to the staging directory
			if bindErr := ns.bindMountWithTimeout(ctx, sourcePath, mountDir, mountMode); bindErr != nil {
				return nil, status.Errorf(codes.Internal,
					"bind-mount recovery failed for device [%s] from [%s] to [%s]: [%v]",
					devicePath, sourcePath, mountDir, bindErr)
			}

			klog.Infof("Bind-mount recovery succeeded: device [%s] is now staged at [%s]",
				devicePath, mountDir)
			return &csi.NodeStageVolumeResponse{}, nil
		} else {
			// the device is mounted as expected, so nothing to do
			klog.Infof("Device [%s] mounted on [%s] with correct mode [%s]",
				devicePath, mountDir, mountMode)
			return &csi.NodeStageVolumeResponse{}, nil
		}
	}

	// Check if  directory exists
	mountDirExists, err := ns.checkIfDirExists(mountDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not verify that [%s] is a dir: [%v]", mountDir, err)
	}
	if !mountDirExists {
		// Directory doesn't exist
		klog.Infof("Path [%s] does not exist. Make it\n", mountDir)
		if err := os.MkdirAll(mountDir, 0750); err != nil {
			return nil, status.Error(codes.Internal,
				fmt.Sprintf("unable to mkdir at path [%s] - [%s] ",
					mountDir, err.Error()))
		}
	}

	// Mounting as the device is not yet mounted
	klog.Infof("Mounting device [%s] to folder [%s] of type [%s] with flags [%v]",
		devicePath, mountDir, fsType, mountFlags)
	if err = ns.formatAndMountWithTimeout(ctx, devicePath, mountDir, fsType, mountFlags...); err != nil {
		return nil, status.Error(codes.Internal,
			fmt.Sprintf("unable to format and mount device [%s] at path [%s] with fs [%s] and flags [%v]: [%v]",
				devicePath, mountDir, fsType, mountFlags, err))
	}
	klog.Infof("Mounted device [%s] at path [%s] with fs [%s] and options [%v]",
		devicePath, mountDir, fsType, mountFlags)

	klog.Infof("NodeStageVolumeFilesystemMount successfully staged at [%s] for device [%s]",
		mountDir, devicePath)
	return &csi.NodeStageVolumeResponse{}, nil
}

// NodeStageVolume mounts the device on a directory on the host. For sharing it with
// pods we need to implement NodePublishVolume
func (ns *nodeService) NodeStageVolume(ctx context.Context,
	req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {

	if req == nil {
		return nil, status.Errorf(codes.InvalidArgument, "NodeStageVolume: Request is empty")
	}

	klog.Infof("NodeStageVolume: called with args [%#v]", *req)

	// Check for block device and exit early if specified
	volumeCapability := req.GetVolumeCapability()
	if volumeCapability == nil {
		return nil, status.Errorf(codes.InvalidArgument, "NodeStageVolume: Volume capability not provided")
	}

	publishContext := req.GetPublishContext()
	if publishContext == nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"NodeStageVolume: Publish context not provided")
	}

	// No staging needed for block device. Must be handled by pod itself.
	if isBlockMount := volumeCapability.GetBlock(); isBlockMount != nil {
		if resp, err := ns.NodeStageVolumeBlockMount(ctx, volumeCapability, publishContext, req); err != nil {
			klog.Infof("NodeStageVolume: failed with err = [%v], resp = [%#v]", err, resp)
			return nil, status.Errorf(codes.Internal, "unable to stage volume as block volume: [%v]", err)
		}
	} else {
		klog.Infof("Staging volume as Filesystem Mount")
		if resp, err := ns.NodeStageVolumeFilesystemMount(ctx, volumeCapability, publishContext, req); err != nil {
			klog.Infof("NodeStageVolume: failed with err = [%v], resp = [%#v]", err, resp)
			return nil, status.Errorf(codes.Internal, "unable to stage volume as filesystem volume: [%v]", err)
		}
	}

	return &csi.NodeStageVolumeResponse{}, nil
}

// NodeUnstageVolume unmounts disk from the host.
func (ns *nodeService) NodeUnstageVolume(ctx context.Context,
	req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {

	mountDir := req.GetStagingTargetPath()
	deviceName := req.GetVolumeId()
	if mountDir == "" {
		return nil, status.Error(codes.InvalidArgument,
			"NodeUnstageVolume: Staging Target Path must be provided")
	}

	// Figure out if the target path is present in mounts or not - Unstage is not required for file volumes
	mountDirExists, err := ns.checkIfDirExists(mountDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not verify that [%s] is a dir: [%v]", mountDir, err)
	}
	if !mountDirExists {
		klog.Infof("Path [%s] does not exist. Hence assuming already unmounted.", mountDir)
		return &csi.NodeUnstageVolumeResponse{}, nil
	}

	isMountDirMounted, err := ns.checkIfPathMounted(ctx, mountDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to check if [%s] is mounted: [%v]", mountDir, err)
	}
	if !isMountDirMounted {
		klog.Infof("Path [%s] is not mounted. Hence assuming already unmounted.", mountDir)
		return &csi.NodeUnstageVolumeResponse{}, nil
	}

	// the directory exists and is mounted, so unmount
	klog.Infof("Attempting to unmount path [%s].", mountDir)
	if err = ns.unmountWithLazyFallback(ctx, mountDir); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to unmount [%s]: [%v", mountDir, err)
	}

	klog.Infof("NodeUnstageVolume successful for target [%s] for volume [%s]", mountDir, deviceName)
	return &csi.NodeUnstageVolumeResponse{}, nil
}

// NodePublishVolume bind-mounts the host mountDir onto a dir specific to each pod
// requesting the pvc.
func (ns *nodeService) NodePublishVolume(ctx context.Context,
	req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {

	klog.Infof("NodePublishVolume: called with args %#v", *req)

	if volumeContext := req.GetVolumeContext(); volumeContext != nil {
		if ephemeralVolume, ok := volumeContext[EphemeralVolumeContext]; ok {
			if ephemeralVolume == "true" {
				return &csi.NodePublishVolumeResponse{},
					status.Errorf(codes.Unimplemented, "[%s] not supported", EphemeralVolumeContext)
			}
		}
	}

	diskName := req.GetVolumeId()
	if diskName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "NodePublishVolume: VolumeId not provided")
	}

	volumeCapability := req.GetVolumeCapability()
	if volumeCapability == nil {
		return nil, status.Errorf(codes.InvalidArgument, "NodePublishVolume: VolumeCapability not provided")
	}

	publishContext := req.GetPublishContext()
	if publishContext == nil {
		return nil, status.Errorf(codes.InvalidArgument, "NodePublishVolume: PublishContext not provided")
	}

	isBlockMount := volumeCapability.GetBlock() != nil
	if isBlockMount {
		klog.Infof("NodePublishVolume: [%s] is a block volume. Hence will not publish volume.",
			diskName)
	}

	mnt := volumeCapability.GetMount()
	if mnt == nil && !isBlockMount {
		return nil, status.Errorf(codes.InvalidArgument,
			"volume capability must have mount details for filesystem mounts")
	}

	podMountPath := req.GetTargetPath()
	if podMountPath == "" {
		return nil, status.Errorf(codes.InvalidArgument, "NodePublishVolume: TargetPath not provided")
	}

	mountMode := "rw"
	if ns.isVolumeReadOnly(volumeCapability) {
		// disallow ro if block, since block devices can still modify storage though mounted read-only
		if isBlockMount {
			klog.Infof("Block volume cannot be ReadOnly, since underlying block can still be modified")
			return nil, status.Errorf(codes.InvalidArgument,
				"Block volume cannot be ReadOnly, since underlying block can still be modified")
		}

		mountMode = "ro"
	}

	if isBlockMount {
		// Create target path as file if not exists. For block mount the target should be a file.
		podMountPathDir := filepath.Dir(podMountPath)
		if err := os.MkdirAll(podMountPathDir, 0750); err != nil {
			return nil, status.Errorf(codes.Internal, "unable to create dir for path [%s]: [%v]",
				podMountPathDir, err)
		}

		file, err := os.OpenFile(podMountPath, os.O_CREATE, 0660)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to create file [%s]: [%v]", podMountPath, err)
		}

		if err := file.Close(); err != nil {
			return nil, status.Errorf(codes.Internal, "unable to close file [%s]: [%v]", podMountPath, err)
		}
	} else {
		// Create target path as dir if not exists.
		if err := ns.mkdir(podMountPath); err != nil {
			return nil, status.Errorf(codes.Internal, "unable to create dir [%s]: [%v]", podMountPath, err)
		}
		klog.Infof("Ensured that dir [%s] exists.", podMountPath)
	}

	hostMountPath := ""
	if isBlockMount {
		// For block-mount, the disk on the host is to be directly bind-mounted to the pod.
		diskUUID, ok := publishContext[DiskUUIDAttribute]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument,
				"PublishContext did not contain disk UUID in publish context")
		}
		vmFullName, ok := publishContext[VMFullNameAttribute]
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument,
				"PublishContext did not contain full vm name in publish context")
		}

		volumeID := req.GetVolumeId()
		if volumeID == "" {
			return nil, status.Error(codes.InvalidArgument, "Volume Id not provided")
		}

		devicePath, err := ns.getDiskPath(ctx, vmFullName, diskUUID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to obtain disk for vm [%s], disk [%s]: [%v]",
				vmFullName, volumeID, err)
		}
		hostMountPath = devicePath
	} else {
		// For Filesystem mount, there is a host-level staging directory which needs to be bind-mounted to the pod.
		hostMountPath = req.GetStagingTargetPath()
		if hostMountPath == "" {
			return nil, status.Errorf(codes.InvalidArgument, "NodeStageVolume: StagingTargetPath not provided")
		}

		// For Filesystem mounts verify that host dir (staging dir) exists.
		hostMountPathExists, err := ns.checkIfDirExists(hostMountPath)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to check if host mount dir [%s] exists: [%v]",
				hostMountPath, err)
		}
		if !hostMountPathExists {
			return nil, status.Errorf(codes.Internal, "host mount dir [%s] does not exist", hostMountPath)
		}
	}
	klog.Infof("NodePublishVolume: host mount path is [%s]", hostMountPath)

	// Check if already mounted
	isMounted, isMountedAsExpected, err := ns.isVolumeMountedAsExpected(ctx, hostMountPath, podMountPath, mountMode)
	if err != nil {
		return nil, fmt.Errorf("unable to check if dir [%s] is mounted on [%s] and mode [%s]: [%v]",
			hostMountPath, podMountPath, mountMode, err)
	}
	if isMounted {
		if !isMountedAsExpected {
			return nil, status.Errorf(codes.Internal,
				"dir [%s] not mounted on [%s] and mode [%s] as expected: [%v]",
				hostMountPath, podMountPath, mountMode, err)
		} else {
			// the device is mounted as expected, so nothing to do
			klog.Infof("dir [%s] mounted on [%s] with correct mode [%s]",
				hostMountPath, podMountPath, mountMode)
			return &csi.NodePublishVolumeResponse{}, nil
		}
	}

	// Mounting as the dir is not yet mounted
	mountFlags := append(mnt.GetMountFlags(), mountMode)
	klog.Infof("Mounting dir [%s] to folder [%s] with flags [%v]",
		hostMountPath, podMountPath, mountFlags)
	if err = ns.bindMountWithTimeout(ctx, hostMountPath, podMountPath, mountFlags...); err != nil {
		return nil, status.Errorf(codes.Internal,
			"unable to format and mount path [%s] at path [%s] with flags [%v]: [%v]",
			hostMountPath, podMountPath, mountFlags, err)
	}
	klog.Infof("Mounted path [%s] at path [%s] with options [%v]", hostMountPath, podMountPath, mountFlags)

	klog.Infof("NodePublishVolume: volume successfully published at [%s] for host path [%s]",
		podMountPath, hostMountPath)
	return &csi.NodePublishVolumeResponse{}, nil
}

// NodeUnpublishVolume detaches the bind mount on the pod
func (ns *nodeService) NodeUnpublishVolume(ctx context.Context,
	req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {

	diskName := req.GetVolumeId()
	if diskName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "NodeUnpublishVolume: volumeID must be provided")
	}

	podMountPath := req.GetTargetPath()
	if podMountPath == "" {
		return nil, status.Errorf(codes.InvalidArgument, "NodeUnpublishVolume: Target Path must be provided")
	}

	podMountPathExists, err := ns.checkIfPathExists(podMountPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unable to check if pod mount path [%s] exists: [%v]",
			podMountPath, err)
	}
	if !podMountPathExists {
		klog.Infof("Pod mount path [%s] does not exist. Assuming already unmounted.", podMountPath)
		return &csi.NodeUnpublishVolumeResponse{}, nil
	}

	isDirMounted, err := ns.checkIfPathMounted(ctx, podMountPath)
	if err != nil {
		return nil, fmt.Errorf("unable to check if pod mount dir [%s] is mounted: [%v]", podMountPath, err)
	}

	klog.Infof("Attempting to unmount pod mount dir [%s].", podMountPath)
	if isDirMounted {
		if err = ns.unmountWithLazyFallback(ctx, podMountPath); err != nil {
			return nil, fmt.Errorf("unable to unmount pod mount dir [%s]: [%v]", podMountPath, err)
		}
	}

	klog.Infof("Attempting to remove pod mount dir [%s].", podMountPath)
	if err := ns.rmdir(podMountPath); err != nil {
		return nil, fmt.Errorf("failed to remove pod mount dir %v", podMountPath)
	}

	klog.Infof("NodeUnpublishVolume successful for disk [%s] at mount path [%s]", diskName, podMountPath)
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

func (ns *nodeService) NodeGetCapabilities(_ context.Context, req *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	klog.Infof("NodeGetCapabilities called with req: %#v", req)

	return &csi.NodeGetCapabilitiesResponse{
		Capabilities: ns.Driver.nodeServiceCapabilities,
	}, nil
}

func (ns *nodeService) NodeGetInfo(_ context.Context, _ *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{
		NodeId:             ns.NodeID,
		AccessibleTopology: nil,
		MaxVolumesPerNode:  maxVolumesPerNode,
	}, nil

}

func (ns *nodeService) NodeGetVolumeStats(ctx context.Context,
	req *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {

	klog.Infof("NodeGetVolumeStats called with req: %#v", req)

	volumePath := req.GetVolumePath()
	if volumePath == "" {
		klog.Errorf("unable to get volume path from request")
		return nil, fmt.Errorf("unable to get volume path from request")
	}

	var statFS unix.Statfs_t
	statDone := make(chan error, 1)
	go func() {
		statDone <- unix.Statfs(volumePath, &statFS)
	}()

	select {
	case err := <-statDone:
		if err != nil {
			klog.Errorf("unable to get stats of volume [%s]: [%v]", volumePath, err)
			return nil, fmt.Errorf("unable to get stats of volume [%s]: [%v]", volumePath, err)
		}
	case <-time.After(5 * time.Second):
		klog.Warningf("statfs timed out after 5s for volume [%s], returning empty stats", volumePath)
		return &csi.NodeGetVolumeStatsResponse{
			Usage: []*csi.VolumeUsage{
				{
					Available: 0,
					Total:     0,
					Used:      0,
					Unit:      csi.VolumeUsage_BYTES,
				},
				{
					Available: 0,
					Total:     0,
					Used:      0,
					Unit:      csi.VolumeUsage_INODES,
				},
			},
		}, nil
	case <-ctx.Done():
		klog.Warningf("context cancelled for volume [%s], returning empty stats", volumePath)
		return &csi.NodeGetVolumeStatsResponse{
			Usage: []*csi.VolumeUsage{
				{
					Available: 0,
					Total:     0,
					Used:      0,
					Unit:      csi.VolumeUsage_BYTES,
				},
				{
					Available: 0,
					Total:     0,
					Used:      0,
					Unit:      csi.VolumeUsage_INODES,
				},
			},
		}, nil
	}

	return &csi.NodeGetVolumeStatsResponse{
		Usage: []*csi.VolumeUsage{
			{
				Available: int64(statFS.Bavail) * int64(statFS.Bsize),
				Total:     int64(statFS.Blocks) * int64(statFS.Bsize),
				Used:      (int64(statFS.Blocks) - int64(statFS.Bavail)) * int64(statFS.Bsize),
				Unit:      csi.VolumeUsage_BYTES,
			},
			{
				Available: int64(statFS.Ffree),
				Total:     int64(statFS.Files),
				Used:      int64(statFS.Files) - int64(statFS.Ffree),
				Unit:      csi.VolumeUsage_INODES,
			},
		},
	}, nil
}

func (ns *nodeService) NodeExpandVolume(ctx context.Context,
	req *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	klog.Infof("NodeGetVolumeStats called with req: [%#v]", req)

	if req.GetVolumeCapability() != nil {
		if req.GetVolumeCapability() != nil && req.GetVolumeCapability().GetBlock() != nil {
			klog.Infof("ONLINE Expansion not supported for Block mount volumes")
			return &csi.NodeExpandVolumeResponse{}, nil
		}
	}

	volumePath := req.GetVolumePath()
	if volumePath == "" {
		klog.Errorf("unable to get volume path from request")
		return nil, fmt.Errorf("unable to get volume path from request")
	}

	stagingTargetPath := req.GetStagingTargetPath()
	if stagingTargetPath == "" {
		return nil, status.Errorf(codes.InvalidArgument, "NodeExpandVolume: Staging Path context not provided")
	}
	klog.Infof("Staging Target Path is [%s]", stagingTargetPath)

	diskUUID := req.GetVolumeId()
	if diskUUID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "NodeExpandVolume: Disk UUID not provided")
	}

	mounter := mountutils.New("")
	devicePath, _, err := mountutils.GetDeviceNameFromMount(mounter, stagingTargetPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "NodeExpandVolume: Unable to get device path for [%s]: [%v]",
			stagingTargetPath, err)
	}
	if devicePath == "" {
		return nil, status.Errorf(codes.Internal, "NodeExpandVolume: Empty device path obtained for [%s]: [%v]",
			stagingTargetPath, err)
	}
	klog.Infof("Obtained device path [%s] from mount path [%s] for disk [%s]", devicePath, stagingTargetPath, volumePath)

	// rescan block devices to get new sizes
	if err := ns.rescanScsiBlockDiskInVM(ctx, devicePath); err != nil {
		return nil, status.Errorf(codes.Internal, "NodeExpandVolume: Unable to rescan disk [%s] in VM: [%v]",
			devicePath, err)
	}
	klog.Infof("Scanned size of disk [%s] successfully", devicePath)

	klog.Infof("Resizing volume [%s] host-mounted at [%s] from node", volumePath, stagingTargetPath)
	r := mountutils.NewResizeFs(utilexec.New())
	if _, err := r.Resize(devicePath, stagingTargetPath); err != nil {
		klog.Errorf("Failed to resize volume [%s] mounted at [%s] from node: [%v]", volumePath, stagingTargetPath, err)
		return nil, status.Errorf(codes.Internal,
			"NodeExpandVolume: Failed to resize volume [%s] host-mounted at [%s] from node: [%v]",
			volumePath, stagingTargetPath, err)
	}
	klog.Infof("Successfully resized volume [%s] host-mounted at [%s] from node", volumePath, stagingTargetPath)

	return &csi.NodeExpandVolumeResponse{}, nil
}

// rescanScsiBlockDiskInVM runs `echo "1" > /sys/class/block/sdX/device/rescan`
func (ns *nodeService) rescanScsiBlockDiskInVM(_ context.Context, blockDevice string) error {
	// block device name is of format /dev/sdX. We need only sdX
	parts := strings.Split(blockDevice, "/")
	if len(parts) != 3 {
		return fmt.Errorf("block device path in invalid format: [%s]", blockDevice)
	}

	filePath := fmt.Sprintf("%s/%s/%s", ScsiBlockPathPrefix, parts[2], ScsiBlockPathSuffix)
	if err := os.WriteFile(filePath, []byte("1"), 0200); err != nil {
		return fmt.Errorf("unable to write '1' into file [%s]: [%v]", filePath, err)
	}

	return nil
}

// rescanDiskInVM re-scans the SCSI bus entirely. CSI runs `echo "- - -" > /sys/class/scsi_host/*/scan` inside VM,
// where "- - -" represent controller channel lun.
func (ns *nodeService) rescanDiskInVM(_ context.Context) error {
	// The filepath.Walk walks the file tree, calling the specified function for each file or directory in the tree, including root.
	//  unnamed function is defined to check and perform rescan.
	err := filepath.Walk(ScsiHostPath, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			klog.Errorf("Encounter error while walking through the folder: [%v]", err)
			return nil
		}
		reg, regErr := regexp.Compile(HostNameRegexPattern)
		if regErr != nil {
			klog.Errorf("Encounter error while generating regex error: [%v]", regErr)
			return fmt.Errorf("encounter error while generating regex error: [%v]", regErr)
		}
		if fi.IsDir() {
			return nil
		}
		if reg.MatchString(fi.Name()) {
			// file mode for scan: --w-------
			executedErr := os.WriteFile(fmt.Sprintf("%s/scan", path), []byte("- - -"), 0200)
			if executedErr != nil {
				klog.Errorf("Encounter error while rescanning the disk in VM [%s];executing command failed, [%v]", ns.NodeID, executedErr)
				return fmt.Errorf("encounter error while rescanning the disk in VM [%s];executing command failed, [%v]", ns.NodeID, executedErr)
			}
			klog.Infof("CSI node plugin rescanned the scsi host [%s] successfully", fi.Name())
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("CSI node plugin could not rescan SCSI bus for [%s]: [%v]", ScsiHostPath, err)
	}
	return nil
}

// getDiskPath looks for a device corresponding to vmName:diskName as stored in vSphere. It
// enumerates devices in /dev/disk/by-path and returns a device with UUID matching the scsi UUID.
// It needs disk.enableUUID to be set for the VM.
func (ns *nodeService) getDiskPath(ctx context.Context, vmFullName string, diskUUID string) (string, error) {

	if diskUUID == "" {
		return "", fmt.Errorf("diskUUID should not be an empty string")
	}

	hexDiskUUID := strings.ReplaceAll(diskUUID, "-", "")

	guestDiskPath := ""
	err := filepath.Walk(DevDiskPath, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if guestDiskPath != "" {
			return nil
		}
		if fi.IsDir() {
			return nil
		}

		fileToProcess := path
		if fi.Mode()&os.ModeSymlink != 0 {
			dst, err := filepath.EvalSymlinks(path)
			if err != nil {
				klog.Infof("Error accessing file [%s]: [%v]", path, err)
				return nil
			}
			fileToProcess = dst
		}
		if fileToProcess == "" {
			return nil
		}

		klog.Infof("Checking file: [%s] => [%s]\n", path, fileToProcess)
		scsiCtx, scsiCancel := context.WithTimeout(ctx, 3*time.Second)
		outBytes, err := exec.CommandContext(
			scsiCtx,
			"/lib/udev/scsi_id",
			"--page=0x83",
			"--whitelisted",
			fmt.Sprintf("--device=%v", fileToProcess)).CombinedOutput()
		scsiCancel()
		if err != nil {
			klog.Infof("Encountered error while processing file [%s]: [%v]", fileToProcess, err)
			klog.Infof("Please check if the `disk.enableUUID` parameter is set to 1 for the VM in VC config.")
			return nil
		}
		out := strings.TrimSpace(string(outBytes))
		if len(out) == 33 {
			out = out[1:]
		} else if len(out) != 32 {
			klog.Infof("Obtained uuid with incorrect length: [%s]", out)
			return nil
		}

		if strings.ToLower(out) == strings.ToLower(hexDiskUUID) {
			guestDiskPath = fileToProcess
		}

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("could not create filepath.Walk for [%s]: [%v]", DevDiskPath, err)
	}

	klog.Infof("Obtained matching disk [%s]", guestDiskPath)
	return guestDiskPath, nil
}

func (ns *nodeService) isVolumeReadOnly(capability *csi.VolumeCapability) bool {
	accessMode := capability.GetAccessMode().GetMode()

	return accessMode == csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY ||
		accessMode == csi.VolumeCapability_AccessMode_MULTI_NODE_READER_ONLY
}

// retryOnMountInfoInconsistency retries the given function when it returns an error
// containing "failed to get a consistent snapshot". This helps when the mount table
// is in flux due to concurrent mount operations on shared volumes.
func retryOnMountInfoInconsistency(fn func() error) error {
	var lastErr error
	for i := 0; i < mountinfoRetries; i++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if strings.Contains(lastErr.Error(), "failed to get a consistent snapshot") {
			time.Sleep(mountinfoRetryDelay)
			continue
		}
		return lastErr
	}
	return lastErr
}

// returns isMounted, isMountedAsExpected, error in checking
func (ns *nodeService) isVolumeMountedAsExpected(ctx context.Context, devicePath string, mountDir string,
	mountMode string) (bool, bool, error) {

	var mountedDevs []gofsutil.Info
	err := retryOnMountInfoInconsistency(func() error {
		var innerErr error
		mountedDevs, innerErr = gofsutil.GetDevMounts(ctx, devicePath)
		return innerErr
	})
	if err != nil {
		return false, false, fmt.Errorf("unable to check if [%s] is mounted: [%v]", devicePath, err)
	}
	if len(mountedDevs) == 0 {
		return false, false, nil
	}

	klog.Infof("Device [%s] is already mounted. Checking if it is at [%s].", devicePath, mountDir)
	for _, mountedDev := range mountedDevs {
		if mountedDev.Path == mountDir {
			klog.Infof("Device [%s] mounted at the right path [%s]. Checking for properties...",
				devicePath, mountDir)

			for _, option := range mountedDev.Opts {
				if option == mountMode {
					klog.Infof("Device [%s] mounted on [%s] with correct mode [%s]",
						devicePath, mountDir, mountMode)
					return true, true, nil
				}
			}

			klog.Infof("Device [%s] already mounted on [%s] but with options [%s]",
				devicePath, mountDir, mountedDev.Opts)
			return true, false, nil
		}
	}

	klog.Infof("Device [%s] already mounted but on a different location", devicePath)
	return true, false, nil
}

func (ns *nodeService) checkIfDirExists(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("unable to get stat of [%s]: [%v]", path, err)
	}

	if !fi.IsDir() {
		return false, fmt.Errorf("path [%s] is not a dir", path)
	}

	return true, nil
}

func (ns *nodeService) checkIfPathExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("unable to get stat of [%s]: [%v]", path, err)
	}

	return true, nil
}

func (ns *nodeService) checkIfPathMounted(ctx context.Context, mountDir string) (bool, error) {
	var mountDevices []gofsutil.Info
	err := retryOnMountInfoInconsistency(func() error {
		var innerErr error
		mountDevices, innerErr = gofsutil.GetMounts(ctx)
		return innerErr
	})
	if err != nil {
		return false, fmt.Errorf("unable to get mounts of node")
	}

	for _, mountDevice := range mountDevices {
		if mountDevice.Path == mountDir {
			return true, nil
		}
	}

	return false, nil
}

func (ns *nodeService) mkdir(path string) error {
	fi, err := os.Stat(path)
	if err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("path [%s] exists but is not a directory", path)
		}

		klog.Infof("Path [%s] already exists and is a directory.", path)
		return nil
	}

	// err != nil here
	if !os.IsNotExist(err) {
		return fmt.Errorf("unable to check stats of path [%s]: [%v]", path, err)
	}

	// os.IsNotExist(err) == true here
	mode := os.FileMode(0755)
	if err = os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("unable to recursively create dir [%s] with mode [%#v]: [%v]",
			path, mode, err)
	}

	return nil
}

func (ns *nodeService) rmdir(path string) error {
	klog.Infof("Deleting path %s", path)
	err := os.Remove(path)
	if os.IsNotExist(err) {
		klog.Infof("%s does not exist", path)
		return nil
	}
	return err
}

// unmountWithLazyFallback tries a normal unmount with a timeout; if it does not
// complete within unmountTimeout, it falls back to a lazy unmount (MNT_DETACH)
// which never blocks in uninterruptible I/O sleep. This prevents pod
// termination from hanging indefinitely when the underlying filesystem or
// block device is wedged.
func (ns *nodeService) unmountWithLazyFallback(ctx context.Context, mountPath string) error {
	klog.Infof("Attempting unmount of [%s]", mountPath)

	done := make(chan error, 1)
	go func() {
		done <- gofsutil.Unmount(ctx, mountPath)
	}()

	select {
	case err := <-done:
		if err == nil {
			klog.Infof("Unmount of [%s] succeeded", mountPath)
			return nil
		}
		klog.Warningf("Normal unmount of [%s] failed: [%v]. Falling back to lazy unmount.", mountPath, err)
	case <-time.After(unmountTimeout):
		klog.Warningf("Normal unmount of [%s] timed out after %v. Falling back to lazy unmount.", mountPath, unmountTimeout)
	}

	// Lazy unmount (MNT_DETACH) detaches the mount immediately and cleans up
	// when the filesystem is no longer busy. It never blocks in D-state.
	cmd := exec.Command("umount", "-l", mountPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("lazy unmount of [%s] failed: [%v]: %s", mountPath, err, string(out))
	}
	klog.Infof("Lazy unmount of [%s] succeeded", mountPath)
	return nil
}

// formatAndMountWithTimeout wraps gofsutil.FormatAndMount with a timeout context
func (ns *nodeService) formatAndMountWithTimeout(ctx context.Context, source, target, fsType string, opts ...string) error {
	klog.Infof("Attempting format and mount of [%s] to [%s] with timeout %v", source, target, mountTimeout)
	done := make(chan error, 1)
	go func() {
		done <- gofsutil.FormatAndMount(ctx, source, target, fsType, opts...)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(mountTimeout):
		klog.Errorf("FormatAndMount of [%s] to [%s] timed out after %v", source, target, mountTimeout)
		return fmt.Errorf("FormatAndMount of [%s] to [%s] timed out after %v", source, target, mountTimeout)
	case <-ctx.Done():
		klog.Errorf("FormatAndMount of [%s] to [%s] context cancelled", source, target)
		return ctx.Err()
	}
}

// bindMountWithTimeout wraps gofsutil.BindMount with a timeout context
func (ns *nodeService) bindMountWithTimeout(ctx context.Context, source, target string, opts ...string) error {
	klog.Infof("Attempting bind mount of [%s] to [%s] with timeout %v", source, target, mountTimeout)
	done := make(chan error, 1)
	go func() {
		done <- gofsutil.BindMount(ctx, source, target, opts...)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(mountTimeout):
		klog.Errorf("BindMount of [%s] to [%s] timed out after %v", source, target, mountTimeout)
		return fmt.Errorf("BindMount of [%s] to [%s] timed out after %v", source, target, mountTimeout)
	case <-ctx.Done():
		klog.Errorf("BindMount of [%s] to [%s] context cancelled", source, target)
		return ctx.Err()
	}
}

