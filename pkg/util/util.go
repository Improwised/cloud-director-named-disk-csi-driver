/*
   Copyright 2021 VMware, Inc.
   SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"k8s.io/klog"
)

const (
	fsTypeXFS = "xfs"
)

// AddrOf is a generic function to return the address of a variable
// Note. It is mainly meant for converting literal values to pointers (e.g. `addrOf(true)`)
// and not getting the address of a variable (e.g. `addrOf(variable)`)
// Adapted from https://github.com/vmware/go-vcloud-director/blob/9837630a1496b5082d83c19984ccf893c673e2f3/govcd/api.go#L696
// since it is not exported.
func AddrOf[T any](variable T) *T {
	return &variable
}

// ParseEndpoint will parse endpoints and return the scheme and addr for the same
func ParseEndpoint(ep string) (string, string, error) {
	u, err := url.Parse(ep)
	if err != nil {
		return "", "", fmt.Errorf("could not parse endpoint: %v", err)
	}

	addr := path.Join(u.Host, filepath.FromSlash(u.Path))

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "tcp":
	case "unix":
		addr = path.Join("/", addr)
		if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
			return "", "", fmt.Errorf("could not remove unix domain socket %q: %v", addr, err)
		}
	default:
		return "", "", fmt.Errorf("unsupported protocol: %s", scheme)
	}

	return scheme, addr, nil
}

func CollectMountOptions(fsType string, mntFlags []string) []string {
	var options []string

	for _, opt := range mntFlags {
		options = append(options, opt)
	}

	// By default, xfs does not allow mounting of two volumes with the same filesystem uuid.
	// Force ignore this uuid to be able to mount volume + its clone / restored snapshot on the same node.
	if fsType == fsTypeXFS {
		options = append(options, "nouuid")
	}
	return options
}

// LazyUnmountCSI performs a lazy unmount of all CSI-related mount points to prevent
// the process from getting stuck in uninterruptible I/O sleep during container shutdown.
// It uses "umount -l" (MNT_DETACH) which detaches the mount immediately and cleans up
// when the filesystem is no longer busy.
func LazyUnmountCSI() error {
	klog.Infof("Performing lazy unmount of all CSI-related mounts")

	script := `mount 2>/dev/null | grep -E 'kubernetes.io~csi|plugins/kubernetes.io/csi|named-disk.csi.cloud-director' | awk '{print $3}' | xargs -r umount -l 2>/dev/null; mount 2>/dev/null | grep '/var/lib/kubelet/pods/.*/volumes/kubernetes.io~csi' | awk '{print $3}' | xargs -r umount -l 2>/dev/null; true`

	cmd := exec.Command("/bin/sh", "-c", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		klog.Warningf("Lazy unmount command had errors: [%v], output: [%s]", err, string(output))
	} else {
		klog.Infof("Lazy unmount completed successfully")
	}

	return nil
}
