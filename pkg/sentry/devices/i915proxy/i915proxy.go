// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package i915proxy implements a restricted proxy for Intel i915 DRM render
// nodes. Unsupported ioctls fail closed.
package i915proxy

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// DRMDeviceMajor is the fixed major number used by Linux DRM devices.
	DRMDeviceMajor = 226

	// renderMinorBase is the first minor number reserved for DRM render nodes.
	renderMinorBase = 128
	renderMinorLimit = 192

	drmVersionSize = 64
	drmGetCapSize = 16
	drmSetClientCapSize = 16
	drmMagicSize = 4

	// maxDRMStringSize bounds allocations for user-supplied DRM_VERSION buffers.
	maxDRMStringSize = 4096
)

const (
	drmIoctlVersion = uintptr(linux.IOWR('d', 0x00, drmVersionSize))
	drmIoctlGetMagic = uintptr(linux.IOR('d', 0x02, drmMagicSize))
	drmIoctlGetCap = uintptr(linux.IOWR('d', 0x0c, drmGetCapSize))
	drmIoctlSetClientCap = uintptr(linux.IOW('d', 0x0d, drmSetClientCapSize))
)

// Device describes a render node assigned to a container. Path must name the
// host-side /dev/dri/renderD<num> device, and Major and Minor must match it.
type Device struct {
	Path string
	Major uint32
	Minor uint32
}

// ValidateDevice verifies that a device assignment names one DRM render node.
// Primary, control, and arbitrary character devices are not accepted.
func ValidateDevice(dev Device) error {
	if dev.Major != DRMDeviceMajor {
		return fmt.Errorf("i915proxy: device %q has major %d, want DRM major %d", dev.Path, dev.Major, DRMDeviceMajor)
	}
	if !filepath.IsAbs(dev.Path) || filepath.Clean(dev.Path) != dev.Path || !strings.HasPrefix(dev.Path, "/dev/dri/renderD") {
		return fmt.Errorf("i915proxy: device path %q is not a /dev/dri/renderD<num> render node", dev.Path)
	}
	suffix := strings.TrimPrefix(filepath.Base(dev.Path), "renderD")
	if suffix == "" {
		return fmt.Errorf("i915proxy: device path %q has no render-node number", dev.Path)
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return fmt.Errorf("i915proxy: invalid render-node number in %q", dev.Path)
		}
	}
	nodeMinor, err := strconv.ParseUint(suffix, 10, 32)
	if err != nil {
		return fmt.Errorf("i915proxy: invalid render-node number in %q: %w", dev.Path, err)
	}
	if nodeMinor != uint64(dev.Minor) || dev.Minor < renderMinorBase || dev.Minor >= renderMinorLimit {
		return fmt.Errorf("i915proxy: device %q has minor %d; expected matching render minor in [%d, %d)", dev.Path, dev.Minor, renderMinorBase, renderMinorLimit)
	}
	return nil
}

// Register registers each explicitly assigned Intel i915 render node in vfsObj.
// Device paths are registered by major/minor, so container device nodes still
// come from the OCI specification.
func Register(vfsObj *vfs.VirtualFilesystem, devices []Device, useDevGofer bool) error {
	if vfsObj == nil {
		return fmt.Errorf("i915proxy: nil VFS")
	}
	if len(devices) == 0 {
		return fmt.Errorf("i915proxy: enabled without an allocated render node")
	}

	seen := make(map[uint32]struct{}, len(devices))
	for _, dev := range devices {
		if err := ValidateDevice(dev); err != nil {
			return err
		}
		if _, ok := seen[dev.Minor]; ok {
			return fmt.Errorf("i915proxy: duplicate render-node minor %d", dev.Minor)
		}
		seen[dev.Minor] = struct{}{}
	}
	for _, dev := range devices {
		renderDev := &renderDevice{
			relpath: strings.TrimPrefix(dev.Path, "/dev/"),
			minor: dev.Minor,
			useDevGofer: useDevGofer,
		}
		if err := vfsObj.RegisterDevice(vfs.CharDevice, dev.Major, dev.Minor, renderDev, &vfs.RegisterDeviceOptions{
			GroupName: "drm",
		}); err != nil {
			return fmt.Errorf("i915proxy: registering %s: %w", dev.Path, err)
		}
	}
	return nil
}

// SupportedIoctl reports whether cmd is a fixed, explicitly implemented DRM
// ioctl. It does not imply support for GEM, submission, mmap, or media ioctls.
func SupportedIoctl(cmd uintptr) bool {
	switch cmd {
	case drmIoctlVersion, drmIoctlGetMagic, drmIoctlGetCap, drmIoctlSetClientCap:
		return true
	default:
		return false
	}
}

// renderDevice implements vfs.Device for an assigned DRM render node.
//
// +stateify savable
type renderDevice struct {
	relpath string
	minor uint32
	useDevGofer bool
}

// Open implements vfs.Device.Open.
func (dev *renderDevice) Open(ctx context.Context, mnt *vfs.Mount, d *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	hostFD, _, err := openHostDevFile(ctx, dev.relpath, dev.useDevGofer, opts.Flags|uint32(unix.O_NOFOLLOW))
	if err != nil {
		return nil, err
	}
	closeHostFD := true
	defer func() {
		if closeHostFD {
			_ = unix.Close(int(hostFD))
		}
	}()

	var st unix.Stat_t
	if err := unix.Fstat(int(hostFD), &st); err != nil {
		return nil, fmt.Errorf("i915proxy: fstat %s: %w", dev.relpath, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFCHR ||
		unix.Major(uint64(st.Rdev)) != DRMDeviceMajor ||
		unix.Minor(uint64(st.Rdev)) != dev.minor {
		return nil, fmt.Errorf("i915proxy: %s does not refer to assigned DRM device %d:%d", dev.relpath, DRMDeviceMajor, dev.minor)
	}
	if err := verifyI915Driver(hostFD); err != nil {
		return nil, fmt.Errorf("i915proxy: rejecting %s: %w", dev.relpath, err)
	}

	fd := &renderFD{hostFD: hostFD}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, d, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile: true,
	}); err != nil {
		return nil, err
	}
	closeHostFD = false
	return &fd.vfsfd, nil
}

// renderFD implements vfs.FileDescriptionImpl for an i915 render node.
//
// +stateify savable
type renderFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	hostFD int32
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *renderFD) Release(context.Context) {
	_ = unix.Close(int(fd.hostFD))
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *renderFD) Ioctl(ctx context.Context, _ usermem.IO, _ uintptr, args arch.SyscallArguments) (uintptr, error) {
	cmd := uintptr(args[1].Uint())
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		panic("Ioctl should be called from a task context")
	}
	if ctx.IsLogging(log.Debug) {
		ctx.Debugf("i915proxy: DRM ioctl cmd=%#x", cmd)
	}
	switch cmd {
	case drmIoctlVersion:
		return fd.ioctlVersion(task, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)))
	case drmIoctlGetCap:
		return fd.ioctlFixed(task, cmd, args[2].Pointer(), drmGetCapSize, true)
	case drmIoctlSetClientCap:
		return fd.ioctlFixed(task, cmd, args[2].Pointer(), drmSetClientCapSize, false)
	case drmIoctlGetMagic:
		return fd.ioctlFixed(task, cmd, args[2].Pointer(), drmMagicSize, true)
	default:
		return 0, linuxerr.ENOTTY
	}
}

func (fd *renderFD) ioctlFixed(task *kernel.Task, cmd uintptr, addr hostarch.Addr, size uint32, copyOut bool) (uintptr, error) {
	if linux.IOC_SIZE(uint32(cmd)) != size {
		return 0, linuxerr.EINVAL
	}
	data := make([]byte, size)
	if cmd != drmIoctlGetMagic {
		if _, err := task.CopyInBytes(addr, data); err != nil {
			return 0, err
		}
	}
	n, err := hostIoctl(fd.hostFD, cmd, data)
	if err != nil {
		return n, err
	}
	if copyOut {
		if _, err := task.CopyOutBytes(addr, data); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (fd *renderFD) ioctlVersion(task *kernel.Task, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != drmVersionSize {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, drmVersionSize)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}

	lengthOffsets := [...]int{16, 32, 48}
	pointerOffsets := [...]int{24, 40, 56}
	guestPtrs := [...]hostarch.Addr{
		hostarch.Addr(binary.LittleEndian.Uint64(params[24:32])),
		hostarch.Addr(binary.LittleEndian.Uint64(params[40:48])),
		hostarch.Addr(binary.LittleEndian.Uint64(params[56:64])),
	}
	var buffers [3][]byte
	var guestCaps [3]uint64
	for i := range buffers {
		guestCaps[i] = binary.LittleEndian.Uint64(params[lengthOffsets[i]:lengthOffsets[i]+8])
		if guestPtrs[i] == 0 || guestCaps[i] == 0 {
			binary.LittleEndian.PutUint64(params[lengthOffsets[i]:lengthOffsets[i]+8], 0)
			continue
		}
		cap := guestCaps[i]
		if cap > maxDRMStringSize {
			cap = maxDRMStringSize
		}
		buffers[i] = make([]byte, int(cap))
		binary.LittleEndian.PutUint64(params[lengthOffsets[i]:lengthOffsets[i]+8], cap)
	}

	n, err := hostIoctlVersion(fd.hostFD, drmIoctlVersion, params, buffers[0], buffers[1], buffers[2], pointerOffsets[:])
	if err != nil {
		return n, err
	}

	for i, buf := range buffers {
		if len(buf) == 0 || guestPtrs[i] == 0 {
			continue
		}
		returnedLen := binary.LittleEndian.Uint64(params[lengthOffsets[i] : lengthOffsets[i]+8])
		copyLen := uint64(len(buf))
		if guestCaps[i] < copyLen {
			copyLen = guestCaps[i]
		}
		// DRM strings are NUL terminated; keep the terminator if the returned
		// length is smaller than the supplied buffer.
		if returnedLen < copyLen {
			copyLen = returnedLen + 1
		}
		if copyLen > uint64(len(buf)) {
			copyLen = uint64(len(buf))
		}
		if copyLen != 0 {
			if _, err := task.CopyOutBytes(guestPtrs[i], buf[:int(copyLen)]); err != nil {
				return n, err
			}
		}
	}
	if _, err := task.CopyOutBytes(addr, params); err != nil {
		return n, err
	}
	return n, nil
}

func openHostDevFile(ctx context.Context, relpath string, useDevGofer bool, openFlags uint32) (int32, error) {
	if useDevGofer {
		devClient := devutil.GoferClientFromContext(ctx)
		if devClient == nil {
			ctx.Warningf("i915proxy: device gofer is unavailable")
			return -1, linuxerr.ENOENT
		}
		hostFD, err := devClient.OpenAt(ctx, relpath, openFlags)
		if err != nil {
			ctx.Warningf("i915proxy: failed to open %s: %v", relpath, err)
			return -1, err
		}
		return int32(hostFD), nil
	}
	hostFD, err := unix.Openat(-1, filepath.Join("/dev", relpath), int(openFlags&unix.O_ACCMODE|unix.O_NOFOLLOW), 0)
	if err != nil {
		ctx.Warningf("i915proxy: failed to open host device %s: %v", relpath, err)
		return -1, err
	}
	return int32(hostFD), nil
}

func verifyI915Driver(hostFD int32) error {
	params := make([]byte, drmVersionSize)
	name := make([]byte, 5)
	binary.LittleEndian.PutUint64(params[16:24], uint64(len(name)))
	if _, err := hostIoctlVersion(hostFD, drmIoctlVersion, params, name, nil, nil, []int{24, 40, 56}); err != nil {
		return fmt.Errorf("DRM version query failed: %w", err)
	}
	if strings.TrimRight(string(name), "\x00") != "i915" {
		return fmt.Errorf("host DRM driver is %q, not i915", strings.TrimRight(string(name), "\x00"))
	}
	return nil
}
