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
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

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
	drmIoctlGemClose = uintptr(linux.IOW('d', 0x09, 8))
	drmIoctlI915GetParam = uintptr(linux.IOWR('d', 0x46, 16))
	drmIoctlI915GemCreate = uintptr(linux.IOWR('d', 0x5b, 16))
	drmIoctlI915GemPread = uintptr(linux.IOW('d', 0x5c, 32))
	drmIoctlI915GemPwrite = uintptr(linux.IOW('d', 0x5d, 32))
	drmIoctlI915GemBusy = uintptr(linux.IOWR('d', 0x57, 8))
	drmIoctlI915GemSetDomain = uintptr(linux.IOW('d', 0x5f, 12))
	drmIoctlI915GemSWFinish = uintptr(linux.IOW('d', 0x60, 4))
	drmIoctlI915GemSetTiling = uintptr(linux.IOWR('d', 0x61, 16))
	drmIoctlI915GemGetTiling = uintptr(linux.IOWR('d', 0x62, 16))
	drmIoctlI915GemGetAperture = uintptr(linux.IOR('d', 0x63, 16))
	drmIoctlI915GemMmapGTT = uintptr(linux.IOWR('d', 0x64, 16))
	drmIoctlI915GemMmapOffset = uintptr(linux.IOWR('d', 0x64, 32))
	drmIoctlI915GemMadvise = uintptr(linux.IOWR('d', 0x66, 12))
	drmIoctlI915GemExecbuffer2 = uintptr(linux.IOW('d', 0x69, 64))
	drmIoctlI915GemExecbuffer2WR = uintptr(linux.IOWR('d', 0x69, 64))
	drmIoctlI915GemWait = uintptr(linux.IOWR('d', 0x6c, 16))
	drmIoctlI915GemContextCreate = uintptr(linux.IOWR('d', 0x6d, 8))
	drmIoctlI915GemContextCreateExt = uintptr(linux.IOWR('d', 0x6d, 16))
	drmIoctlI915GemContextDestroy = uintptr(linux.IOW('d', 0x6e, 8))
	drmIoctlI915GemSetCaching = uintptr(linux.IOW('d', 0x6f, 8))
	drmIoctlI915GemGetCaching = uintptr(linux.IOWR('d', 0x70, 8))
	drmIoctlI915GetResetStats = uintptr(linux.IOWR('d', 0x72, 20))
	drmIoctlI915GemContextGetParam = uintptr(linux.IOWR('d', 0x74, 24))
	drmIoctlI915GemContextSetParam = uintptr(linux.IOWR('d', 0x75, 24))
	drmIoctlI915Query = uintptr(linux.IOWR('d', 0x79, 16))
	drmIoctlI915GemVMCreate = uintptr(linux.IOWR('d', 0x7a, 16))
	drmIoctlI915GemVMDestroy = uintptr(linux.IOW('d', 0x7b, 16))
	drmIoctlI915GemCreateExt = uintptr(linux.IOWR('d', 0x7c, 24))
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
			openFDs: make(map[*renderFD]struct{}),
		}
		if err := vfsObj.RegisterDevice(vfs.CharDevice, dev.Major, dev.Minor, renderDev, &vfs.RegisterDeviceOptions{
			GroupName: "drm",
		}); err != nil {
			return fmt.Errorf("i915proxy: registering %s: %w", dev.Path, err)
		}
	}
	return nil
}

// SupportedIoctl reports whether cmd is in the proxy's reviewed ioctl allowlist.
// It does not imply full support for every extension of the corresponding UAPI.
func SupportedIoctl(cmd uintptr) bool {
	switch cmd {
	case drmIoctlVersion, drmIoctlGetMagic, drmIoctlGetCap, drmIoctlSetClientCap,
		drmIoctlGemClose, drmIoctlI915GetParam, drmIoctlI915GemCreate,
		drmIoctlI915GemPread, drmIoctlI915GemPwrite, drmIoctlI915GemSWFinish,
		drmIoctlI915GemBusy, drmIoctlI915GemSetDomain,
		drmIoctlI915GemSetTiling, drmIoctlI915GemGetTiling, drmIoctlI915GemGetAperture,
		drmIoctlI915GemMadvise,
		drmIoctlI915GemMmapGTT, drmIoctlI915GemMmapOffset,
		drmIoctlI915GemExecbuffer2, drmIoctlI915GemExecbuffer2WR,
		drmIoctlI915GemWait, drmIoctlI915GemContextCreate,
		drmIoctlI915GemContextCreateExt, drmIoctlI915GemContextDestroy,
		drmIoctlI915GemSetCaching, drmIoctlI915GemGetCaching,
		drmIoctlI915GetResetStats, drmIoctlI915GemContextGetParam,
		drmIoctlI915GemContextSetParam, drmIoctlI915Query,
		drmIoctlI915GemVMCreate, drmIoctlI915GemVMDestroy,
		drmIoctlI915GemCreateExt, drmIoctlPrimeHandleToFD, drmIoctlPrimeFDToHandle:
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

	mu sync.Mutex `state:"nosave"`
	// +checklocks:mu
	openFDs map[*renderFD]struct{} `state:"nosave"`
	// +checklocks:mu
	openDMABufFDs map[*i915DMABufFD]struct{} `state:"nosave"`
}

func (dev *renderDevice) addFD(fd *renderFD) {
	dev.mu.Lock()
	defer dev.mu.Unlock()
	if dev.openFDs == nil {
		dev.openFDs = make(map[*renderFD]struct{})
	}
	dev.openFDs[fd] = struct{}{}
}

func (dev *renderDevice) removeFD(fd *renderFD) {
	dev.mu.Lock()
	defer dev.mu.Unlock()
	delete(dev.openFDs, fd)
}

func (dev *renderDevice) addDMABufFD(fd *i915DMABufFD) {
	dev.mu.Lock()
	defer dev.mu.Unlock()
	if dev.openDMABufFDs == nil {
		dev.openDMABufFDs = make(map[*i915DMABufFD]struct{})
	}
	dev.openDMABufFDs[fd] = struct{}{}
}

func (dev *renderDevice) removeDMABufFD(fd *i915DMABufFD) {
	dev.mu.Lock()
	defer dev.mu.Unlock()
	delete(dev.openDMABufFDs, fd)
}

func (dev *renderDevice) hasOpenFDs() bool {
	dev.mu.Lock()
	defer dev.mu.Unlock()
	return len(dev.openFDs) != 0 || len(dev.openDMABufFDs) != 0
}

// AnyDevicesOpen reports whether an assigned i915 render node has an open file
// description. Live i915 state cannot be checkpointed or restored safely.
func AnyDevicesOpen(vfsObj *vfs.VirtualFilesystem) bool {
	if vfsObj == nil {
		return false
	}
	type deviceID struct {
		kind vfs.DeviceKind
		major uint32
		minor uint32
	}
	var ids []deviceID
	_ = vfsObj.ForEachDevice(func(_ string, kind vfs.DeviceKind, major, minor uint32, _ uint16) error {
		if kind == vfs.CharDevice && major == DRMDeviceMajor {
			ids = append(ids, deviceID{kind: kind, major: major, minor: minor})
		}
		return nil
	})
	for _, id := range ids {
		dev, ok := vfsObj.GetRegisteredDevice(id.kind, id.major, id.minor).(*renderDevice)
		if ok && dev.hasOpenFDs() {
			return true
		}
	}
	return false
}

// Open implements vfs.Device.Open.
func (dev *renderDevice) Open(ctx context.Context, mnt *vfs.Mount, d *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	hostFD, err := openHostDevFile(ctx, dev.relpath, dev.useDevGofer, opts.Flags|uint32(unix.O_NOFOLLOW|unix.O_CLOEXEC))
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

	fd := &renderFD{dev: dev, hostFD: hostFD}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, d, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile: true,
	}); err != nil {
		return nil, err
	}
	fd.memmapFile.SetFD(int(hostFD))
	dev.addFD(fd)
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

	dev *renderDevice
	hostFD int32 `state:"nosave"`
	memmapFile renderMemmapFile

	// gemMu protects gemObjects.
	gemMu sync.Mutex `state:"nosave"`
	// +checklocks:gemMu
	gemObjects map[uint32]uint64 `state:"nosave"`
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *renderFD) Release(context.Context) {
	fd.dev.removeFD(fd)
	fd.memmapFile.MmapFileRefs.Closer = &fd.memmapFile
	fd.memmapFile.MappableRelease()
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
		return fd.ioctlGetCap(task, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)))
	case drmIoctlSetClientCap:
		return fd.ioctlFixed(task, cmd, args[2].Pointer(), drmSetClientCapSize, false)
	case drmIoctlGetMagic:
		return fd.ioctlFixed(task, cmd, args[2].Pointer(), drmMagicSize, true)
	case drmIoctlGemClose:
		return fd.ioctlGemClose(task, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)))
	case drmIoctlI915GemCreate:
		return fd.ioctlGemCreate(task, cmd, args[2].Pointer(), 16, 0)
	case drmIoctlI915GemPread:
		return fd.ioctlGemTransfer(task, cmd, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)), false)
	case drmIoctlI915GemPwrite:
		return fd.ioctlGemTransfer(task, cmd, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)), true)
	case drmIoctlI915GemSWFinish:
		return fd.ioctlGEMHandleFixed(task, cmd, args[2].Pointer(), 4, false)
	case drmIoctlI915GemBusy:
		return fd.ioctlGEMHandleFixed(task, cmd, args[2].Pointer(), 8, true)
	case drmIoctlI915GemSetDomain:
		return fd.ioctlGEMHandleFixed(task, cmd, args[2].Pointer(), 12, false)
	case drmIoctlI915GemSetTiling, drmIoctlI915GemGetTiling:
		return fd.ioctlGEMHandleFixed(task, cmd, args[2].Pointer(), 16, true)
	case drmIoctlI915GemGetAperture:
		return fd.ioctlFixed(task, cmd, args[2].Pointer(), 16, true)
	case drmIoctlI915GemMadvise:
		return fd.ioctlGemMadvise(task, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)))
	case drmIoctlI915GemMmapGTT:
		return fd.ioctlGemMmapGTT(task, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)))
	case drmIoctlI915GemMmapOffset:
		return fd.ioctlGemMmapOffset(task, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)))
	case drmIoctlI915GetParam:
		return fd.ioctlGetParam(task, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)))
	case drmIoctlI915GemExecbuffer2, drmIoctlI915GemExecbuffer2WR:
		return fd.ioctlExecbuffer2(task, cmd, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)))
	case drmIoctlI915GemWait:
		return fd.ioctlGEMHandleFixed(task, cmd, args[2].Pointer(), 16, true)
	case drmIoctlI915GemContextCreate:
		return fd.ioctlContextCreate(task, cmd, args[2].Pointer(), false)
	case drmIoctlI915GemContextCreateExt:
		return fd.ioctlContextCreate(task, cmd, args[2].Pointer(), true)
	case drmIoctlI915GemContextDestroy:
		return fd.ioctlContextDestroy(task, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)))
	case drmIoctlI915GemSetCaching:
		return fd.ioctlGEMHandleFixed(task, cmd, args[2].Pointer(), 8, false)
	case drmIoctlI915GemGetCaching:
		return fd.ioctlGEMHandleFixed(task, cmd, args[2].Pointer(), 8, true)
	case drmIoctlI915GetResetStats:
		return fd.ioctlFixed(task, cmd, args[2].Pointer(), 20, true)
	case drmIoctlI915GemContextGetParam, drmIoctlI915GemContextSetParam:
		return fd.ioctlFixed(task, cmd, args[2].Pointer(), 24, true)
	case drmIoctlI915Query:
		return fd.ioctlQuery(task, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)))
	case drmIoctlI915GemVMCreate:
		return fd.ioctlVMControl(task, cmd, args[2].Pointer(), true)
	case drmIoctlI915GemVMDestroy:
		return fd.ioctlVMControl(task, cmd, args[2].Pointer(), false)
	case drmIoctlI915GemCreateExt:
		return fd.ioctlGemCreate(task, cmd, args[2].Pointer(), 24, 16)
	case drmIoctlPrimeHandleToFD, drmIoctlPrimeFDToHandle:
		return fd.ioctlPrime(ctx, task, cmd, args[2].Pointer(), linux.IOC_SIZE(uint32(cmd)))
	default:
		return 0, linuxerr.ENOTTY
	}
}

const maxGEMTransferBytes = 16 << 20

func (fd *renderFD) ioctlGemMadvise(task *kernel.Task, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != 12 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	handle := binary.LittleEndian.Uint32(params[0:4])
	advice := binary.LittleEndian.Uint32(params[4:8])
	if advice > 1 {
		return 0, linuxerr.EINVAL
	}
	fd.gemMu.Lock()
	if _, ok := fd.gemObjects[handle]; !ok {
		fd.gemMu.Unlock()
		return 0, linuxerr.EINVAL
	}
	n, err := hostIoctl(fd.hostFD, drmIoctlI915GemMadvise, params)
	fd.gemMu.Unlock()
	if err != nil {
		return n, err
	}
	if _, err := task.CopyOutBytes(addr, params); err != nil {
		return n, err
	}
	return n, nil
}

// ioctlGemTransfer translates data_ptr in GEM_PREAD/GEM_PWRITE and bounds the
// amount of memory copied or exposed to the host driver.
func (fd *renderFD) ioctlGemTransfer(task *kernel.Task, cmd uintptr, addr hostarch.Addr, size uint32, write bool) (uintptr, error) {
	if size != 32 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	handle := binary.LittleEndian.Uint32(params[0:4])
	if binary.LittleEndian.Uint32(params[4:8]) != 0 {
		return 0, linuxerr.EINVAL
	}
	offset := binary.LittleEndian.Uint64(params[8:16])
	length := binary.LittleEndian.Uint64(params[16:24])
	dataAddr := hostarch.Addr(binary.LittleEndian.Uint64(params[24:32]))
	if length > maxGEMTransferBytes {
		return 0, linuxerr.E2BIG
	}
	if length != 0 && dataAddr == 0 {
		return 0, linuxerr.EFAULT
	}
	data := make([]byte, int(length))
	if write && length != 0 {
		if _, err := task.CopyInBytes(dataAddr, data); err != nil {
			return 0, err
		}
	}

	fd.gemMu.Lock()
	objectSize, ok := fd.gemObjects[handle]
	if !ok || offset > objectSize || length > objectSize-offset {
		fd.gemMu.Unlock()
		return 0, linuxerr.EINVAL
	}
	n, err := hostIoctlI915GemTransfer(fd.hostFD, cmd, params, data)
	fd.gemMu.Unlock()
	if err != nil {
		return n, err
	}
	if !write && length != 0 {
		if _, err := task.CopyOutBytes(dataAddr, data); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (fd *renderFD) ioctlGEMHandleFixed(task *kernel.Task, cmd uintptr, addr hostarch.Addr, size uint32, copyOut bool) (uintptr, error) {
	if linux.IOC_SIZE(uint32(cmd)) != size || size < 4 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	handle := binary.LittleEndian.Uint32(params[0:4])
	fd.gemMu.Lock()
	if _, ok := fd.gemObjects[handle]; !ok {
		fd.gemMu.Unlock()
		return 0, linuxerr.EINVAL
	}
	n, err := hostIoctl(fd.hostFD, cmd, params)
	fd.gemMu.Unlock()
	if err != nil {
		return n, err
	}
	if copyOut {
		if _, err := task.CopyOutBytes(addr, params); err != nil {
			return n, err
		}
	}
	return n, nil
}

const (
	drmCapPrime = 0x5
	drmCapSyncobj = 0x13
	drmCapSyncobjTimeline = 0x14

	drmPrimeCapImport = 1
	drmPrimeCapExport = 2
)

// ioctlGetCap reports only capabilities that the proxy can provide safely.
// In particular, syncobj support is hidden until its handles and fence FDs
// have explicit translation support.
func (fd *renderFD) ioctlGetCap(task *kernel.Task, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != drmGetCapSize {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	switch binary.LittleEndian.Uint64(params[0:8]) {
	case drmCapPrime:
		if _, err := hostIoctl(fd.hostFD, drmIoctlGetCap, params); err != nil {
			return 0, err
		}
		value := binary.LittleEndian.Uint64(params[8:16])
		value &= drmPrimeCapImport | drmPrimeCapExport
		binary.LittleEndian.PutUint64(params[8:16], value)
	case drmCapSyncobj, drmCapSyncobjTimeline:
		binary.LittleEndian.PutUint64(params[8:16], 0)
	default:
		if _, err := hostIoctl(fd.hostFD, drmIoctlGetCap, params); err != nil {
			return 0, err
		}
	}
	if _, err := task.CopyOutBytes(addr, params); err != nil {
		return 0, err
	}
	return 0, nil
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

const (
	maxExecBufferObjects = 16384
	maxExecBufferRelocations = 65536
	i915ExecObject2Size = 56
	i915RelocationEntrySize = 32
	i915ExecFenceArrayFlag = uint64(1 << 19)
	i915ExecUseExtensionsFlag = uint64(1 << 21)
	i915ExecFenceInFlag = uint64(1 << 16)
	i915ExecFenceOutFlag = uint64(1 << 17)
	i915ExecFenceSubmitFlag = uint64(1 << 20)
	i915ExecNoRelocFlag = uint64(1 << 11)
	i915ExecHandleLUTFlag = uint64(1 << 12)
	// Bits outside this mask are not passed to the host driver.
	i915ExecFlagMask = uint64(0x3f | (3 << 6) | (1 << 8) | (1 << 10) | (1 << 11) | (1 << 12) | (3 << 13) | (1 << 15) | (1 << 18))
)

const maxTrackedGEMObjects = 1 << 16

func (fd *renderFD) ioctlGemClose(task *kernel.Task, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != 8 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(params[4:8]) != 0 {
		return 0, linuxerr.EINVAL
	}
	handle := binary.LittleEndian.Uint32(params[0:4])
	fd.gemMu.Lock()
	if _, ok := fd.gemObjects[handle]; !ok {
		fd.gemMu.Unlock()
		return 0, linuxerr.EINVAL
	}
	n, err := hostIoctl(fd.hostFD, drmIoctlGemClose, params)
	if err != nil {
		fd.gemMu.Unlock()
		return n, err
	}
	delete(fd.gemObjects, handle)
	fd.memmapFile.forgetOffsets(handle)
	fd.gemMu.Unlock()
	return n, nil
}

func (fd *renderFD) ioctlGemCreate(task *kernel.Task, cmd uintptr, addr hostarch.Addr, size uint32, extensionOffset int) (uintptr, error) {
	if linux.IOC_SIZE(uint32(cmd)) != size || (size != 16 && size != 24) {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	requestedSize := binary.LittleEndian.Uint64(params[0:8])
	if requestedSize == 0 || requestedSize > math.MaxInt64 {
		return 0, linuxerr.EINVAL
	}
	// The GEM_CREATE pad and GEM_CREATE_EXT flags are restricted to zero.
	if binary.LittleEndian.Uint32(params[12:16]) != 0 {
		return 0, linuxerr.EINVAL
	}
	if extensionOffset != 0 {
		if extensionOffset+8 > int(size) || binary.LittleEndian.Uint64(params[extensionOffset:extensionOffset+8]) != 0 {
			return 0, linuxerr.EINVAL
		}
	}

	fd.gemMu.Lock()
	defer fd.gemMu.Unlock()
	if len(fd.gemObjects) >= maxTrackedGEMObjects {
		return 0, linuxerr.ENOMEM
	}
	n, err := hostIoctl(fd.hostFD, cmd, params)
	if err != nil {
		return n, err
	}
	handle := binary.LittleEndian.Uint32(params[8:12])
	actualSize := binary.LittleEndian.Uint64(params[0:8])
	if handle == 0 || actualSize == 0 || actualSize > math.MaxInt64 {
		return n, linuxerr.EIO
	}
	if fd.gemObjects == nil {
		fd.gemObjects = make(map[uint32]uint64)
	}
	if _, exists := fd.gemObjects[handle]; exists {
		return n, linuxerr.EIO
	}
	fd.gemObjects[handle] = actualSize
	if _, err := task.CopyOutBytes(addr, params); err != nil {
		closeParams := make([]byte, 8)
		binary.LittleEndian.PutUint32(closeParams[0:4], handle)
		_, closeErr := hostIoctl(fd.hostFD, drmIoctlGemClose, closeParams)
		delete(fd.gemObjects, handle)
		if closeErr != nil {
			return n, fmt.Errorf("copying GEM create result to application failed: %v; closing unreturned GEM handle failed: %w", err, closeErr)
		}
		return n, err
	}
	return n, nil
}

func (fd *renderFD) ioctlContextCreate(task *kernel.Task, cmd uintptr, addr hostarch.Addr, extended bool) (uintptr, error) {
	size := uint32(8)
	if extended {
		size = 16
	}
	if linux.IOC_SIZE(uint32(cmd)) != size {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(params[0:4]) != 0 || binary.LittleEndian.Uint32(params[4:8]) != 0 {
		return 0, linuxerr.EINVAL
	}
	if extended && binary.LittleEndian.Uint64(params[8:16]) != 0 {
		return 0, linuxerr.EINVAL
	}
	n, err := hostIoctl(fd.hostFD, cmd, params)
	if err != nil {
		return n, err
	}
	if _, err := task.CopyOutBytes(addr, params); err != nil {
		return n, err
	}
	return n, nil
}

func (fd *renderFD) ioctlContextDestroy(task *kernel.Task, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != 8 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(params[0:4]) == 0 || binary.LittleEndian.Uint32(params[4:8]) != 0 {
		return 0, linuxerr.EINVAL
	}
	return hostIoctl(fd.hostFD, drmIoctlI915GemContextDestroy, params)
}

func (fd *renderFD) ioctlVMControl(task *kernel.Task, cmd uintptr, addr hostarch.Addr, create bool) (uintptr, error) {
	if linux.IOC_SIZE(uint32(cmd)) != 16 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, 16)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	vmID := binary.LittleEndian.Uint32(params[0:4])
	flags := binary.LittleEndian.Uint32(params[4:8])
	extensions := binary.LittleEndian.Uint64(params[8:16])
	if flags != 0 || extensions != 0 || (create && vmID != 0) || (!create && vmID == 0) {
		return 0, linuxerr.EINVAL
	}
	n, err := hostIoctl(fd.hostFD, cmd, params)
	if err != nil {
		return n, err
	}
	if create {
		if _, err := task.CopyOutBytes(addr, params); err != nil {
			return n, err
		}
	}
	return n, nil
}

const (
	maxI915QueryItems = 64
	maxI915QueryItemBytes = 16 << 20
	maxI915QueryTotalBytes = 64 << 20
	i915QueryItemSize = 24

	i915QueryTopologyInfo = 1
	i915QueryEngineInfo = 2
	i915QueryMemoryRegions = 4
	i915QueryHWConfigTable = 5
	i915QueryGeometrySubSlices = 6
	i915QueryGuCSubmissionVersion = 7
)

func (fd *renderFD) ioctlQuery(task *kernel.Task, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != 16 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	itemCount := binary.LittleEndian.Uint32(params[0:4])
	if binary.LittleEndian.Uint32(params[4:8]) != 0 {
		return 0, linuxerr.EINVAL
	}
	itemsAddr := hostarch.Addr(binary.LittleEndian.Uint64(params[8:16]))
	if itemCount == 0 || itemCount > maxI915QueryItems || itemsAddr == 0 {
		return 0, linuxerr.EINVAL
	}
	items := make([]byte, int(itemCount)*i915QueryItemSize)
	if _, err := task.CopyInBytes(itemsAddr, items); err != nil {
		return 0, err
	}
	dataAddrs := make([]hostarch.Addr, int(itemCount))
	dataBuffers := make([][]byte, int(itemCount))
	totalBytes := uint32(0)
	for i := 0; i < int(itemCount); i++ {
		base := i * i915QueryItemSize
		queryID := binary.LittleEndian.Uint64(items[base : base+8])
		switch queryID {
		case i915QueryTopologyInfo, i915QueryEngineInfo, i915QueryMemoryRegions,
			i915QueryHWConfigTable, i915QueryGeometrySubSlices, i915QueryGuCSubmissionVersion:
		default:
			return 0, linuxerr.EINVAL
		}
		if binary.LittleEndian.Uint32(items[base+12:base+16]) != 0 {
			return 0, linuxerr.EINVAL
		}
		length := int32(binary.LittleEndian.Uint32(items[base+8 : base+12]))
		ptr := hostarch.Addr(binary.LittleEndian.Uint64(items[base+16 : base+24]))
		if length < 0 || uint32(length) > maxI915QueryItemBytes {
			return 0, linuxerr.E2BIG
		}
		if uint32(length) > maxI915QueryTotalBytes-totalBytes {
			return 0, linuxerr.E2BIG
		}
		totalBytes += uint32(length)
		if length == 0 {
			continue
		}
		if ptr == 0 {
			return 0, linuxerr.EFAULT
		}
		dataAddrs[i] = ptr
		dataBuffers[i] = make([]byte, int(length))
	}
	n, err := hostIoctlI915Query(fd.hostFD, drmIoctlI915Query, params, items, dataBuffers)
	if err != nil {
		return n, err
	}
	for i, data := range dataBuffers {
		if len(data) == 0 {
			continue
		}
		if _, err := task.CopyOutBytes(dataAddrs[i], data); err != nil {
			return n, err
		}
	}
	if _, err := task.CopyOutBytes(itemsAddr, items); err != nil {
		return n, err
	}
	if _, err := task.CopyOutBytes(addr, params); err != nil {
		return n, err
	}
	return n, nil
}

func (fd *renderFD) ioctlExecbuffer2(task *kernel.Task, cmd uintptr, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != 64 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	objectsAddr := hostarch.Addr(binary.LittleEndian.Uint64(params[0:8]))
	objectCount := binary.LittleEndian.Uint32(params[8:12])
	flags := binary.LittleEndian.Uint64(params[40:48])
	if objectCount == 0 || objectCount > maxExecBufferObjects || objectsAddr == 0 {
		return 0, linuxerr.EINVAL
	}
	if flags&^i915ExecFlagMask != 0 ||
		flags&(i915ExecUseExtensionsFlag|i915ExecFenceInFlag|i915ExecFenceOutFlag|i915ExecFenceSubmitFlag|i915ExecFenceArrayFlag) != 0 {
		return 0, linuxerr.EINVAL
	}
	// Cliprect, extension, and fence pointer arrays are not implemented.
	if binary.LittleEndian.Uint32(params[28:32]) != 0 || binary.LittleEndian.Uint64(params[32:40]) != 0 {
		return 0, linuxerr.EINVAL
	}
	// rsvd1 carries a 32-bit context ID. rsvd2 requires FD translation for
	// sync-file fences and must remain zero until that path is implemented.
	if binary.LittleEndian.Uint64(params[48:56])>>32 != 0 || binary.LittleEndian.Uint64(params[56:64]) != 0 {
		return 0, linuxerr.EINVAL
	}

	objects := make([]byte, int(objectCount)*i915ExecObject2Size)
	if _, err := task.CopyInBytes(objectsAddr, objects); err != nil {
		return 0, err
	}
	relocations := make([][]byte, int(objectCount))
	relocationAddrs := make([]hostarch.Addr, int(objectCount))
	totalRelocations := uint32(0)
	for i := 0; i < int(objectCount); i++ {
		base := i * i915ExecObject2Size
		handle := binary.LittleEndian.Uint32(objects[base : base+4])
		count := binary.LittleEndian.Uint32(objects[base+4 : base+8])
		ptr := hostarch.Addr(binary.LittleEndian.Uint64(objects[base+8 : base+16]))
		alignment := binary.LittleEndian.Uint64(objects[base+16 : base+24])
		objectFlags := binary.LittleEndian.Uint64(objects[base+32 : base+40])
		if handle == 0 || objectFlags&^uint64(0xdf) != 0 ||
			binary.LittleEndian.Uint64(objects[base+40:base+48]) != 0 ||
			binary.LittleEndian.Uint64(objects[base+48:base+56]) != 0 {
			return 0, linuxerr.EINVAL
		}
		if alignment != 0 && alignment&(alignment-1) != 0 {
			return 0, linuxerr.EINVAL
		}
		if count == 0 && ptr != 0 {
			return 0, linuxerr.EINVAL
		}
		if count > maxExecBufferRelocations-totalRelocations {
			return 0, linuxerr.E2BIG
		}
		totalRelocations += count
		if count == 0 {
			continue
		}
		if ptr == 0 {
			return 0, linuxerr.EFAULT
		}
		relocationAddrs[i] = ptr
		relocations[i] = make([]byte, int(count)*i915RelocationEntrySize)
		if _, err := task.CopyInBytes(ptr, relocations[i]); err != nil {
			return 0, err
		}
	}
	if flags&i915ExecNoRelocFlag != 0 && totalRelocations != 0 {
		return 0, linuxerr.EINVAL
	}

	// The GEM handle table and host file description must remain consistent
	// for the full duration of submission.
	fd.gemMu.Lock()
	for i := 0; i < int(objectCount); i++ {
		handle := binary.LittleEndian.Uint32(objects[i*i915ExecObject2Size : i*i915ExecObject2Size+4])
		if _, ok := fd.gemObjects[handle]; !ok {
			fd.gemMu.Unlock()
			return 0, linuxerr.EINVAL
		}
		for offset := 0; offset < len(relocations[i]); offset += i915RelocationEntrySize {
			targetHandle := binary.LittleEndian.Uint32(relocations[i][offset : offset+4])
			if flags&i915ExecHandleLUTFlag != 0 {
				if targetHandle >= objectCount {
					fd.gemMu.Unlock()
					return 0, linuxerr.EINVAL
				}
			} else if _, ok := fd.gemObjects[targetHandle]; !ok {
				fd.gemMu.Unlock()
				return 0, linuxerr.EINVAL
			}
		}
	}
	n, err := hostIoctlI915Execbuffer2(fd.hostFD, cmd, params, objects, relocations, nil)
	fd.gemMu.Unlock()
	if err != nil {
		return n, err
	}
	for i, relocs := range relocations {
		if len(relocs) == 0 {
			continue
		}
		if _, err := task.CopyOutBytes(relocationAddrs[i], relocs); err != nil {
			return n, err
		}
	}
	if _, err := task.CopyOutBytes(objectsAddr, objects); err != nil {
		return n, err
	}
	if cmd == drmIoctlI915GemExecbuffer2WR {
		if _, err := task.CopyOutBytes(addr, params); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (fd *renderFD) ioctlGemMmapGTT(task *kernel.Task, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != 16 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(params[4:8]) != 0 {
		return 0, linuxerr.EINVAL
	}
	handle := binary.LittleEndian.Uint32(params[0:4])
	fd.gemMu.Lock()
	objectSize, ok := fd.gemObjects[handle]
	if !ok {
		fd.gemMu.Unlock()
		return 0, linuxerr.EINVAL
	}
	n, err := hostIoctl(fd.hostFD, drmIoctlI915GemMmapGTT, params)
	if err != nil {
		fd.gemMu.Unlock()
		return n, err
	}
	offset := binary.LittleEndian.Uint64(params[8:16])
	if err := fd.memmapFile.recordOffset(offset, hostarch.MemoryTypeWriteCombine, objectSize, handle); err != nil {
		fd.gemMu.Unlock()
		return n, err
	}
	fd.gemMu.Unlock()
	if _, err := task.CopyOutBytes(addr, params); err != nil {
		return n, err
	}
	return n, nil
}

func (fd *renderFD) ioctlGemMmapOffset(task *kernel.Task, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != 32 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(params[4:8]) != 0 || binary.LittleEndian.Uint64(params[24:32]) != 0 {
		return 0, linuxerr.EINVAL
	}
	handle := binary.LittleEndian.Uint32(params[0:4])
	var memoryType hostarch.MemoryType
	switch binary.LittleEndian.Uint64(params[16:24]) {
	case 0: // I915_MMAP_OFFSET_GTT
		memoryType = hostarch.MemoryTypeWriteCombine
	case 1: // I915_MMAP_OFFSET_WC
		memoryType = hostarch.MemoryTypeWriteCombine
	case 2: // I915_MMAP_OFFSET_WB
		memoryType = hostarch.MemoryTypeWriteBack
	case 3: // I915_MMAP_OFFSET_UC
		memoryType = hostarch.MemoryTypeUncached
	default:
		return 0, linuxerr.EINVAL
	}
	fd.gemMu.Lock()
	objectSize, ok := fd.gemObjects[handle]
	if !ok {
		fd.gemMu.Unlock()
		return 0, linuxerr.EINVAL
	}
	n, err := hostIoctl(fd.hostFD, drmIoctlI915GemMmapOffset, params)
	if err != nil {
		fd.gemMu.Unlock()
		return n, err
	}
	offset := binary.LittleEndian.Uint64(params[8:16])
	if err := fd.memmapFile.recordOffset(offset, memoryType, objectSize, handle); err != nil {
		fd.gemMu.Unlock()
		return n, err
	}
	fd.gemMu.Unlock()
	if _, err := task.CopyOutBytes(addr, params); err != nil {
		return n, err
	}
	return n, nil
}

func (fd *renderFD) ioctlGetParam(task *kernel.Task, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != 16 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	valuePtr := hostarch.Addr(binary.LittleEndian.Uint64(params[8:16]))
	if valuePtr == 0 {
		return 0, linuxerr.EFAULT
	}
	value := make([]byte, 4)
	n, err := hostIoctlI915GetParam(fd.hostFD, drmIoctlI915GetParam, params, value)
	if err != nil {
		return n, err
	}
	if _, err := task.CopyOutBytes(valuePtr, value); err != nil {
		return n, err
	}
	if _, err := task.CopyOutBytes(addr, params); err != nil {
		return n, err
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
	hostFD, err := unix.Openat(-1, filepath.Join("/dev", relpath), int(openFlags&unix.O_ACCMODE|uint32(unix.O_NOFOLLOW|unix.O_CLOEXEC)), 0)
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
