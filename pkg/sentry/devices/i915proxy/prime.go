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

package i915proxy

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	drmIoctlPrimeHandleToFD = uintptr(linux.IOWR('d', 0x2d, 12))
	drmIoctlPrimeFDToHandle = uintptr(linux.IOWR('d', 0x2e, 12))

	drmPrimeFlagCloexec = uint32(unix.O_CLOEXEC)
	drmPrimeFlagReadWrite = uint32(unix.O_RDWR)
	drmPrimeAllowedFlags = drmPrimeFlagCloexec | drmPrimeFlagReadWrite
)

// i915DMABufFD exposes a host dma-buf FD to one sandbox as an opaque FD.
// Its host FD is accepted only by i915proxy's PRIME_FD_TO_HANDLE handler.
//
// +stateify savable
type i915DMABufFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	dev *renderDevice
	hostFD int32 `state:"nosave"`
	size uint64
}

// HostFD implements vfs.HostFDProvider.HostFD.
func (fd *i915DMABufFD) HostFD() int {
	return int(fd.hostFD)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *i915DMABufFD) Release(context.Context) {
	fd.dev.removeDMABufFD(fd)
	_ = unix.Close(int(fd.hostFD))
}

// newDMABufFDWrapper takes ownership of hostFD, wraps it, and installs the
// resulting FD in the sandbox's FD table.
func newDMABufFDWrapper(task *kernel.Task, dev *renderDevice, hostFD int32, size uint64, fileFlags uint32, closeOnExec bool) (int32, error) {
	unix.CloseOnExec(int(hostFD))
	vfsObj := task.Kernel().VFS()
	vd := vfsObj.NewAnonVirtualDentry("[i915-dmabuf]")
	defer vd.DecRef(task)

	fd := &i915DMABufFD{
		dev: dev,
		hostFD: hostFD,
		size: size,
	}
	if err := fd.vfsfd.Init(fd, fileFlags, task.Credentials(), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		_ = unix.Close(int(hostFD))
		return -1, err
	}
	dev.addDMABufFD(fd)
	defer fd.vfsfd.DecRef(task)
	sandboxFD, err := task.NewFDFrom(0, &fd.vfsfd, kernel.FDFlags{CloseOnExec: closeOnExec})
	if err != nil {
		return -1, err
	}
	return sandboxFD, nil
}

// ioctlPrimeHandleToFD exports a tracked GEM object as a sandbox dma-buf FD.
func (fd *renderFD) ioctlPrimeHandleToFD(ctx context.Context, task *kernel.Task, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != 12 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	handle := binary.LittleEndian.Uint32(params[0:4])
	flags := binary.LittleEndian.Uint32(params[4:8])
	if flags &^ drmPrimeAllowedFlags != 0 {
		return 0, linuxerr.EINVAL
	}

	fd.gemMu.Lock()
	objectSize, ok := fd.gemObjects[handle]
	if !ok {
		fd.gemMu.Unlock()
		return 0, linuxerr.EINVAL
	}
	// fd is an output parameter; do not forward an application-supplied FD.
	binary.LittleEndian.PutUint32(params[8:12], 0)
	n, err := hostIoctl(fd.hostFD, drmIoctlPrimeHandleToFD, params)
	fd.gemMu.Unlock()
	if err != nil {
		return n, err
	}
	hostFD := int32(binary.LittleEndian.Uint32(params[8:12]))
	if hostFD < 0 {
		return n, linuxerr.EIO
	}

	fileFlags := uint32(linux.O_RDONLY)
	if flags&drmPrimeFlagReadWrite != 0 {
		fileFlags = uint32(linux.O_RDWR)
	}
	sandboxFD, err := newDMABufFDWrapper(task, fd.dev, hostFD, objectSize, fileFlags, flags&drmPrimeFlagCloexec != 0)
	if err != nil {
		return n, err
	}
	binary.LittleEndian.PutUint32(params[8:12], uint32(sandboxFD))
	if _, err := task.CopyOutBytes(addr, params); err != nil {
		if removed := task.FDTable().Remove(ctx, sandboxFD); removed != nil {
			removed.DecRef(ctx)
		}
		return n, err
	}
	return n, nil
}

// ioctlPrimeFDToHandle imports a sandbox dma-buf FD into this DRM file.
func (fd *renderFD) ioctlPrimeFDToHandle(ctx context.Context, task *kernel.Task, addr hostarch.Addr, size uint32) (uintptr, error) {
	if size != 12 {
		return 0, linuxerr.EINVAL
	}
	params := make([]byte, size)
	if _, err := task.CopyInBytes(addr, params); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(params[4:8]) != 0 {
		return 0, linuxerr.EINVAL
	}
	sandboxFD := int32(binary.LittleEndian.Uint32(params[8:12]))
	if sandboxFD < 0 {
		return 0, linuxerr.EBADF
	}
	fileGeneric, _ := task.FDTable().Get(sandboxFD)
	if fileGeneric == nil {
		return 0, linuxerr.EBADF
	}
	defer fileGeneric.DecRef(ctx)
	dmabuf, ok := fileGeneric.Impl().(*i915DMABufFD)
	if !ok || dmabuf.dev.minor != fd.dev.minor || dmabuf.hostFD < 0 || dmabuf.size == 0 {
		return 0, linuxerr.EINVAL
	}

	fd.gemMu.Lock()
	defer fd.gemMu.Unlock()
	binary.LittleEndian.PutUint32(params[8:12], uint32(dmabuf.hostFD))
	n, err := hostIoctl(fd.hostFD, drmIoctlPrimeFDToHandle, params)
	if err != nil {
		return n, err
	}
	handle := binary.LittleEndian.Uint32(params[0:4])
	if handle == 0 {
		return n, linuxerr.EIO
	}
	_, alreadyTracked := fd.gemObjects[handle]
	if existingSize, exists := fd.gemObjects[handle]; exists {
		if existingSize != dmabuf.size {
			return n, fmt.Errorf("i915proxy: imported GEM handle %d has size %d, dma-buf size is %d", handle, existingSize, dmabuf.size)
		}
	} else {
		fd.gemObjects[handle] = dmabuf.size
	}
	// Restore the sandbox FD number; host FD numbers never escape the proxy.
	binary.LittleEndian.PutUint32(params[8:12], uint32(sandboxFD))
	if _, err := task.CopyOutBytes(addr, params); err != nil {
		if !alreadyTracked {
			closeParams := make([]byte, 8)
			binary.LittleEndian.PutUint32(closeParams[0:4], handle)
			_, closeErr := hostIoctl(fd.hostFD, drmIoctlGemClose, closeParams)
			if closeErr == nil {
				delete(fd.gemObjects, handle)
				fd.memmapFile.forgetOffsets(handle)
			} else {
				return n, fmt.Errorf("copying PRIME import result to application failed: %v; closing unreturned GEM handle failed: %w", err, closeErr)
			}
		}
		return n, err
	}
	return n, nil
}

// ioctl implements PRIME ioctls while keeping host dma-buf descriptors private.
func (fd *renderFD) ioctlPrime(ctx context.Context, task *kernel.Task, cmd uintptr, addr hostarch.Addr, size uint32) (uintptr, error) {
	switch cmd {
	case drmIoctlPrimeHandleToFD:
		return fd.ioctlPrimeHandleToFD(ctx, task, addr, size)
	case drmIoctlPrimeFDToHandle:
		return fd.ioctlPrimeFDToHandle(ctx, task, addr, size)
	default:
		return 0, linuxerr.ENOTTY
	}
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl for dma-buf wrapper descriptors.
// The wrapper intentionally exposes no extra host ioctls.
func (fd *i915DMABufFD) Ioctl(context.Context, usermem.IO, uintptr, arch.SyscallArguments) (uintptr, error) {
	return 0, linuxerr.ENOTTY
}
