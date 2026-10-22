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
	"errors"
	"fmt"
	"math"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *renderFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if opts.Offset > math.MaxInt64 || opts.Length > math.MaxInt64-opts.Offset {
		return linuxerr.EOVERFLOW
	}
	if _, err := fd.memmapFile.memoryTypeForRange(opts.Offset, opts.Length); err != nil {
		return err
	}
	// Use a per-mapping mappable so KVM page tables use the cache type
	// requested when the mmap offset was obtained.
	return vfs.GenericProxyDeviceConfigureMMap(&fd.vfsfd, &renderMappable{
		file: &fd.memmapFile,
	}, opts)
}

// renderMappable represents one application mapping of an i915 render node.
//
// +stateify savable
type renderMappable struct {
	memmap.MappableNoTrackMappings
	file *renderMemmapFile
}

// Translate implements memmap.Mappable.Translate.
func (m *renderMappable) Translate(_ context.Context, _, optional memmap.MappableRange, _ hostarch.AccessType) ([]memmap.Translation, error) {
	memoryType, err := m.file.memoryTypeForRange(optional.Start, optional.Length())
	if err != nil {
		return nil, err
	}
	return []memmap.Translation{{
		Source: optional,
		File: &renderMappedFile{
			file: m.file,
			memoryType: memoryType,
		},
		Offset: optional.Start,
		Perms: hostarch.AnyAccess,
	}}, nil
}

// renderMemmapFile backs render-node mappings with the host DRM file.
//
// +stateify savable
type renderMemmapFile struct {
	memmap.NoBufferedIOFallback
	fsutil.MmapFileRefs

	// fd is the host DRM render-node file descriptor. It remains open until
	// the last mapping reference is released.
	fd int32 `state:"nosave"`
	fdValid bool `state:"nosave"`

	// mu protects the host mappings and mmap offset types.
	mu sync.Mutex `state:"nosave"`
	pages map[uint64][]byte `state:"nosave"`
	offsetTypes map[uint64]hostarch.MemoryType `state:"nosave"`
}

// SetFD implements fsutil.MmapFile.SetFD.
func (mf *renderMemmapFile) SetFD(fd int) {
	mf.fd = int32(fd)
	mf.fdValid = true
}

// IncRef implements memmap.File.IncRef.
func (mf *renderMemmapFile) IncRef(fr memmap.FileRange, memCgID uint32) {
	mf.MmapFileRefs.IncRef(fr, memCgID)
}

// DecRef implements memmap.File.DecRef.
func (mf *renderMemmapFile) DecRef(fr memmap.FileRange) {
	// Keep host mappings cached until the file description and all mappings
	// are released. MapInternal limits the total number of cached pages.
	mf.MmapFileRefs.DecRef(fr)
}

// MappableRelease is called when the render-node file description is closed.
func (mf *renderMemmapFile) MappableRelease() {
	mf.MmapFileRefs.MappableRelease()
}

// FD implements memmap.File.FD.
func (mf *renderMemmapFile) FD() int {
	mf.mu.Lock()
	defer mf.mu.Unlock()
	if !mf.fdValid {
		return -1
	}
	return int(mf.fd)
}

// DataFD implements memmap.File.DataFD.
func (mf *renderMemmapFile) DataFD(memmap.FileRange) (int, error) {
	fd := mf.FD()
	if fd < 0 {
		return -1, linuxerr.EBADF
	}
	return fd, nil
}

// MemoryType implements memmap.File.MemoryType.
func (mf *renderMemmapFile) MemoryType() hostarch.MemoryType {
	return hostarch.MemoryTypeWriteBack
}

// recordOffset records the cache type associated with a host-generated mmap offset.
func (mf *renderMemmapFile) recordOffset(offset uint64, memoryType hostarch.MemoryType) error {
	if offset > math.MaxInt64 {
		return linuxerr.EOVERFLOW
	}
	if offset%uint64(hostarch.PageSize) != 0 {
		return linuxerr.EINVAL
	}
	mf.mu.Lock()
	defer mf.mu.Unlock()
	if mf.offsetTypes == nil {
		mf.offsetTypes = make(map[uint64]hostarch.MemoryType)
	}
	if existing, ok := mf.offsetTypes[offset]; ok && existing != memoryType {
		return fmt.Errorf("i915proxy: host reused mmap offset %#x with conflicting cache types", offset)
	}
	mf.offsetTypes[offset] = memoryType
	return nil
}

// memoryTypeForRange returns the cache type for an mmap range. It rejects
// offsets that were not returned by a supported i915 mmap-offset ioctl and
// ranges that overlap the next known buffer-object mapping.
func (mf *renderMemmapFile) memoryTypeForRange(offset, length uint64) (hostarch.MemoryType, error) {
	if length == 0 || offset > math.MaxInt64 || length > math.MaxInt64-offset {
		return hostarch.MemoryTypeWriteBack, linuxerr.EINVAL
	}
	end := offset + length
	mf.mu.Lock()
	defer mf.mu.Unlock()
	var base uint64
	var memoryType hostarch.MemoryType
	found := false
	for candidate, candidateType := range mf.offsetTypes {
		if candidate <= offset && (!found || candidate > base) {
			base = candidate
			memoryType = candidateType
			found = true
		}
		if candidate > offset && candidate < end {
			return hostarch.MemoryTypeWriteBack, linuxerr.EINVAL
		}
	}
	if !found {
		return hostarch.MemoryTypeWriteBack, linuxerr.EINVAL
	}
	return memoryType, nil
}

// Close implements io.Closer.Close for MmapFileRefs.
func (mf *renderMemmapFile) Close() error {
	mf.mu.Lock()
	var errs []error
	for off, page := range mf.pages {
		if err := unix.Munmap(page); err != nil {
			errs = append(errs, fmt.Errorf("munmap %#x: %w", off, err))
		}
		delete(mf.pages, off)
	}
	fd := mf.fd
	fdValid := mf.fdValid
	mf.fd = -1
	mf.fdValid = false
	mf.mu.Unlock()
	if fdValid && fd >= 0 {
		if err := unix.Close(fd); err != nil {
			errs = append(errs, fmt.Errorf("close host DRM fd: %w", err))
		}
	}
	return errors.Join(errs...)
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (m *renderMappable) InvalidateUnsavable(context.Context) error {
	// The proxy does not implement host FD, mmap-offset, or GPU execution
	// state restoration. Do not permit checkpointing a live GPU mapping.
	return linuxerr.EBUSY
}

// renderMappedFile supplies per-mapping cache attributes while sharing the
// host file's reference-counted mapping lifecycle.
//
// +stateify savable
type renderMappedFile struct {
	memmap.NoBufferedIOFallback
	file *renderMemmapFile
	memoryType hostarch.MemoryType
}

// IncRef implements memmap.File.IncRef.
func (mf *renderMappedFile) IncRef(fr memmap.FileRange, memCgID uint32) {
	mf.file.IncRef(fr, memCgID)
}

// DecRef implements memmap.File.DecRef.
func (mf *renderMappedFile) DecRef(fr memmap.FileRange) {
	mf.file.DecRef(fr)
}

// MemoryType implements memmap.File.MemoryType.
func (mf *renderMappedFile) MemoryType() hostarch.MemoryType {
	return mf.memoryType
}

// DataFD implements memmap.File.DataFD.
func (mf *renderMappedFile) DataFD(fr memmap.FileRange) (int, error) {
	return mf.file.DataFD(fr)
}

// FD implements memmap.File.FD.
func (mf *renderMappedFile) FD() int {
	return mf.file.FD()
}
