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
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *renderFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if opts.Offset > math.MaxInt64 || opts.Length > math.MaxInt64-opts.Offset {
		return linuxerr.EOVERFLOW
	}
	if opts.Length > uint64(maxInternalMapPages)*uint64(hostarch.PageSize) {
		return linuxerr.E2BIG
	}
	base, info, err := fd.memmapFile.lookupOffset(opts.Offset, opts.Length)
	if err != nil {
		return err
	}
	// Keep the validated offset metadata with this mapping. The GEM handle may
	// be closed before the mapping is removed.
	return vfs.GenericProxyDeviceConfigureMMap(&fd.vfsfd, renderMappable{
		file: &fd.memmapFile,
		base: base,
		length: info.length,
		memoryType: info.memoryType,
	}, opts)
}

// renderMappable represents one application mapping of an i915 render node.
//
// +stateify savable
type renderMappable struct {
	memmap.MappableNoTrackMappings
	file *renderMemmapFile
	base uint64
	length uint64
	memoryType hostarch.MemoryType
}

// Translate implements memmap.Mappable.Translate.
func (m renderMappable) Translate(_ context.Context, _, optional memmap.MappableRange, _ hostarch.AccessType) ([]memmap.Translation, error) {
	end := optional.Start + optional.Length()
	if optional.Start < m.base || optional.Start > math.MaxInt64 || end > m.base+m.length {
		return nil, linuxerr.EINVAL
	}
	return []memmap.Translation{{
		Source: optional,
		File: &renderMappedFile{
			file: m.file,
			base: m.base,
			length: m.length,
			memoryType: m.memoryType,
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

	// mu protects fd, fdValid, pages, and offsetTypes.
	mu sync.Mutex `state:"nosave"`
	// +checklocks:mu
	fd int32 `state:"nosave"`
	// +checklocks:mu
	fdValid bool `state:"nosave"`
	// +checklocks:mu
	pages map[uint64][]byte `state:"nosave"`
	// +checklocks:mu
	offsetTypes map[uint64]mmapOffsetInfo `state:"nosave"`
}

// SetFD implements fsutil.MmapFile.SetFD.
func (mf *renderMemmapFile) SetFD(fd int) {
	mf.mu.Lock()
	defer mf.mu.Unlock()
	mf.fd = int32(fd)
	mf.fdValid = true
}

// IncRef implements memmap.File.IncRef.
func (mf *renderMemmapFile) IncRef(fr memmap.FileRange, memCgID uint32) {
	mf.MmapFileRefs.IncRef(fr, memCgID)
}

// DecRef implements memmap.File.DecRef.
func (mf *renderMemmapFile) DecRef(fr memmap.FileRange) {
	// Internal mappings remain cached until Close. This avoids unmapping a page
	// while another userspace mapping or Sentry operation may still use it.
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

type mmapOffsetInfo struct {
	memoryType hostarch.MemoryType
	length uint64
}

// recordOffset records the cache type and object size associated with a
// host-generated mmap offset.
func (mf *renderMemmapFile) recordOffset(offset uint64, memoryType hostarch.MemoryType, length uint64) error {
	if offset > math.MaxInt64 {
		return linuxerr.EOVERFLOW
	}
	if offset%uint64(hostarch.PageSize) != 0 || length == 0 || length > math.MaxInt64-offset {
		return linuxerr.EINVAL
	}
	mf.mu.Lock()
	defer mf.mu.Unlock()
	if mf.offsetTypes == nil {
		mf.offsetTypes = make(map[uint64]mmapOffsetInfo)
	}
	info := mmapOffsetInfo{memoryType: memoryType, length: length}
	if existing, ok := mf.offsetTypes[offset]; ok && existing != info {
		return fmt.Errorf("i915proxy: host reused mmap offset %#x with different object metadata", offset)
	}
	mf.offsetTypes[offset] = info
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
	var info mmapOffsetInfo
	found := false
	for candidate, candidateInfo := range mf.offsetTypes {
		if candidate <= offset && (!found || candidate > base) {
			base = candidate
			info = candidateInfo
			found = true
		}
		if candidate > offset && candidate < end {
			return hostarch.MemoryTypeWriteBack, linuxerr.EINVAL
		}
	}
	if !found || offset < base || end > base+info.length {
		return hostarch.MemoryTypeWriteBack, linuxerr.EINVAL
	}
	return info.memoryType, nil
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
func (m renderMappable) InvalidateUnsavable(context.Context) error {
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

// MapInternal implements memmap.File.MapInternal.
func (mf *renderMappedFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	if _, err := mf.file.memoryTypeForRange(fr.Start, fr.Length()); err != nil {
		return safemem.BlockSeq{}, err
	}
	return mf.file.MapInternal(fr, at)
}
