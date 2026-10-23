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
	"math"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

const maxInternalMapPages = 1 << 16

// MapInternal implements memmap.File.MapInternal.
func (mf *renderMemmapFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	if at.Execute {
		return safemem.BlockSeq{}, linuxerr.EACCES
	}
	if fr.Length() == 0 || fr.End > math.MaxInt64 {
		return safemem.BlockSeq{}, linuxerr.EINVAL
	}

	pageSize := uint64(hostarch.PageSize)
	start := fr.Start &^ (pageSize - 1)
	if fr.End > math.MaxInt64-pageSize {
		return safemem.BlockSeq{}, linuxerr.EOVERFLOW
	}
	end := (fr.End + pageSize - 1) &^ (pageSize - 1)
	pageCount := (end - start) / pageSize
	if pageCount > maxInternalMapPages {
		return safemem.BlockSeq{}, linuxerr.E2BIG
	}
	blocks := make([]safemem.Block, 0, int(pageCount))

	mf.mu.Lock()
	defer mf.mu.Unlock()
	if !mf.fdValid || mf.fd < 0 {
		return safemem.BlockSeq{}, linuxerr.EBADF
	}
	if mf.pages == nil {
		mf.pages = make(map[uint64][]byte)
	}
	var newPages uint64
	for off := start; off < end; off += pageSize {
		if _, ok := mf.pages[off]; !ok {
			newPages++
		}
	}
	if uint64(len(mf.pages))+newPages > maxInternalMapPages {
		return safemem.BlockSeq{}, linuxerr.E2BIG
	}
	prot := at.Prot()
	for off := start; off < end; off += pageSize {
		page, ok := mf.pages[off]
		if !ok {
			var err error
			page, err = unix.Mmap(int(mf.fd), int64(off), int(hostarch.PageSize), prot, unix.MAP_SHARED)
			if err != nil {
				return safemem.BlockSeq{}, err
			}
			mf.pages[off] = page
		}
		lo := uint64(0)
		if fr.Start > off {
			lo = fr.Start - off
		}
		hi := pageSize
		if fr.End < off+pageSize {
			hi = fr.End - off
		}
		blocks = append(blocks, safemem.BlockFromUnsafePointer(unsafe.Pointer(&page[int(lo)]), int(hi-lo)))
	}
	return safemem.BlockSeqOf(blocks...), nil
}

// MapInternal implements memmap.File.MapInternal for a cache-type-specific view.
func (mf *renderMappedFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	return mf.file.MapInternal(fr, at)
}
