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
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// hostIoctl invokes one approved host ioctl with a Sentry-owned parameter
// buffer. Callers must not pass application addresses to this function.
func hostIoctl(fd int32, cmd uintptr, params []byte) (uintptr, error) {
	var arg uintptr
	if len(params) != 0 {
		arg = uintptr(unsafe.Pointer(&params[0]))
	}
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd), cmd, arg)
	runtime.KeepAlive(params)
	if errno != 0 {
		return n, errno
	}
	return n, nil
}

// hostIoctlI915Execbuffer2 translates every pointer in the base execbuffer2
// structure, the exec-object array, and its relocation arrays to Sentry-owned
// buffers. Extension chains are rejected by the caller.
func hostIoctlI915Execbuffer2(fd int32, cmd uintptr, params, objects []byte, relocations [][]byte, fences []byte) (uintptr, error) {
	if len(params) != 64 || len(objects) == 0 || len(objects)%i915ExecObject2Size != 0 || len(relocations) != len(objects)/i915ExecObject2Size {
		return 0, unix.EINVAL
	}
	var originalBuffersPtr [8]byte
	var originalFencesPtr [8]byte
	copy(originalBuffersPtr[:], params[0:8])
	copy(originalFencesPtr[:], params[32:40])
	originalRelocPtrs := make([][8]byte, len(relocations))
	for i, relocs := range relocations {
		off := i*i915ExecObject2Size + 8
		copy(originalRelocPtrs[i][:], objects[off:off+8])
		if len(relocs) == 0 {
			binary.LittleEndian.PutUint64(objects[off:off+8], 0)
			continue
		}
		binary.LittleEndian.PutUint64(objects[off:off+8], uint64(uintptr(unsafe.Pointer(&relocs[0]))))
	}
	binary.LittleEndian.PutUint64(params[0:8], uint64(uintptr(unsafe.Pointer(&objects[0]))))
	if len(fences) == 0 {
		binary.LittleEndian.PutUint64(params[32:40], 0)
	} else {
		binary.LittleEndian.PutUint64(params[32:40], uint64(uintptr(unsafe.Pointer(&fences[0]))))
	}
	defer func() {
		copy(params[0:8], originalBuffersPtr[:])
		copy(params[32:40], originalFencesPtr[:])
		for i := range originalRelocPtrs {
			off := i*i915ExecObject2Size + 8
			copy(objects[off:off+8], originalRelocPtrs[i][:])
		}
	}()

	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&params[0])))
	runtime.KeepAlive(params)
	runtime.KeepAlive(objects)
	runtime.KeepAlive(relocations)
	runtime.KeepAlive(fences)
	if errno != 0 {
		return n, errno
	}
	return n, nil
}

// hostIoctlI915Query translates the i915 query list and each query's payload
// pointer to Sentry-owned memory. Guest pointers are restored before returning.
func hostIoctlI915Query(fd int32, cmd uintptr, params, items []byte, buffers [][]byte) (uintptr, error) {
	if len(params) != 16 || len(items) == 0 || len(items)%i915QueryItemSize != 0 || len(buffers) != len(items)/i915QueryItemSize {
		return 0, unix.EINVAL
	}
	var originalItemsPtr [8]byte
	copy(originalItemsPtr[:], params[8:16])
	originalDataPtrs := make([][8]byte, len(buffers))
	for i, buf := range buffers {
		off := i*i915QueryItemSize + 16
		copy(originalDataPtrs[i][:], items[off:off+8])
		if len(buf) == 0 {
			binary.LittleEndian.PutUint64(items[off:off+8], 0)
			continue
		}
		binary.LittleEndian.PutUint64(items[off:off+8], uint64(uintptr(unsafe.Pointer(&buf[0]))))
	}
	binary.LittleEndian.PutUint64(params[8:16], uint64(uintptr(unsafe.Pointer(&items[0]))))
	defer func() {
		copy(params[8:16], originalItemsPtr[:])
		for i := range originalDataPtrs {
			off := i*i915QueryItemSize + 16
			copy(items[off:off+8], originalDataPtrs[i][:])
		}
	}()
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&params[0])))
	runtime.KeepAlive(params)
	runtime.KeepAlive(items)
	runtime.KeepAlive(buffers)
	if errno != 0 {
		return n, errno
	}
	return n, nil
}

// hostIoctlI915GemTransfer translates the data_ptr field in GEM_PREAD/PWRITE
// to a Sentry-owned buffer and restores the original pointer afterward.
func hostIoctlI915GemTransfer(fd int32, cmd uintptr, params, data []byte) (uintptr, error) {
	if len(params) != 32 {
		return 0, unix.EINVAL
	}
	var original [8]byte
	copy(original[:], params[24:32])
	if len(data) == 0 {
		binary.LittleEndian.PutUint64(params[24:32], 0)
	} else {
		binary.LittleEndian.PutUint64(params[24:32], uint64(uintptr(unsafe.Pointer(&data[0]))))
	}
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&params[0])))
	copy(params[24:32], original[:])
	runtime.KeepAlive(params)
	runtime.KeepAlive(data)
	if errno != 0 {
		return n, errno
	}
	return n, nil
}

// hostIoctlI915GemCreateExt translates the pointer graph accepted by the
// restricted GEM_CREATE_EXT_MEMORY_REGIONS path. The caller has validated that
// the extension is a single system-memory region with no extension successor.
func hostIoctlI915GemCreateExt(fd int32, cmd uintptr, params, extension, regions []byte) (uintptr, error) {
	if len(params) != i915GemCreateExtSize || len(extension) != i915GemCreateExtMemoryRegionsSize || len(regions) != i915GemMemoryClassInstanceSize {
		return 0, unix.EINVAL
	}
	var originalExtensionPtr [8]byte
	var originalRegionsPtr [8]byte
	copy(originalExtensionPtr[:], params[16:24])
	copy(originalRegionsPtr[:], extension[24:32])
	binary.LittleEndian.PutUint64(params[16:24], uint64(uintptr(unsafe.Pointer(&extension[0]))))
	binary.LittleEndian.PutUint64(extension[24:32], uint64(uintptr(unsafe.Pointer(&regions[0]))))
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&params[0])))
	copy(params[16:24], originalExtensionPtr[:])
	copy(extension[24:32], originalRegionsPtr[:])
	runtime.KeepAlive(params)
	runtime.KeepAlive(extension)
	runtime.KeepAlive(regions)
	if errno != 0 {
		return n, errno
	}
	return n, nil
}

// hostIoctlI915GetParam translates drm_i915_getparam.value to a Sentry-owned
// integer buffer. The pointer in the ioctl structure never refers to application
// memory while the host kernel is handling the request.
func hostIoctlI915GetParam(fd int32, cmd uintptr, params, value []byte) (uintptr, error) {
	if len(params) != 16 || len(value) != 4 {
		return 0, unix.EINVAL
	}
	var original [8]byte
	copy(original[:], params[8:16])
	binary.LittleEndian.PutUint64(params[8:16], uint64(uintptr(unsafe.Pointer(&value[0]))))
	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&params[0])))
	copy(params[8:16], original[:])
	runtime.KeepAlive(params)
	runtime.KeepAlive(value)
	if errno != 0 {
		return n, errno
	}
	return n, nil
}

// hostIoctlVersion translates the three pointer fields in struct drm_version
// to Sentry-owned buffers for the duration of the host ioctl. It restores the
// guest pointer values before returning so the caller can safely copy the
// structure back to application memory.
func hostIoctlVersion(fd int32, cmd uintptr, params, name, date, desc []byte, pointerOffsets []int) (uintptr, error) {
	if len(params) != 64 || len(pointerOffsets) != 3 {
		return 0, unix.EINVAL
	}
	buffers := [3][]byte{name, date, desc}
	var originalPointers [3][8]byte
	for i, off := range pointerOffsets {
		if off < 0 || off+8 > len(params) {
			return 0, unix.EINVAL
		}
		copy(originalPointers[i][:], params[off:off+8])
		if len(buffers[i]) == 0 {
			binary.LittleEndian.PutUint64(params[off:off+8], 0)
			continue
		}
		ptr := uintptr(unsafe.Pointer(&buffers[i][0]))
		binary.LittleEndian.PutUint64(params[off:off+8], uint64(ptr))
	}
	defer func() {
		for i, off := range pointerOffsets {
			copy(params[off:off+8], originalPointers[i][:])
		}
	}()

	n, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&params[0])))
	runtime.KeepAlive(params)
	runtime.KeepAlive(buffers)
	if errno != 0 {
		return n, errno
	}
	return n, nil
}
