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
