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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Filters returns the host syscall rules needed by the implemented i915 proxy
// operations. It intentionally does not permit a range of DRM ioctl values.
func Filters() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_IOCTL: seccomp.Or([]seccomp.SyscallRule{
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlVersion)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlGetCap)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlSetClientCap)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlGetMagic)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlGemClose)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GetParam)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemCreate)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemBusy)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemSetDomain)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemSetTiling)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemGetTiling)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemMmapGTT)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemMmapOffset)},
		}),
		unix.SYS_MMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.MAP_SHARED | unix.MAP_FIXED_NOREPLACE),
		},
		unix.SYS_MREMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
			seccomp.AnyValue{},
			seccomp.EqualTo(linux.MREMAP_MAYMOVE | linux.MREMAP_FIXED),
			seccomp.AnyValue{},
			seccomp.EqualTo(0),
		},
	})
}
