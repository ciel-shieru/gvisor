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
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemExecbuffer2)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemExecbuffer2WR)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemWait)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemContextCreate)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemContextCreateExt)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemContextDestroy)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemSetCaching)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemGetCaching)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GetResetStats)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemContextGetParam)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemContextSetParam)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915Query)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemVMCreate)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemVMDestroy)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlI915GemCreateExt)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlPrimeHandleToFD)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(drmIoctlPrimeFDToHandle)},
		}),
		unix.SYS_MMAP: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.PROT_READ | unix.PROT_WRITE),
			seccomp.EqualTo(unix.MAP_SHARED),
			seccomp.NonNegativeFD{},
			seccomp.AnyValue{},
		},
	})
}
