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

import "testing"

func TestValidateDevice(t *testing.T) {
	for _, tc := range []struct {
		name string
		dev Device
		wantErr bool
	}{
		{
			name: "valid render node",
			dev: Device{Path: "/dev/dri/renderD128", Major: DRMDeviceMajor, Minor: 128},
		},
		{
			name: "wrong major",
			dev: Device{Path: "/dev/dri/renderD128", Major: 1, Minor: 128},
			wantErr: true,
		},
		{
			name: "primary node rejected",
			dev: Device{Path: "/dev/dri/card0", Major: DRMDeviceMajor, Minor: 0},
			wantErr: true,
		},
		{
			name: "control node rejected",
			dev: Device{Path: "/dev/dri/controlD64", Major: DRMDeviceMajor, Minor: 64},
			wantErr: true,
		},
		{
			name: "path traversal rejected",
			dev: Device{Path: "/dev/dri/../renderD128", Major: DRMDeviceMajor, Minor: 128},
			wantErr: true,
		},
		{
			name: "mismatched minor rejected",
			dev: Device{Path: "/dev/dri/renderD129", Major: DRMDeviceMajor, Minor: 128},
			wantErr: true,
		},
		{
			name: "non-numeric suffix rejected",
			dev: Device{Path: "/dev/dri/renderD128x", Major: DRMDeviceMajor, Minor: 128},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDevice(tc.dev)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateDevice(%+v) error = %v, wantErr %t", tc.dev, err, tc.wantErr)
			}
		})
	}
}

func TestI915GemCreateCommandNumber(t *testing.T) {
	if got := drmIoctlI915GemCreate; got != uintptr(0xc010645b) {
		t.Fatalf("DRM_IOCTL_I915_GEM_CREATE = %#x, want %#x", got, uintptr(0xc010645b))
	}
}

func TestIoctlABIEncodings(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "GEM_CREATE", got: drmIoctlI915GemCreate, want: 0xc010645b},
		{name: "GEM_MMAP_GTT", got: drmIoctlI915GemMmapGTT, want: 0xc0106464},
		{name: "GEM_MMAP_OFFSET", got: drmIoctlI915GemMmapOffset, want: 0xc0206464},
		{name: "GEM_EXECBUFFER2", got: drmIoctlI915GemExecbuffer2, want: 0x40406469},
		{name: "GEM_EXECBUFFER2_WR", got: drmIoctlI915GemExecbuffer2WR, want: 0xc0406469},
		{name: "QUERY", got: drmIoctlI915Query, want: 0xc0106479},
		{name: "PRIME_HANDLE_TO_FD", got: drmIoctlPrimeHandleToFD, want: 0xc00c642d},
		{name: "PRIME_FD_TO_HANDLE", got: drmIoctlPrimeFDToHandle, want: 0xc00c642e},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("ioctl encoding = %#x, want %#x", tc.got, tc.want)
			}
		})
	}
}

func TestSupportedIoctl(t *testing.T) {
	for _, cmd := range []uintptr{
		drmIoctlVersion,
		drmIoctlGetMagic,
		drmIoctlGetCap,
		drmIoctlSetClientCap,
		drmIoctlGemClose,
		drmIoctlI915GetParam,
		drmIoctlI915GemCreate,
		drmIoctlI915GemBusy,
		drmIoctlI915GemSetDomain,
		drmIoctlI915GemSetTiling,
		drmIoctlI915GemGetTiling,
		drmIoctlI915GemMmapGTT,
		drmIoctlI915GemMmapOffset,
		drmIoctlI915GemExecbuffer2,
		drmIoctlI915GemExecbuffer2WR,
		drmIoctlI915GemWait,
		drmIoctlI915GemContextCreate,
		drmIoctlI915GemContextCreateExt,
		drmIoctlI915GemContextDestroy,
		drmIoctlI915GemSetCaching,
		drmIoctlI915GemGetCaching,
		drmIoctlI915GetResetStats,
		drmIoctlI915GemContextGetParam,
		drmIoctlI915GemContextSetParam,
		drmIoctlI915Query,
		drmIoctlI915GemVMCreate,
		drmIoctlI915GemVMDestroy,
		drmIoctlI915GemCreateExt,
		drmIoctlPrimeHandleToFD,
		drmIoctlPrimeFDToHandle,
	} {
		if !SupportedIoctl(cmd) {
			t.Errorf("SupportedIoctl(%#x) = false, want true", cmd)
		}
	}
	for _, cmd := range []uintptr{
		0,
		0x40406468, // Unimplemented DRM ioctl of the same size.
		0xc0106440, // Unimplemented DRM ioctl.
	} {
		if SupportedIoctl(cmd) {
			t.Errorf("SupportedIoctl(%#x) = true, want false", cmd)
		}
	}
}
