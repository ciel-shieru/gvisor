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

func TestSupportedIoctl(t *testing.T) {
	for _, cmd := range []uintptr{
		drmIoctlVersion,
		drmIoctlGetMagic,
		drmIoctlGetCap,
		drmIoctlSetClientCap,
	} {
		if !SupportedIoctl(cmd) {
			t.Errorf("SupportedIoctl(%#x) = false, want true", cmd)
		}
	}
	for _, cmd := range []uintptr{
		0,
		0xc0406469, // DRM_IOCTL_I915_GEM_EXECBUFFER2 on one common ABI.
		0xc0106440, // Unimplemented DRM ioctl.
	} {
		if SupportedIoctl(cmd) {
			t.Errorf("SupportedIoctl(%#x) = true, want false", cmd)
		}
	}
}
