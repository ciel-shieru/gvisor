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

package specutils

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
)

const (
	// AnnotationI915Proxy enables the Intel i915 render-node proxy.
	AnnotationI915Proxy = "dev.gvisor.internal.i915proxy"
)

// I915ProxyEnabled reports whether the explicitly opt-in i915 proxy is enabled
// for a container.
func I915ProxyEnabled(spec *specs.Spec, conf *config.Config) bool {
	return conf.I915Proxy || AnnotationToBool(spec, AnnotationI915Proxy)
}
