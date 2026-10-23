# Intel i915 GPU Driver Proxy

Status: Experimental partial implementation. Not production-ready.

The branch contains an initial Sentry render-node proxy and runtime opt-in, but
it does not yet provide complete graphics or Quick Sync Video compatibility.
PRs and release notes must not describe i915, VA-API, oneVPL, Jellyfin, Plex, or
Emby hardware acceleration as supported until the remaining implementation,
build, security, and real-hardware validation work below is complete.

## Synopsis

Allow applications in gVisor sandboxes to use Intel integrated GPUs backed by
the Linux `i915` kernel-mode driver for 3D rendering and hardware-accelerated
video decode, encode, and processing. The target includes Intel Quick Sync
Video workloads such as VA-API and oneVPL applications, including media servers
that use FFmpeg for transcoding.

The implementation should follow the security model of
[`nvproxy`](https://github.com/google/gvisor/tree/master/pkg/sentry/devices/nvproxy):
implement virtual device files in the Sentry and forward only explicitly
supported operations to the host driver. It must not expose an unrestricted
host character device or pass every guest `ioctl(2)` through to Linux.

This proposal is scoped to render clients using the Intel `i915` driver. The
host driver binding, not a CPU marketing-generation check, is the source of
truth. A machine with an Intel GPU bound to `xe` is outside the initial scope
and must not be silently treated as `i915`.

## Goals

- Support 3D rendering through the Linux DRM render-node interface, including
  common Mesa OpenGL and Vulkan workloads, subject to the host driver and
  hardware capabilities.
- Support Intel Quick Sync media workloads through the same render-node
  interface. Cover VA-API and oneVPL decode, encode, and video-processing
  operations, including every codec profile and entry point advertised by each
  qualified hardware/driver combination.
- Preserve gVisor's host-kernel attack-surface controls by registering virtual
  devices, validating ioctl arguments, and allowing only the host ioctls that
  the proxy implements.
- Keep driver and hardware support explicit and testable. Unsupported devices,
  operations, and ioctl variants must fail closed rather than fall through to
  generic character-device passthrough.
- Keep the application-facing userspace ABI compatible with normal container
  images. The application should use the libraries installed in the image and
  should not need gVisor-specific changes.

## Non-goals

- Implementing an Intel GPU kernel driver in Go or emulating GPU execution.
- Providing additional hardware-level isolation, GPU scheduling, or memory
  safety beyond the host kernel driver, firmware, and hardware.
- Exposing display modesetting, DRM master operations, physical display
  management, or privileged primary-node interfaces in the initial version.
- Supporting Intel GPUs bound to the `xe` driver. That should be a separate
  driver-proxy effort with its own UAPI coverage and test matrix.
- Claiming that every codec is available on every Intel GPU. Codec support
  depends on the GPU generation, firmware, host kernel driver, media-driver
  build, and advertised VA-API/oneVPL profile support.

## Background

gVisor implements a Linux-like kernel in the Sentry. The existing NVIDIA
implementation registers virtual character devices and forwards a deliberately
limited set of requests to the host NVIDIA kernel driver. It copies ioctl
structures into Sentry memory and translates pointers and file descriptors
where required. Host seccomp rules constrain which ioctl commands the Sentry
may issue. The implementation and security trade-offs are documented in the
[gVisor GPU guide](https://gvisor.dev/docs/user_guide/gpu/) and the
[NVIDIA proxy design](nvidia_driver_proxy.md).

Intel's Linux graphics stack uses the Direct Rendering Manager (DRM) UAPI.
Unprivileged render clients use `/dev/dri/renderD<num>`, which omits display
modesetting and DRM-master operations. The i915-specific UAPI includes GEM
buffer management, GPU submission, contexts, synchronization, and PRIME
buffer sharing. The user-mode components normally remain in the container:
for example, Mesa for OpenGL/Vulkan, libdrm, libva, Intel's
[VA-API media driver](https://github.com/intel/media-driver), and the
[Intel oneVPL GPU runtime](https://github.com/intel/oneVPL-intel-gpu).

Quick Sync is not a separate character-device ABI that can be enabled merely
by exposing a device node. VA-API and oneVPL applications submit work through
the DRM/i915 device interface and rely on user-mode libraries, firmware, and
the features of the specific GPU. Therefore, an i915 proxy that supports only
basic GEM allocation or simple rendering is not sufficient for the stated
media-server use case.

## Proposed architecture

### 1. Add a dedicated `i915proxy` package

Add `pkg/sentry/devices/i915proxy`, with its own BUILD targets, tests, and
documentation. Use `nvproxy` as an architectural reference, but do not copy
its NVIDIA-specific object model or ABI assumptions.

The package should own:

- Discovery and validation of the host render node selected for a sandbox.
- Registration of the corresponding virtual DRM character device in the
  Sentry VFS.
- The set of DRM-common and i915-specific ioctl handlers that are supported.
- Translation and validation of ioctl payloads, nested arrays, pointers, and
  file descriptors.
- Buffer-object mapping and synchronization semantics required by the supported
  render-node ABI.
- Host seccomp rules for the exact ioctl commands used by the proxy.
- Focused unit tests for pointer translation, length and overflow validation,
  unsupported commands, and file-descriptor translation.

Do not add cgo or a userspace library dependency to `pkg/...` or `runsc`.
The proxy should be implemented in Go and should use the existing gVisor
syscall, memory, VFS, and seccomp abstractions.

### 2. Expose only explicitly allocated render nodes

The initial interface should expose only `/dev/dri/renderD<num>` nodes selected
by the OCI device allocation or a documented device-injection path. It should
not expose every host DRM device automatically. A container must not be able
to open another host GPU merely because it knows that GPU's device number.

Use an explicit `runsc` opt-in, such as `--i915proxy`, and reject startup if
the selected host device is not an i915 render node or if the host device cannot
be opened with the required permissions. The exact flag behavior should follow
existing runtime configuration conventions and should be validated before the
feature is enabled by default.

Do not expose `/dev/dri/card<num>`, control nodes, DRM-master operations,
modesetting, or debug/performance interfaces in the initial implementation.
Do not rely on `--character-device-policy=passthrough` as the implementation:
that policy would bypass the required ioctl mediation.

The proxy must scope device access to the node actually allocated to the
container. The host device file descriptor must be opened and retained by the
Sentry using the established gVisor device-proxy lifecycle. Device removal,
open failure, and restore behavior must be handled explicitly.

### 3. Maintain a fail-closed ioctl allowlist

Start from the documented Linux
[DRM UAPI](https://docs.kernel.org/gpu/drm-uapi.html) and
[i915 UAPI](https://docs.kernel.org/gpu/i915.html), then validate the actual
requests emitted by the target libraries and workloads.

Organize handlers by ABI area so reviewers can audit the attack surface:

- DRM identification, capability discovery, and supported render-node queries.
- GEM buffer creation, lookup, closing, mapping, and required mmap offsets.
- i915 context and engine queries, context creation, and GPU submission.
- PRIME dma-buf import/export and the required file-descriptor translations.
- Synchronization primitives and fences required by Mesa, VA-API, and oneVPL.
- Any additional i915 operations demonstrated to be necessary by the
  compatibility test suite.

This list is a coverage plan, not permission to forward these operations
without review. Each ioctl needs a handler that defines the command, ABI
structure, direction of data flow, supported fields, size limits, and whether
nested pointers or file descriptors require translation. Unknown ioctls and
unimplemented variants must not be forwarded.

For every pointer-bearing request, copy data between application and Sentry
memory with the existing memory-manager interfaces. Validate array counts,
multiplications, pointer ranges, offsets, and integer conversions before
allocating or accessing memory. Translate any guest file descriptors before
calling the host, and translate returned descriptors back into the guest
descriptor table using established gVisor mechanisms. Do not pass guest
addresses or guest-local descriptor numbers directly to the host kernel.

DRM UAPI compatibility does not remove the need to validate ioctl sizes,
feature availability, and driver-specific behavior. Prefer explicit capability
discovery and documented UAPI behavior over guessing from CPU generation or
accepting an arbitrary kernel version. Record any kernel-version constraints
that testing shows are necessary.

### 4. Integrate with Sentry seccomp

The host seccomp filter must permit only the ioctl command numbers that have
reviewed handlers. Keep this allowlist local to the i915 proxy and integrate it
with the existing Sentry filter construction; do not broadly permit DRM ioctl
ranges or relax the global ioctl filter.

The proxy's dispatch checks and the host seccomp rules are complementary:
dispatch prevents the guest from reaching unsupported commands through the
proxy, while seccomp constrains a compromised Sentry from issuing unapproved
host ioctls. Add tests that assert both the proxy's accepted command set and
the generated host filter's allowlist.

GPU-driver vulnerabilities may still be reachable through approved commands.
Document this residual risk and require timely host kernel and firmware updates.
The proxy does not add GPU hardware isolation or guarantee safety from malicious
GPU command buffers.

### 5. Support graphics and media through the same render-node ABI

The container should use its own userspace libraries, with host access limited
to the proxied render-node UAPI. Relevant integration stacks include:

- OpenGL and Vulkan through compatible Mesa drivers.
- VA-API through libva and a compatible Intel media driver, commonly `iHD`.
- Intel oneVPL through a compatible oneVPL GPU runtime.
- FFmpeg builds that use VA-API or oneVPL hardware paths, including the
  FFmpeg process used by Jellyfin, Plex, or Emby.

The proxy must support the memory management, command submission, and
synchronization operations needed by the complete paths above. Supporting
`vainfo` or successful device discovery alone is not sufficient evidence of
transcoding support.

Codec coverage must be defined by the capability matrix of qualified devices,
not by a universal list that assumes feature parity across Intel generations.
For each supported hardware and host-stack combination, enumerate the profiles
and entry points reported by VA-API and oneVPL, then test each advertised
decode, encode, and video-processing path. This includes AVC/H.264, HEVC/H.265,
MPEG-2, VP8/VP9, VC-1, JPEG, and AV1 wherever the hardware/runtime advertises
them. Encoding and decoding support differ by codec, generation, and media
driver build. The implementation must not claim support for a profile just
because the host library recognizes its name.

A separate `video-only` capability flag may be considered only if its ioctl
allowlist provides meaningful isolation. Graphics and media workloads share
GEM, submission, memory-mapping, and synchronization interfaces; the proxy must
not claim that a capability label enforces workload-level isolation when the
same commands can submit general GPU work.

### 6. Handle memory mappings and platform differences explicitly

GPU workloads depend on mapped buffer objects and shared memory. Implement and
test the full mapping lifecycle, including creation of mmap offsets, mappings
with the required protection and caching attributes, unmapping, and cleanup
when a file description is closed. Apply existing gVisor mapping abstractions
where possible; do not introduce raw host mappings that outlive their owning
device file.

PRIME dma-buf sharing, implicit or explicit synchronization, and fence handling
need specific tests. These interfaces have cross-file lifetimes and can affect
isolation between containers. Shared buffers must not become accessible to a
container unless the corresponding file descriptor or supported import path was
explicitly provided to it.

Qualify systrap, ptrace, and KVM independently. If the required mapping or
synchronization semantics cannot be implemented safely on a platform, fail
closed on that platform rather than silently exposing reduced protection.
Do not advertise KVM support until the real-hardware integration tests pass.

## Current implementation status

The current branch implements a restricted render-node proxy with a runtime
`--i915proxy` opt-in. It validates the allocated DRM major/minor and confirms
that the host render node reports the `i915` driver. The host ioctl policy
allows an explicit command set, and implemented handlers translate
Sentry/application pointers for DRM version queries, i915 getparam and query,
execbuffer2, and bounded GEM pread/pwrite transfers. The subset also includes
GEM madvise, aperture, context/VM operations, and restricted DRM PRIME
handle-to-FD / FD-to-handle translation using opaque sandbox dma-buf wrappers.

GEM handles are tracked per open file description, and render-node mmap offsets
are checked against tracked GEM objects and object sizes. The implementation
hides syncobj capabilities while syncobj/fence translation remains unavailable.
It also rejects checkpoint/restore while an i915 render-node or exported
dma-buf descriptor is open, and marks mappings as unsavable. This avoids
restoring stale host device FDs or GPU execution state.

The current implementation is incomplete. It does not yet provide:

- Complete DRM PRIME / dma-buf support. Handle-to-FD and FD-to-handle translation
  is restricted to dma-buf FDs created by this proxy for the same render node;
  other dma-buf providers and general dma-buf read/write/mmap behavior are not
  implemented.
- DRM syncobj support, explicit sync-file fences, or execbuffer fence arrays.
- Full i915 ioctl coverage required by all Mesa OpenGL/Vulkan and media-driver
  versions, including all pointer-bearing structures and extensions.
- Full context, VM, GEM, reset, and memory-management ABI tracking.
- A confirmed correct host seccomp policy on every supported Sentry platform.
- Native-versus-gVisor ABI/syscall tests, fuzz coverage, Bazel builds, lint, or
  benchmarks for the new package.
- Real-hardware verification of OpenGL/Vulkan rendering, VA-API or oneVPL
  decode/encode, video processing, codec profiles, FFmpeg transcoding, or
  Jellyfin/Plex/Emby workflows.

This status is intentional and fail-closed. Unsupported ioctl variants return
an error instead of falling back to unrestricted character-device passthrough.
Do not enable the proxy for untrusted production workloads until all required
handlers have been reviewed and the validation matrix passes.

## Validation plan

The implementation should include tests at several layers.

### Build and static checks

- Build the new package and its direct dependents with Bazel.
- Run the package tests, relevant sentry tests, and the repository's lint and
  C/C++ lint targets.
- Verify the generated seccomp filter against the exact ioctl allowlist.
- Add no syscall behavior tests as Go unit tests; use the existing syscall-test
  approach for application-observable Linux ABI behavior.

### Device and ABI tests

- Compare render-node identity and DRM/i915 capability discovery with native
  Linux for the same allocated host device.
- Exercise supported and unsupported ioctl numbers, sizes, malformed payloads,
  nested pointers, oversized counts, invalid offsets, and invalid descriptors.
- Test GEM buffer lifecycle, context/engine creation, GPU submission, mmap,
  dma-buf import/export, and synchronization.
- Ensure attempts to access an unallocated render node or primary DRM node fail.

### Real-hardware graphics and media tests

Run the same workloads natively and in gVisor on every qualified i915 hardware
generation and supported host-driver window:

- `vulkaninfo` and a small Vulkan rendering workload using the Intel GPU, not
  a software renderer.
- A Mesa OpenGL rendering test that checks the selected renderer.
- `vainfo` to record the VA-API profiles and entry points reported by the host.
- Decode and encode test vectors for every advertised VA-API/oneVPL profile and
  entry point, including pixel-format conversion, scaling, and other advertised
  video-processing operations.
- FFmpeg transcoding with hardware decode, hardware encode, and both combined;
  check output correctness as well as whether the hardware path was selected.
- A Jellyfin integration test using its FFmpeg build, demonstrating a
  representative hardware-accelerated transcode without exposing the primary
  DRM node.

The suite must record the i915 kernel driver, kernel version, GPU PCI ID, media
driver build type/version, libva version, oneVPL runtime version, and the
profiles tested. A profile absent from a device's native capability report is
not a proxy failure; every profile that is reported must be accounted for.

### Performance tests

Measure native Linux versus gVisor GPU workloads before claiming negligible
overhead. Include GPU submission and synchronization microbenchmarks, as well
as end-to-end 3D rendering and video transcoding. For CPU-side proxy overhead,
use repeated measurements and report raw `benchstat` output where applicable.
Do not use GPU model names alone as evidence of codec support or performance.

## Rollout

Implement this as incremental work, but keep the user-facing feature incomplete
until the end-to-end requirements above are met:

1. Add the package structure, explicit render-node allocation, lifecycle, and
   fail-closed device validation.
2. Implement and test common DRM and i915 ioctl handlers, including safe pointer
   and file-descriptor translation, mmap, and synchronization.
3. Establish working Vulkan/OpenGL and VA-API/oneVPL paths on real hardware.
4. Expand the codec matrix until every profile/entry point advertised by each
   qualified hardware/driver combination is covered; add FFmpeg integration.
5. Integrate and document supported host versions and runtime configuration.
6. Only then update the GPU user guide to list Intel support as supported.

## References

- [gVisor GPU support and security model](https://gvisor.dev/docs/user_guide/gpu/)
- [NVIDIA proxy implementation](https://github.com/google/gvisor/tree/master/pkg/sentry/devices/nvproxy)
- [NVIDIA driver proxy design](nvidia_driver_proxy.md)
- [Linux DRM UAPI](https://docs.kernel.org/gpu/drm-uapi.html)
- [Linux i915 driver documentation](https://docs.kernel.org/gpu/i915.html)
- [Intel media-driver for VA-API](https://github.com/intel/media-driver)
- [Intel oneVPL GPU runtime](https://github.com/intel/oneVPL-intel-gpu)
