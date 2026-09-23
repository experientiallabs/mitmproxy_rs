#!/usr/bin/env bash
set -euo pipefail

# No system-extension loading, installation, trust changes, or provider traffic.
project_root="$(cd "$(dirname "$0")/../.." && pwd)"
build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT
swiftc -module-cache-path "$build_dir/modules" \
  "$project_root/mitmproxy-macos/redirector/network-extension/CaptureAdmission.swift" \
  "$project_root/mitmproxy-macos/redirector/network-extension/CaptureLease.swift" \
  "$project_root/mitmproxy-macos/redirector/network-extension/InterceptConf.swift" \
  "$project_root/mitmproxy-macos/redirector/tests/CaptureSafetyFixtures.swift" \
  "$project_root/mitmproxy-macos/redirector/tests/CaptureSafetyTests.swift" \
  -o "$build_dir/capture-policy-tests"
"$build_dir/capture-policy-tests"
swiftc -module-cache-path "$build_dir/modules" \
  "$project_root/mitmproxy-macos/redirector/macos-redirector/CaptureSupervisorPolicy.swift" \
  "$project_root/mitmproxy-macos/redirector/tests/CaptureSupervisorTests.swift" \
  -o "$build_dir/capture-supervisor-tests"
"$build_dir/capture-supervisor-tests"
