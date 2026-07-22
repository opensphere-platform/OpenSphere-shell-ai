#!/usr/bin/env bash
set -euo pipefail

image="${1:?image reference is required}"
expected_version="${2:?expected module version is required}"
manifest=""

for attempt in {1..12}; do
  if manifest="$(crane manifest "$image" 2>/dev/null)"; then break; fi
  if [[ "$attempt" -eq 12 ]]; then
    echo "module label gate: image manifest was not readable: $image" >&2
    exit 1
  fi
  sleep 5
done

platforms=0
baseline_descriptor=""
baseline_signature=""
while IFS= read -r platform_digest; do
  config="$(crane config "${image%@*}@$platform_digest")"
  descriptor="$(jq -er '.config.Labels["io.opensphere.module.descriptor"]' <<<"$config")"
  signature="$(jq -er '.config.Labels["io.opensphere.module.descriptor.signature"]' <<<"$config")"
  key_id="$(jq -er '.config.Labels["io.opensphere.module.descriptor.key-id"]' <<<"$config")"
  version="$(jq -er '.config.Labels["org.opencontainers.image.version"]' <<<"$config")"
  source="$(jq -er '.config.Labels["org.opencontainers.image.source"]' <<<"$config")"
  revision="$(jq -er '.config.Labels["org.opencontainers.image.revision"]' <<<"$config")"
  jq -e --arg version "$expected_version" '.version == $version and .permissionProfile == "ai-domain-operator-v1"' <<<"$descriptor" >/dev/null
  test "$version" = "$expected_version"
  test "$key_id" = "opensphere-plugins-v1"
  test "$source" = "https://github.com/opensphere-platform/OpenSphere-shell-ai"
  test "${#revision}" = 40
  test -n "$signature"
  if [[ -z "$baseline_descriptor" ]]; then
    baseline_descriptor="$descriptor"
    baseline_signature="$signature"
  else
    test "$descriptor" = "$baseline_descriptor"
    test "$signature" = "$baseline_signature"
  fi
  platforms=$((platforms + 1))
done < <(jq -er '.manifests[] | select(.platform.os == "linux" and (.platform.architecture == "amd64" or .platform.architecture == "arm64")) | .digest' <<<"$manifest")

test "$platforms" = 2
