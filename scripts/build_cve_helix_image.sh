#!/usr/bin/env bash
# Build the pinned Helix server with the reviewed 3 GiB runtime profile.
set -euo pipefail

if [[ $# != 2 ]]; then
    echo "Usage: $0 CLEAN_UPSTREAM_CHECKOUT OUTPUT_IMAGE_TAR" >&2
    exit 2
fi

upstream_commit=1ffadba6124ede16e76b463bae463efc33bf3282
image_tag=homelab/helix-cve:1ffadba6124ed-mem2
repo_root=$(cd "$(dirname "$0")/.." && pwd)
patch_file="$repo_root/ansible/roles/cve_helix/files/server-memory-profile.patch"
source_dir=$(cd "$1" && pwd)
output_dir=$(cd "$(dirname "$2")" && pwd)
archive="$output_dir/$(basename "$2")"

for output in "$archive" "$archive.metadata.json" "$archive.receipt.json"; do
    if [[ -e "$output" ]]; then
        echo "Refusing to overwrite $output" >&2
        exit 1
    fi
done
if [[ $(git -C "$source_dir" rev-parse HEAD) != "$upstream_commit" ]]; then
    echo "Helix checkout must be at $upstream_commit" >&2
    exit 1
fi
if [[ -n $(git -C "$source_dir" status --porcelain --untracked-files=all) ]]; then
    echo "Helix checkout must be clean, including untracked files" >&2
    exit 1
fi

build_dir=$(mktemp -d "${TMPDIR:-/tmp}/helix-cve-build.XXXXXXXX")
trap 'rm -rf "$build_dir"' EXIT
git -C "$source_dir" archive "$upstream_commit" | tar -x -C "$build_dir"
# git apply rejects altered context instead of accepting patch fuzz.
git -C "$build_dir" apply --check "$patch_file"
git -C "$build_dir" apply "$patch_file"
patch_sha=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$patch_file")

# Upstream Dockerfile uses Cargo.lock and cargo build --locked.
docker buildx build --platform linux/amd64 --load \
    --tag "$image_tag" \
    --label "org.opencontainers.image.revision=$upstream_commit" \
    --label "io.homelab.helix.memory-profile=homelab-3g-v2" \
    --label "io.homelab.helix.patch-sha256=$patch_sha" \
    --metadata-file "$archive.metadata.json" "$build_dir"
image_id=$(docker image inspect --format '{{.Id}}' "$image_tag")
docker image save --output "$archive" "$image_tag"
if [[ $(docker image inspect --format '{{.Id}}' "$image_tag") != "$image_id" ]]; then
    echo "Image tag changed while saving the archive" >&2
    exit 1
fi
python3 - "$archive" "$upstream_commit" "$patch_sha" "$image_tag" "$image_id" <<'PY'
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

archive, commit, patch, tag, engine_id = sys.argv[1:]
with open(archive, 'rb') as stream:
    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
with tarfile.open(archive) as saved:
    def read_blob(descriptor):
        algorithm, value = descriptor['digest'].split(':', 1)
        if algorithm != 'sha256':
            raise ValueError('unsupported image digest algorithm')
        data = saved.extractfile('blobs/sha256/' + value).read()
        if hashlib.sha256(data).hexdigest() != value:
            raise ValueError('image blob hash mismatch')
        if len(data) != descriptor['size']:
            raise ValueError('image blob size mismatch')
        return data

    images = json.load(saved.extractfile('manifest.json'))
    if len(images) != 1 or images[0]['RepoTags'] != [tag]:
        raise ValueError('archive must contain exactly the requested image tag')
    image = images[0]
    config_bytes = saved.extractfile(image['Config']).read()
    config_digest = 'sha256:' + hashlib.sha256(config_bytes).hexdigest()
    config = json.loads(config_bytes)
    if (config['os'], config['architecture']) != ('linux', 'amd64'):
        raise ValueError('archive platform does not match linux/amd64')
    labels = config['config']['Labels']
    if (labels['org.opencontainers.image.revision'] != commit or
            labels['io.homelab.helix.patch-sha256'] != patch or
            labels['io.homelab.helix.memory-profile'] != 'homelab-3g-v2'):
        raise ValueError('archive build labels do not match the receipt inputs')

    index_digest = None
    manifest_digest = None
    manifest = None
    # Containerd archives retain OCI descriptors; classic Docker archives may
    # contain only manifest.json plus the platform config and layer tar files.
    if 'index.json' in saved.getnames():
        roots = json.load(saved.extractfile('index.json'))['manifests']
        if len(roots) != 1:
            raise ValueError('archive must contain exactly one OCI image root')
        root = roots[0]
        root_body = json.loads(read_blob(root))
        if 'manifests' in root_body:
            index_digest = root['digest']
            candidates = [item for item in root_body['manifests']
                          if item.get('platform', {}).get('os') == 'linux'
                          and item.get('platform', {}).get('architecture') == 'amd64']
            if len(candidates) != 1:
                raise ValueError('OCI index must select exactly one linux/amd64 manifest')
            selected = candidates[0]
            manifest = json.loads(read_blob(selected))
        else:
            selected, manifest = root, root_body
        manifest_digest = selected['digest']
        if manifest['config']['digest'] != config_digest:
            raise ValueError('OCI manifest does not reference the archive config')
        if read_blob(manifest['config']) != config_bytes:
            raise ValueError('OCI and Docker configuration bytes differ')
        if image['Layers'] != ['blobs/' + layer['digest'].replace(':', '/')
                               for layer in manifest['layers']]:
            raise ValueError('OCI and Docker layer order differs')
    if engine_id not in {config_digest, index_digest, manifest_digest}:
        raise ValueError('build engine identity does not match archive descriptors')

    diff_ids = config['rootfs']['diff_ids']
    if len(diff_ids) != len(image['Layers']):
        raise ValueError('configuration and archive layer counts differ')
    binary_digest = None
    binary_bytes = None
    for position, (path, diff_id) in enumerate(zip(image['Layers'], diff_ids)):
        data = saved.extractfile(path).read()
        if manifest is not None and data != read_blob(manifest['layers'][position]):
            raise ValueError('archive layer differs from OCI blob')
        unpacked = gzip.decompress(data) if data[:2] == b'\x1f\x8b' else data
        if 'sha256:' + hashlib.sha256(unpacked).hexdigest() != diff_id:
            raise ValueError('uncompressed layer hash does not match configuration')
        with tarfile.open(fileobj=io.BytesIO(unpacked)) as layer:
            for member in layer:
                name = member.name.removeprefix('./')
                if name in {'bin/.wh.helix-server', '.wh.bin', 'bin/.wh..wh..opq'}:
                    raise ValueError('unexpected server binary whiteout')
                if name == 'bin/helix-server':
                    if not member.isfile():
                        raise ValueError('server entrypoint is not a regular file')
                    binary = layer.extractfile(member).read()
                    binary_digest = hashlib.sha256(binary).hexdigest()
                    binary_bytes = len(binary)
    if binary_digest is None:
        raise ValueError('archive has no server binary')
Path(archive + '.receipt.json').write_text(json.dumps({
    'receipt_version': 2,
    'upstream_commit': commit,
    'patch_sha256': patch,
    'profile': 'homelab-3g-v2',
    'platform': 'linux/amd64',
    'image_tag': tag,
    'build_engine_image_id': engine_id,
    'oci_index_digest': index_digest,
    'platform_manifest_digest': manifest_digest,
    'config_digest': config_digest,
    'rootfs_diff_ids': diff_ids,
    'server_binary_sha256': binary_digest,
    'server_binary_bytes': binary_bytes,
    'archive_sha256': digest,
    'archive_bytes': Path(archive).stat().st_size,
}, indent=2) + '\n')
print(f'Built {tag}; config {config_digest}; receipt: {archive}.receipt.json')
PY
