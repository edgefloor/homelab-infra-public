"""Fetch one public, digest-bound image without importing or executing it."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile

MAX_DOWNLOAD = 256*1024*1024
MAX_EXPANDED = 1024*1024*1024
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def repository(image):
    value = image.split('@', 1)[0]
    if ':' in value.rsplit('/', 1)[-1]:
        value = value.rsplit(':', 1)[0]
    if '/' not in value:
        value = 'docker.io/library/'+value
    elif '.' not in value.split('/')[0]:
        value = 'docker.io/'+value
    if not re.fullmatch(r'(docker\.io|ghcr\.io)/[a-z0-9][a-z0-9._/-]*', value) or '..' in value.split('/'):
        raise ValueError('replacement repository is not a supported public deployment repository')
    return value


def descriptor(value):
    if (not isinstance(value, dict) or not DIGEST.fullmatch(str(value.get('digest', '')))
            or type(value.get('size')) is not int or not 0 < value['size'] <= MAX_DOWNLOAD
            or value.get('urls')):
        raise ValueError('invalid, oversized, or externally redirected image descriptor')
    return value


def checked_blob(root, value):
    descriptor(value)
    path = root/value['digest'].split(':')[1]
    if path.is_symlink() or not path.is_file() or path.stat().st_size != value['size']:
        raise ValueError('image blob size or type differs from manifest')
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            digest.update(chunk)
    if 'sha256:'+digest.hexdigest() != value['digest']:
        raise ValueError('image blob digest mismatch')
    return path


def extract_executable(root, manifest, executable, destination):
    """Apply only the requested file's layer history; never extract arbitrary paths."""
    target = executable.lstrip('/')
    if not target or '..' in PurePosixPath(target).parts:
        raise ValueError('invalid executable path')
    ancestors = list(PurePosixPath(target).parents)
    deletes = {str(p.parent/('.wh.'+p.name)) for p in [PurePosixPath(target), *ancestors] if p.name}
    opaque = {str(p/'.wh..wh..opq') for p in ancestors}
    expanded = members = 0
    present = False
    for layer in manifest['layers']:
        blob = checked_blob(root, layer)
        replacement = None
        removed = False
        with tarfile.open(blob, 'r|*') as archive:
            for member in archive:
                members += 1
                expanded += member.size
                if expanded > MAX_EXPANDED or members > 100000:
                    raise ValueError('image expansion exceeds analysis limit')
                name = member.name.removeprefix('./').rstrip('/')
                if name in deletes or name in opaque:
                    removed = True
                if name != target:
                    # An ancestor symlink changes resolution even if this layer
                    # does not contain the requested executable.
                    if name in {str(p) for p in ancestors} and not member.isdir():
                        raise ValueError('candidate path traverses an image link')
                    continue
                if not member.isfile() or not 0 < member.size <= MAX_DOWNLOAD:
                    raise ValueError('candidate executable is not a bounded regular layer file')
                replacement = destination.with_suffix('.layer')
                with archive.extractfile(member) as source, replacement.open('wb') as output:
                    shutil.copyfileobj(source, output, length=65536)
                if replacement.stat().st_size != member.size:
                    raise ValueError('candidate executable is truncated')
        if removed:
            destination.unlink(missing_ok=True)
            present = False
        if replacement is not None:
            replacement.replace(destination)
            present = True
    if not present:
        raise ValueError('candidate image does not contain the exact deployed executable path')


def fetch(image, candidate, executable, directory, run):
    repo = repository(image)
    if not isinstance(candidate, str) or not (DIGEST.fullmatch(candidate) or re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', candidate)):
        raise ValueError('candidate must be a tag or sha256 digest in the deployed repository')
    if shutil.disk_usage(directory).free < 2*1024*1024*1024:
        raise ValueError('replacement analysis requires 2 GiB of temporary free space')

    def command(args, seconds=30):
        result = run(['/usr/bin/skopeo', *args], seconds, 128*1024,
                     disk_root=directory, disk_limit=512*1024*1024)
        if result['returncode'] or result['timed_out'] or result['overflow']:
            raise ValueError('registry read failed or exceeded time, output, or temporary storage limits')
        return result['stdout']

    def manifest(digest):
        raw = command(['inspect', '--raw', '--no-creds', '--tls-verify=true', 'docker://'+repo+'@'+digest]).encode()
        for data in (raw, raw.rstrip(b'\n')):
            if 'sha256:'+hashlib.sha256(data).hexdigest() == digest:
                return json.loads(data)
        raise ValueError('registry manifest differs from its immutable digest')

    requested = candidate
    if not DIGEST.fullmatch(candidate):
        candidate = command(['inspect', '--no-creds', '--tls-verify=true', '--no-tags', '--format', '{{.Digest}}',
                             'docker://'+repo+':'+candidate]).strip()
        if not DIGEST.fullmatch(candidate):
            raise ValueError('registry did not resolve the tag to a digest')
    top_digest = candidate
    document = manifest(candidate)
    if 'manifests' in document:
        choices = [d for d in document['manifests'] if d.get('platform', {}).get('os') == 'linux'
                   and d.get('platform', {}).get('architecture') == 'amd64' and not d.get('platform', {}).get('variant')]
        if len(choices) != 1:
            raise ValueError('candidate has no unique linux/amd64 manifest')
        candidate = descriptor(choices[0])['digest']
        document = manifest(candidate)
    layers = document.get('layers')
    if not isinstance(layers, list) or not 1 <= len(layers) <= 32:
        raise ValueError('invalid or excessive image layers')
    config = descriptor(document.get('config'))
    if sum(descriptor(d)['size'] for d in [config, *layers]) > MAX_DOWNLOAD:
        raise ValueError('candidate exceeds compressed download allowance')
    image_dir = directory/'image'
    command(['copy', '--src-no-creds', '--src-tls-verify=true', '--preserve-digests',
             'docker://'+repo+'@'+candidate, 'dir:'+str(image_dir)], 120)
    raw = (image_dir/'manifest.json').read_bytes()
    if 'sha256:'+hashlib.sha256(raw).hexdigest() != candidate:
        raise ValueError('downloaded manifest identity changed')
    configuration = json.loads(checked_blob(image_dir, config).read_bytes())
    if (configuration.get('os'), configuration.get('architecture')) != ('linux', 'amd64'):
        raise ValueError('candidate configuration platform mismatch')
    destination = directory/'candidate-executable'
    extract_executable(image_dir, document, executable, destination)
    return destination, {'repository': repo, 'requested': requested, 'index_digest': top_digest,
                         'manifest_digest': candidate, 'platform': 'linux/amd64', 'path': executable}
