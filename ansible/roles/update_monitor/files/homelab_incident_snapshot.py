"""Build complete, source-authenticated scan snapshots and retry an immutable outbox."""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import os
import time
from pathlib import Path
from urllib import parse, request

MAX_BYTES = 32 * 1024 * 1024
CHUNK_BYTES = 384 * 1024
PACKAGE_DERIVATION_RULE = 'package-consumer-derivation/v3'
FINITE_DOMAIN_DERIVATION_RULE = 'finite-execution-domain/v1'
RUNTIME_DERIVATION_RULE = 'runtime-relationship-derivation/v3'
REPLACEMENT_DERIVATION_RULE = 'graph-snapshot-replacement/v1'
COVERAGE_DERIVATION_RULE = 'relationship-coverage-derivation/v2'
PACKAGE_IDENTITY_DERIVATION_RULE = 'native-package-identity/v1'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def installation_resource_key(source, installation, ecosystem, package, location):
    identity = [source, installation, ecosystem, package, location]
    return 'installation:' + hashlib.sha256(canonical(identity)).hexdigest()


def consumer_scope(source, finding):
    """Identify consumer coverage for one stable package installation."""
    return 'consumer:' + source + ':' + installation_resource_key(
        source, *(finding.get(field, '') for field in
                  ('installation', 'ecosystem', 'package', 'location')))


def legacy_consumer_scope(source, finding):
    """Return the retired host-wide scope used before package scoping."""
    return ('consumer:' + source + ':' + finding['scope'] + ':' +
            finding['consumer_class'])


def consumer_discovery_scope(source, finding):
    """Identify discovery shared by packages in one runtime namespace."""
    installation = str(finding.get('installation') or '')
    namespace = installation if installation.startswith('container:') else 'host'
    return 'consumer-discovery:' + source + ':' + namespace


def consumer_discovery_failures(discovery, finding):
    """Select raw failures that can hide consumers in the package namespace."""
    gaps = discovery.get('gaps') or []
    installation = str(finding.get('installation') or '')
    if installation.startswith('container:'):
        name = installation.removeprefix('container:')
        prefixes = (
            'container-discovery-failed',
            'container-process-discovery-failed:' + name,
            'container-executable-unreadable:' + name,
            'container-package-evidence-incomplete:' + name,
        )
    else:
        prefixes = (
            'service-discovery-failed', 'process-discovery-failed:host',
            'process-unreadable:host:', 'host-package-evidence-incomplete',
            'scheduled-job-discovery-failed:',
            'scheduled-command-unsupported:',
        )
    return sorted(gap for gap in gaps if gap.startswith(prefixes))


def container_resource_key(source, namespace):
    """Identify the durable container slot, not one engine instance."""
    return 'container:' + source + ':' + str(namespace.get('container_name') or '').lstrip('/')


def purl_architecture(purl):
    values = parse.parse_qs(parse.urlsplit(str(purl or '')).query).get('arch', [])
    return values[0] if len(values) == 1 else ''


def purl_version(purl):
    """Return the decoded package version carried by an exact package URL."""
    parsed = parse.urlsplit(str(purl or ''))
    path = parsed.path
    package = path.rsplit('/', 1)[-1]
    version = parse.unquote(package.rsplit('@', 1)[1]) if '@' in package else ''
    epochs = parse.parse_qs(parsed.query).get('epoch', [])
    if version and len(epochs) == 1 and epochs[0] and epochs[0] != '0':
        version = epochs[0] + ':' + version
    return version


def released_version(version, release='', epoch=''):
    """Recompose the native version fields emitted separately by Trivy."""
    value = str(version or '')
    release = str(release or '')
    epoch = str(epoch or '')
    if not value:
        return ''
    if release:
        value += '-' + release
    if epoch and epoch != '0':
        value = epoch + ':' + value
    return value


def native_package_identity(package):
    """Derive the exact installed slot while retaining its scanner facts."""
    identifier = package.get('Identifier') or {}
    purl = str(identifier.get('PURL') or '')
    facts = {
        'version': str(package.get('Version') or ''),
        'release': str(package.get('Release') or ''),
        'epoch': str(package.get('Epoch') or ''),
        'source_name': str(package.get('SrcName') or ''),
        'source_version': str(package.get('SrcVersion') or ''),
        'source_release': str(package.get('SrcRelease') or ''),
        'source_epoch': str(package.get('SrcEpoch') or ''),
        'purl': purl,
    }
    installed = purl_version(purl) or released_version(
        facts['version'], facts['release'], facts['epoch'])
    source_version = released_version(
        facts['source_version'], facts['source_release'], facts['source_epoch'])
    identity = {
        'binary_package': str(package.get('Name') or 'unknown'),
        'installed': installed or 'unknown',
        'architecture': purl_architecture(purl),
        'source_package': facts['source_name'],
        'source_version': source_version,
        'purl': purl,
        'package_identity_derivation': {
            'rule': PACKAGE_IDENTITY_DERIVATION_RULE,
            'facts': facts,
        },
    }
    return identity


def package_identity(package, native):
    if native:
        return native_package_identity(package)
    purl = str((package.get('Identifier') or {}).get('PURL') or '')
    return {
        'binary_package': str(package.get('Name') or 'unknown'),
        'installed': str(package.get('Version') or 'unknown'),
        'architecture': purl_architecture(purl),
        'source_package': str(package.get('SrcName') or ''),
        'source_version': str(package.get('SrcVersion') or ''),
        'purl': purl,
    }


def vulnerability_package_identity(vulnerability, package_candidates, native):
    """Resolve only one exact scanner package identity for a vulnerability."""
    name = str(vulnerability.get('PkgName') or 'unknown')
    installed = str(vulnerability.get('InstalledVersion') or 'unknown')
    candidates = [(package, package_identity(package, native))
                  for package in package_candidates
                  if str(package.get('Name') or '') == name]
    candidates = [(package, identity) for package, identity in candidates
                  if identity['installed'] == installed]
    vulnerability_identifier = vulnerability.get('PkgIdentifier') or {}
    for field in ('UID', 'PURL'):
        expected = str(vulnerability_identifier.get(field) or '')
        if expected:
            candidates = [(package, identity) for package, identity in candidates
                          if str((package.get('Identifier') or {}).get(field) or '') == expected]
    identities = {}
    for _, identity in candidates:
        key = canonical({key: identity.get(key) for key in
                         ('binary_package', 'installed', 'architecture',
                          'source_package', 'source_version', 'purl')})
        identities.setdefault(key, identity)
    if len(identities) == 1:
        return next(iter(identities.values())), 'exact'
    return {}, 'ambiguous' if len(identities) > 1 else 'missing'


def package_slot(value):
    """Return the exact installed slot used to bind package evidence."""
    return {
        'installation': str(value.get('installation') or ''),
        'consumer_class': str(value.get('consumer_class') or ''),
        'ecosystem': str(value.get('ecosystem') or ''),
        'artifact_id': str(value.get('artifact_id') or ''),
        'binary_package': str(value.get('binary_package') or value.get('package') or ''),
        'version': str(value.get('version') or value.get('installed') or ''),
        'architecture': str(value.get('architecture') or ''),
        'source_package': str(value.get('source_package') or ''),
        'source_version': str(value.get('source_version') or ''),
        'location': str(value.get('location') or ''),
    }


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.new')
    with temporary.open('w', encoding='utf-8') as handle:
        os.fchmod(handle.fileno(), 0o600)
        json.dump(value, handle, sort_keys=True, separators=(',', ':'), allow_nan=False)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def snapshot_findings(reports, config=None):
    findings = {}
    complete = set()
    unknown = set()
    packages = {}
    config = config or {}
    for report in reports:
        library = report.get('_homelab_library') or {}
        binary = report.get('_homelab_host_binary') or {}
        runtime = report.get('_homelab_runtime') or {}
        installations = []
        if runtime:
            for container in runtime.get('containers', []):
                name = container['name'].lstrip('/')
                owners = sorted(set(d['id'] for d in config.get('deployments', [])
                    if any(fnmatch.fnmatchcase(name, p) for p in d.get('containers', []))
                    or container.get('compose_service') in d.get('compose_services', [])))
                installations.append((
                    'container:' + name, name,
                    owners if len(owners) == 1 else [],
                    owners if container.get('running') is True and len(owners) == 1 else [],
                    owners if len(owners) > 1 else []))
        elif library:
            installations = [('deployment:' + library['deployment'], library['path'],
                              [library['deployment']], [library['deployment']], [])]
        elif binary:
            installations = [('binary:' + binary['path'], binary['path'], [], [], [])]
        else:
            installations = [('os', '/', [], [], [])]
        for (installation, component, owner_deployments, declared_consumers,
             ambiguous_consumers) in installations:
            # Preserve independently deployed components inside one application.
            scope = installation + ':' + component
            covered = library.get('status', 'covered') == 'covered'
            complete_inventory = bool(report.get('Results')) and all('Packages' in r for r in report['Results'])
            if covered and complete_inventory:
                complete.add(scope)
            else:
                unknown.add(scope)
            for result in report.get('Results') or []:
                ecosystem = str(result.get('Type') or result.get('Class') or 'unknown')
                native = result.get('Class') == 'os-pkgs'
                target = binary.get('path') or str(result.get('Target') or component)
                if runtime and result.get('Class') == 'os-pkgs':
                    target = '/'
                for package in result.get('Packages') or []:
                    identity = package_identity(package, native)
                    pkg = {'installation': installation, 'ecosystem': ecosystem,
                           'package': str(package.get('Name') or 'unknown'),
                           'location': component + ':' + str(package.get('FilePath') or package.get('PkgPath') or target),
                           'scope': scope,
                           'consumer_class': ('library' if library else 'binary' if binary
                               else 'runtime-language' if runtime and result.get('Class') == 'lang-pkgs'
                               else 'runtime-os' if runtime else 'host-os'),
                           'owner_deployments': sorted(set(owner_deployments)),
                           'consumer_deployments': sorted(set(declared_consumers))
                               if library or (runtime and result.get('Class') == 'lang-pkgs') else [],
                           'ambiguous_deployments': ambiguous_consumers,
                           'containers': [c for c in runtime.get('containers', [])
                               if c['name'].lstrip('/') == component],
                           'artifact_id': runtime.get('image_id') or binary.get('sha256') or
                               library.get('identity', {}).get('sha256', ''),
                           **identity}
                    packages[tuple(pkg[field] for field in
                                   ('installation', 'ecosystem', 'package',
                                    'location', 'installed', 'architecture',
                                    'source_package', 'source_version', 'purl'))] = pkg
                for vuln in result.get('Vulnerabilities') or []:
                    advisory = str(vuln.get('VulnerabilityID') or '')
                    if not advisory:
                        continue
                    location = str(vuln.get('PkgPath') or target)
                    package_identity_value, identity_status = vulnerability_package_identity(
                        vuln, result.get('Packages') or [], native)
                    value = {
                        'id': advisory, 'installation': installation, 'scope': scope,
                        'ecosystem': ecosystem, 'package': str(vuln.get('PkgName') or 'unknown'),
                        'location': component + ':' + location,
                        'installed': str(vuln.get('InstalledVersion') or 'unknown'),
                        'fixed': str(vuln.get('FixedVersion') or ''),
                        'severity': str(vuln.get('Severity') or 'UNKNOWN'),
                        'binary_package': str(package_identity_value.get('binary_package')
                                              or vuln.get('PkgName') or 'unknown'),
                        'architecture': str(package_identity_value.get('architecture') or ''),
                        'source_package': str(package_identity_value.get('source_package') or ''),
                        'source_version': str(package_identity_value.get('source_version') or ''),
                        'purl': str(package_identity_value.get('purl') or ''),
                        'artifact_id': runtime.get('image_id') or binary.get('sha256') or library.get('identity', {}).get('sha256', ''),
                        'containers': [c for c in runtime.get('containers', []) if c['name'].lstrip('/') == component],
                        'target': target,
                        'consumer_class': ('library' if library else 'binary' if binary
                            else 'runtime-language' if runtime and result.get('Class') == 'lang-pkgs'
                            else 'runtime-os' if runtime else 'host-os'),
                        'owner_deployments': sorted(set(owner_deployments)),
                    }
                    if package_identity_value.get('package_identity_derivation'):
                        value['package_identity_derivation'] = package_identity_value[
                            'package_identity_derivation']
                    if identity_status != 'exact':
                        value['package_identity_status'] = identity_status
                    if (library or
                            (runtime and result.get('Class') == 'lang-pkgs')):
                        value['consumer_deployments'] = sorted(set(declared_consumers))
                    if ambiguous_consumers:
                        value['ambiguous_deployments'] = ambiguous_consumers
                    if not covered:
                        value['coverage_status'] = 'unknown'
                    key = tuple(value[k] for k in ('id', 'installation', 'ecosystem', 'package', 'location'))
                    previous = findings.get(key)
                    if previous and previous['installed'] != value['installed']:
                        # Missing package paths cannot safely collapse different installed versions.
                        raise ValueError('scanner returned ambiguous package locations')
                    findings[key] = value
    return list(findings.values()), sorted(complete - unknown), list(packages.values())


def lifecycle_graph(source, generation, sequence, observed, coverage, inventory,
                    findings=(), previous_graph=None):
    """Convert this source's runtime discovery into a scoped graph batch."""
    discovery = coverage.get('discovery') if isinstance(coverage, dict) else None
    if not isinstance(discovery, dict):
        return None
    runtime_identity = discovery.get('runtime_sha256') or hashlib.sha256(
        canonical({key: discovery.get(key) for key in
                   ('relationships', 'relationship_coverage', 'gaps')})).hexdigest()
    evidence_id = 'evidence_runtime_' + hashlib.sha256(canonical(
        [source, generation, sequence, runtime_identity])).hexdigest()
    version = runtime_identity + ':' + str(sequence)
    valid_until = observed + 36 * 3600
    resources = {}
    assertions = []

    def add_resource(key, **properties):
        prefix, _, name = key.partition(':')
        item = resources.setdefault(key, {
            'resource_key': key, 'kind': prefix or 'resource',
            'name': name or key, 'properties': {'source': source}})
        item['properties'].update(properties)

    relationships = list(discovery.get('relationships') or [])
    ownership = list(discovery.get('relationship_coverage') or [])

    def relationship(subject, relation, object_key, scope, kind='derived', *,
                     rule=PACKAGE_DERIVATION_RULE, input_refs=()):
        item = {'subject': subject, 'relation': relation,
                'object': object_key, 'scope': scope,
                'kind': kind, 'status': 'valid'}
        if kind == 'derived':
            item['derivation'] = {'rule': rule,
                                  'input_refs': list(input_refs)}
        relationships.append(item)

    def package_observations(finding):
        matches = []
        containers = {item.get('id') for item in finding.get('containers') or []}
        expected = package_slot(finding)
        if not all(expected[field] for field in (
                'installation', 'consumer_class', 'ecosystem', 'binary_package',
                'version', 'architecture', 'source_package', 'source_version',
                'location')):
            return matches
        for item in discovery.get('package_evidence') or []:
            namespace = item.get('namespace') or {}
            slots = item.get('slots') or ([item['slot']] if item.get('slot') else [])
            if expected not in [package_slot(slot) for slot in slots]:
                continue
            if finding.get('consumer_class') == 'host-os' and namespace.get('kind') != 'host':
                continue
            if finding.get('consumer_class') == 'runtime-os' and (
                    namespace.get('kind') != 'container' or
                    namespace.get('container_id') not in containers):
                continue
            matches.append(item)
        return matches

    binding_by_installation = {}
    binary_bindings = []
    for binary in coverage.get('native_go') or []:
        installation = 'binary:' + binary['path']
        consumers = set()
        for process in discovery.get('processes') or []:
            if (process.get('executable') != binary.get('resolved_path', binary['path'])
                    or not binary.get('sha256') or process.get('sha256') != binary['sha256']):
                continue
            for service in discovery.get('services') or []:
                # Match the observed service process, never a guessed unit name.
                if not process.get('pid') or str(service.get('MainPID')) != str(process['pid']):
                    continue
                consumers.update(service.get('deployments') or [])
                binary_bindings.append({'path': binary['path'], 'sha256': binary['sha256'],
                    'pid': process['pid'], 'start_ticks': process.get('start_ticks'),
                    'service': service['Id'], 'deployments': service.get('deployments') or []})
        binding_by_installation[installation] = consumers
    installation_bindings = []
    seen_installations = set()
    legacy_consumer_scopes = set()
    for finding in findings:
        subject = installation_resource_key(
            source, *(finding.get(field, '') for field in
                      ('installation', 'ecosystem', 'package', 'location')))
        if subject in seen_installations:
            continue
        seen_installations.add(subject)
        scope = consumer_scope(source, finding)
        legacy_consumer_scopes.add(legacy_consumer_scope(source, finding))
        dependency_scopes = []
        shared_discovery_scope = consumer_discovery_scope(source, finding)
        shared_discovery_failures = consumer_discovery_failures(
            discovery, finding)
        dependency_scopes.append(shared_discovery_scope)
        ownership.append({
            'scope': shared_discovery_scope,
            'relationship': 'consumer_discovery',
            'complete': not shared_discovery_failures,
            'status': ('incomplete' if shared_discovery_failures else 'valid'),
            'gaps': shared_discovery_failures})
        add_resource(subject, consumer_scope=scope,
                     binary_package=finding.get('binary_package') or finding.get('package'),
                     source_package=finding.get('source_package') or '',
                     source_version=finding.get('source_version') or '',
                     installed_version=finding.get('installed') or '',
                     architecture=finding.get('architecture') or '',
                     ecosystem=finding.get('ecosystem') or '',
                     purl=finding.get('purl') or '')
        consumers = set(finding.get('consumer_deployments') or [])
        if finding.get('installation', '').startswith('binary:'):
            consumers.update(binding_by_installation.get(finding['installation'], set()))
        evidence_matches = package_observations(finding)
        scheduled_dependencies = [dependency for package in evidence_matches
            for dependency in
            package.get('consumer_coverage_dependencies') or []]
        if scheduled_dependencies:
            scheduled_scope = ('scheduled-discovery:' + source + ':' + hashlib.sha256(
                canonical([source, subject, 'scheduled_execution'])).hexdigest())
            dependency_scopes.append(scheduled_scope)
            ownership.append({
                'scope': scheduled_scope,
                'relationship': 'scheduled_execution_discovery',
                'complete': False, 'status': 'incomplete',
                'gaps': scheduled_dependencies})
        add_resource(subject, consumer_dependency_scopes=sorted(set(
            dependency_scopes)))
        if evidence_matches:
            add_resource(subject, installed_package_identities=sorted(
                [item.get('installed') or {} for item in evidence_matches],
                key=lambda value: canonical(value)))
        execution_domain_map = {}
        for package in evidence_matches:
            owned_paths = set(package.get('files') or [])
            for domain in package.get('execution_domains') or []:
                selected = set(domain.get('files') or []).intersection(owned_paths)
                if (domain.get('id') and
                        (selected or not domain.get('files')) and
                        (selected or not domain.get('elf_dependency_roots'))):
                    execution_domain_map.setdefault(domain['id'], domain)
        execution_domains = [execution_domain_map[key]
                             for key in sorted(execution_domain_map)]
        domain_scopes = []
        domain_owned_files = set()
        occurrence_owned_files = set().union(*(
            set(package.get('files') or []) for package in evidence_matches)) \
            if evidence_matches else set()
        for domain in execution_domains:
            domain_id = domain.get('id')
            if not domain_id:
                continue
            base = 'current-domain:' + source + ':' + domain_id
            scopes = {
                'declaration': base + ':declaration',
                'entry': base + ':entry',
                'input': base + ':input',
                'file_authority': base + ':file-authority',
                'membership': base + ':membership',
                'catalogue': ('current-domain:' + source + ':package:' +
                              str(finding.get('package')) + ':catalogue'),
            }
            domain_scopes.extend(scopes.values())
            domain_key = 'execution-domain:' + source + ':' + domain_id
            occurrence_files = sorted(set(domain.get('files') or []).intersection(
                                      occurrence_owned_files))
            declaration = {key: domain.get(key) for key in
                ('packages', 'files', 'entries', 'inputs', 'authority_paths',
                 'operation_files', 'interpreter', 'elf_dependency_roots',
                 'selector_evidence')}
            add_resource(domain_key, declaration=declaration,
                evidence_refs=domain.get('evidence_refs') or [])
            refs = ['domain-observation:' + domain_id,
                    *list(domain.get('evidence_refs') or [])]
            relationship(subject, 'CURRENT_DOMAIN', domain_key,
                         scopes['membership'], rule=FINITE_DOMAIN_DERIVATION_RULE,
                         input_refs=refs)
            observation = domain.get('observation') or {}
            file_artifacts = {}
            for path in sorted(set(observation.get('files') or []).intersection(
                               occurrence_files)):
                artifact = 'package-file:' + hashlib.sha256(canonical([
                    source, subject, path,
                    next((package.get('file_inventory_sha256') for package in
                          evidence_matches if path in (package.get('files') or [])),
                         '')])).hexdigest()
                add_resource(artifact, path=path,
                             finite_domain=domain_id,
                             installed_package_identities=sorted(
                                 [package.get('installed') or {} for package in
                                  evidence_matches if path in
                                  (package.get('files') or [])],
                                 key=lambda value: canonical(value)))
                file_artifacts[path] = artifact
                if artifact not in domain_owned_files:
                    domain_owned_files.add(artifact)
                    relationship(subject, 'OWNS_FILE', artifact, scope,
                                 rule=FINITE_DOMAIN_DERIVATION_RULE,
                                 input_refs=['finite-domain-file:' + path])
                relation = ('DECLARES_DEPENDENCY' if
                            domain.get('elf_dependency_roots') else 'PARSES_WITH')
                relationship(domain_key, relation, artifact,
                             scopes['membership'],
                             rule=FINITE_DOMAIN_DERIVATION_RULE,
                             input_refs=refs)
            for path in sorted(set(observation.get('operation_files') or []).intersection(
                               domain.get('operation_files') or [])):
                operation_key = 'operation-file:' + hashlib.sha256(canonical(
                    [source, domain_id, path])).hexdigest()
                add_resource(operation_key, path=path, finite_domain=domain_id)
                relationship(domain_key, 'EXECUTES_FILE', operation_key,
                             scopes['membership'],
                             rule=FINITE_DOMAIN_DERIVATION_RULE,
                             input_refs=refs)
                interpreter = domain.get('interpreter')
                if interpreter in file_artifacts:
                    relationship(operation_key, 'INTERPRETED_BY',
                                 file_artifacts[interpreter],
                                 scopes['membership'],
                                 rule=FINITE_DOMAIN_DERIVATION_RULE,
                                 input_refs=refs)
            for entry in sorted(observation.get('entries') or []):
                entry_key = ('execution-entry:' + source + ':' + domain_id + ':' +
                             hashlib.sha256(entry.encode()).hexdigest())
                add_resource(entry_key, member=entry, finite_domain=domain_id)
                relationship(domain_key, 'ENTERED_BY', entry_key,
                             scopes['entry'], rule=FINITE_DOMAIN_DERIVATION_RULE,
                             input_refs=refs)
            for input_class in sorted(observation.get('inputs') or []):
                input_key = ('input-class:' + source + ':' + domain_id + ':' +
                             hashlib.sha256(input_class.encode()).hexdigest())
                add_resource(input_key, member=input_class, finite_domain=domain_id)
                relationship(domain_key, 'ADMITS_INPUT', input_key,
                             scopes['input'], rule=FINITE_DOMAIN_DERIVATION_RULE,
                             input_refs=refs)
            coverage = domain.get('coverage') or {}
            domain_coverage = {
                'declaration': True,
                'entry': (coverage.get('entry') or {}).get('complete') is True,
                'input': (coverage.get('input') or {}).get('complete') is True,
                'file_authority': ((coverage.get('file_authority') or {}).get(
                    'complete') is True),
                'membership': domain.get('complete') is True,
                'catalogue': True,
            }
            for name, complete in domain_coverage.items():
                ownership.append({
                    'scope': scopes[name],
                    'relationship': 'current_domain_' + name,
                    'complete': complete,
                    'status': 'valid' if complete else 'incomplete'})
            disposition_ready = (domain.get('complete') is True or
                (domain.get('disposition') == 'requires_work' and
                 domain.get('work_evidence_complete') is True))
            if disposition_ready and domain.get('disposition'):
                relationship(subject, 'WORK_DISPOSITION', None,
                             scopes['membership'], rule=FINITE_DOMAIN_DERIVATION_RULE,
                             input_refs=refs)
                relationships[-1]['value'] = domain['disposition']
        if domain_scopes:
            add_resource(subject, current_domain_scopes=sorted(set(domain_scopes)))
        observed_files = []
        slot_ref = ('package-slot:sha256:' +
                    hashlib.sha256(canonical(package_slot(finding))).hexdigest())
        for package in evidence_matches:
            namespace = package.get('namespace') or {}
            namespace_key = (container_resource_key(source, namespace)
                             if namespace.get('kind') == 'container' else
                             'host:' + source)
            profile = package.get('artifact_profile') or {}
            package_refs = [slot_ref,
                            'package-file-inventory:sha256:' +
                            str(package.get('file_inventory_sha256') or '')]
            build_consumers = sorted(set(inventory.get('build_consumers') or []))
            if (profile.get('kind') == 'development-headers' and
                    profile.get('classification_complete') is True and
                    build_consumers):
                for deployment in build_consumers:
                    relationship(subject, 'AVAILABLE_TO',
                                 'deployment:' + source + ':' + deployment,
                                 scope, input_refs=[*package_refs,
                                     'inventory:sha256:' + hashlib.sha256(
                                         canonical(inventory)).hexdigest()])
            for capability in package.get('declared_capabilities') or []:
                capability_scope = ('runtime:' + source + ':package-capability:' +
                                    capability['id'])
                capability_key = ('command-capability:' + source + ':' +
                                  capability['id'])
                add_resource(capability_key,
                             required_executables=capability.get('required_executables', []),
                             dependency_path=capability.get('dependency_path', []),
                             evidence=capability.get('evidence', []))
                relationship(subject, 'AVAILABLE_TO', capability_key, scope,
                             input_refs=[*package_refs,
                                 *(capability.get('derivation') or {}).get(
                                     'input_refs', [])])
                for application in capability.get('applications') or []:
                    relationship(capability_key, 'USED_BY',
                                 'application:' + application,
                                 capability_scope, 'declaration')
                ownership.append({
                    'scope': capability_scope,
                    'relationship': 'package_capability', 'complete': True,
                    'status': 'valid'})
            for observation in package.get('observations') or []:
                observation_refs = ((observation.get('derivation') or {}).get(
                                    'input_refs', []))
                file_identity = observation.get('file') or {}
                if not file_identity.get('path') or not file_identity.get('sha256'):
                    continue
                artifact = 'package-file:' + hashlib.sha256(canonical([
                    source, namespace_key, file_identity['path'],
                    file_identity['sha256']])).hexdigest()
                add_resource(artifact, path=file_identity['path'],
                             sha256=file_identity['sha256'],
                             inode=file_identity.get('inode'),
                             device=file_identity.get('device'),
                             packaged_md5=file_identity.get('packaged_md5'),
                             actual_md5=file_identity.get('actual_md5'),
                             replacement_status=file_identity.get('replacement_status'),
                             namespace=namespace,
                             installed_package=package.get('installed') or {},
                             file_inventory_sha256=package.get('file_inventory_sha256'))
                relationship(subject, 'OWNS_FILE', artifact, scope,
                             input_refs=[*package_refs,
                                 'file:sha256:' + file_identity['sha256']])
                consumer = observation.get('consumer') or {}
                deployments = sorted(set(consumer.get('deployments') or []))
                if len(deployments) == 1:
                    consumers.update(deployments)
                if consumer.get('kind') == 'process':
                    consumer_key = 'process:' + hashlib.sha256(canonical([
                        source, namespace_key, consumer.get('executable'),
                        consumer.get('executable_sha256'),
                        consumer.get('service')])).hexdigest()
                    add_resource(consumer_key, pid=consumer.get('pid'),
                                 start_ticks=consumer.get('start_ticks'),
                                 executable=consumer.get('executable'),
                                 executable_sha256=consumer.get('executable_sha256'),
                                 namespace=namespace)
                    relationship(artifact, 'LOADED_BY', consumer_key, scope,
                                 input_refs=observation_refs)
                    if namespace.get('kind') == 'container':
                        container_key = container_resource_key(source, namespace)
                        add_resource(container_key, name=namespace.get('container_name'),
                                     image_id=namespace.get('image_id'),
                                     observed_container_id=namespace.get('container_id'))
                        relationship(consumer_key, 'RUNS_IN', container_key,
                                     shared_discovery_scope,
                                     input_refs=observation_refs)
                        for deployment in deployments if len(deployments) == 1 else []:
                            relationship(container_key, 'OWNED_BY',
                                         'deployment:' + source + ':' + deployment,
                                         shared_discovery_scope,
                                         input_refs=observation_refs)
                    elif consumer.get('service'):
                        service_key = 'service:' + source + ':' + consumer['service']
                        add_resource(service_key)
                        relationship(consumer_key, 'RUNS_UNDER', service_key,
                                     shared_discovery_scope,
                                     input_refs=observation_refs)
                        for deployment in deployments if len(deployments) == 1 else []:
                            relationship(service_key, 'OWNED_BY',
                                         'deployment:' + source + ':' + deployment,
                                         shared_discovery_scope,
                                         input_refs=observation_refs)
                elif consumer.get('kind') == 'service':
                    consumer_key = 'service:' + source + ':' + str(consumer.get('id'))
                    add_resource(consumer_key, active_state=consumer.get('active_state'),
                                 unit_file_state=consumer.get('unit_file_state'))
                    relationship(artifact, 'ACTIVATES', consumer_key, scope,
                                 input_refs=observation_refs)
                    for deployment in deployments if len(deployments) == 1 else []:
                        relationship(consumer_key, 'OWNED_BY',
                                     'deployment:' + source + ':' + deployment,
                                     shared_discovery_scope,
                                     input_refs=observation_refs)
                else:
                    consumer_key = 'job:' + hashlib.sha256(canonical(
                        [source, namespace_key, consumer.get('id')])).hexdigest()
                    add_resource(consumer_key, job_id=consumer.get('id'))
                    relationship(artifact, 'SCHEDULED_AS', consumer_key, scope,
                                 input_refs=observation_refs)
                    for deployment in deployments if len(deployments) == 1 else []:
                        relationship(consumer_key, 'OWNED_BY',
                                     'deployment:' + source + ':' + deployment,
                                     shared_discovery_scope,
                                     input_refs=observation_refs)
                observed_files.append({'path': file_identity['path'],
                                       'sha256': file_identity['sha256'],
                                       'consumer': consumer})
        for consumer in sorted(consumers):
            if finding.get('consumer_class') not in {'host-os', 'runtime-os'}:
                relationship(subject, 'CONSUMED_BY',
                             'deployment:' + source + ':' + consumer, scope)
        complete = (bool(consumers) if finding.get('consumer_class') not in
                    {'host-os', 'runtime-os'} else bool(evidence_matches) and all(
                        item.get('consumer_coverage_complete') is True
                        for item in evidence_matches))
        ownership.append({
            'scope': scope, 'relationship': 'package_consumer',
            'complete': complete,
            'status': 'valid' if complete else 'incomplete'})
        installation_bindings.append({
            'installation': subject, 'package': finding.get('package'),
            'location': finding.get('location'),
            'installed': finding.get('installed'),
            'source_package': finding.get('source_package'),
            'source_version': finding.get('source_version'),
            'deployments': sorted(consumers),
            'package_evidence_records': len(evidence_matches),
            'artifact_profiles': [item.get('artifact_profile') or {}
                                  for item in evidence_matches],
            'declared_capabilities': [capability for item in evidence_matches
                                      for capability in item.get('declared_capabilities') or []],
            'consumer_coverage_dependencies': scheduled_dependencies,
            'running_kernel': discovery.get('kernel'),
            'observed_files': observed_files})
    for deployment in inventory.get('deployments', []):
        subject = 'deployment:' + source + ':' + deployment['id']
        relationships.append({
            'subject': subject, 'relation': 'DEPLOYS',
            'object': 'application:' + deployment['id'],
            'scope': 'runtime:' + source + ':' + deployment['id'],
            'kind': 'declaration', 'status': 'valid'})
    relationship_index = {}
    deduplicated_relationships = []
    for relationship in relationships:
        if relationship.get('kind', 'observation') == 'observation':
            relationship['kind'] = 'derived'
            relationship['derivation'] = {
                'rule': RUNTIME_DERIVATION_RULE,
                'input_refs': ['discovery-relationship:sha256:' +
                               hashlib.sha256(canonical({key: relationship.get(key)
                                   for key in ('subject', 'relation', 'object',
                                               'value', 'scope')})).hexdigest()]}
        subject = relationship['subject']
        object_key = relationship.get('object')
        relationship_key = (subject, relationship['relation'], object_key,
                            canonical(relationship.get('value')),
                            relationship['scope'], relationship.get('kind', 'observation'))
        prior = relationship_index.get(relationship_key)
        if prior is not None:
            if (relationship.get('kind') == 'derived' and
                    prior.get('derivation', {}).get('rule') ==
                    relationship.get('derivation', {}).get('rule')):
                prior['derivation']['input_refs'] = sorted(set(
                    prior['derivation'].get('input_refs', []) +
                    relationship['derivation'].get('input_refs', [])))
            continue
        relationship_index[relationship_key] = relationship
        deduplicated_relationships.append(relationship)
    relationships = deduplicated_relationships
    for relationship in relationships:
        subject = relationship['subject']
        object_key = relationship.get('object')
        add_resource(subject)
        if object_key:
            add_resource(object_key)
        # The same edge can be evidenced in multiple package or domain scopes.
        # Scope is part of its identity so one conclusion cannot replace another.
        logical_identity = [source, subject, relationship['relation'], object_key,
                            relationship.get('value'), relationship['scope']]
        logical = hashlib.sha256(canonical(logical_identity)).hexdigest()
        assertion = {
            'logical_key': 'runtime:' + logical, 'version': version,
            'subject': subject, 'relation': relationship['relation'],
            'object_key': object_key,
            'value': True if object_key else relationship.get('value'),
            'kind': relationship.get('kind', 'observation'),
            'scope': relationship['scope'], 'source': source,
            'provenance': 'runtime:' + runtime_identity,
            'evidence_id': evidence_id, 'valid_from': observed,
            'valid_until': valid_until}
        if relationship.get('kind') == 'derived':
            assertion['provenance'] = ('derived:' +
                relationship['derivation']['rule'] + ':runtime:' + runtime_identity)
            assertion['derivation'] = {
                **relationship['derivation'],
                'input_evidence_ids': [evidence_id],
            }
        assertions.append(assertion)
    graph_coverage = []
    coverage_by_scope = {}
    for item in ownership:
        key = (item['scope'], item['relationship'])
        aggregate = coverage_by_scope.setdefault(key, {
            'scope': item['scope'], 'relationship': item['relationship'],
            'complete': True, 'statuses': set()})
        aggregate['complete'] = aggregate['complete'] and item.get('complete') is True
        aggregate['statuses'].add(item.get('status', 'incomplete'))
    for item in coverage_by_scope.values():
        logical = hashlib.sha256(canonical(
            [source, item['scope'], item['relationship']])).hexdigest()
        if 'conflicting' in item['statuses']:
            status = 'conflicting'
        elif item['complete']:
            status = 'valid'
        else:
            status = 'incomplete'
        graph_coverage.append({
            'logical_key': 'runtime-coverage:' + logical,
            'version': version, 'scope': item['scope'],
            'relationship': item['relationship'], 'producer': source,
            'complete': item['complete'], 'status': status,
            'valid_from': observed, 'valid_until': valid_until,
            'evidence_id': evidence_id})
    current_package_scopes = {item['scope'] for item in graph_coverage
                              if item['relationship'] == 'package_consumer'}
    for retired_scope in sorted(legacy_consumer_scopes - current_package_scopes):
        logical = hashlib.sha256(canonical(
            [source, retired_scope, 'package_consumer'])).hexdigest()
        graph_coverage.append({
            'logical_key': 'runtime-coverage:' + logical,
            'version': version, 'scope': retired_scope,
            'relationship': 'package_consumer', 'producer': source,
            'complete': False, 'status': 'withdrawn',
            'valid_from': observed, 'valid_until': observed,
            'evidence_id': evidence_id})
    covered_scopes = {item['scope'] for item in graph_coverage}
    discovery_failures = [gap for gap in discovery.get('gaps') or []
                          if gap.startswith(('service-discovery-failed',
                                             'container-discovery-failed',
                                             'process-unreadable',
                                             'listener-discovery-failed'))]
    for scope in sorted({item['scope'] for item in relationships} - covered_scopes):
        logical = hashlib.sha256(canonical([source, scope, '*'])).hexdigest()
        complete = not discovery_failures
        graph_coverage.append({
            'logical_key': 'runtime-coverage:' + logical,
            'version': version, 'scope': scope, 'relationship': '*',
            'producer': source, 'complete': complete,
            'status': 'valid' if complete else 'incomplete',
            'valid_from': observed, 'valid_until': valid_until,
            'evidence_id': evidence_id})
    if isinstance(previous_graph, dict):
        prior_resources = {item.get('resource_key'): item
                           for item in previous_graph.get('resources') or []
                           if item.get('resource_key')}
        current_assertions = {item['logical_key'] for item in assertions}
        for prior in previous_graph.get('assertions') or []:
            if (prior.get('source') != source or not prior.get('logical_key') or
                    prior['logical_key'] in current_assertions):
                continue
            for key in (prior.get('subject'), prior.get('object_key')):
                if key and key not in resources:
                    old_resource = prior_resources.get(key)
                    if old_resource:
                        resources[key] = old_resource
                    else:
                        add_resource(key)
            assertions.append({
                **{key: prior.get(key) for key in
                   ('logical_key', 'subject', 'relation', 'object_key', 'value',
                    'kind', 'scope', 'source')},
                'version': version, 'status': 'withdrawn', 'kind': 'derived',
                'provenance': ('derived:' + REPLACEMENT_DERIVATION_RULE +
                               ':runtime:' + runtime_identity),
                'evidence_id': evidence_id, 'valid_from': observed,
                'valid_until': observed,
                'derivation': {
                    'rule': REPLACEMENT_DERIVATION_RULE,
                    'input_evidence_ids': sorted(set(value for value in
                        [evidence_id, prior.get('evidence_id')] if value)),
                    'input_refs': ['prior-assertion:' + prior['logical_key']],
                }})
        current_coverage = {item['logical_key'] for item in graph_coverage}
        for prior in previous_graph.get('coverage') or []:
            if (prior.get('producer') != source or not prior.get('logical_key') or
                    prior['logical_key'] in current_coverage):
                continue
            graph_coverage.append({
                **{key: prior.get(key) for key in
                   ('logical_key', 'scope', 'relationship', 'producer')},
                'version': version, 'complete': False, 'status': 'withdrawn',
                'valid_from': observed, 'valid_until': observed,
                'evidence_id': evidence_id})
    for item in graph_coverage:
        item.setdefault('derivation', {
            'rule': COVERAGE_DERIVATION_RULE,
            'input_evidence_ids': [evidence_id],
            'input_refs': ['coverage-scope:' + str(item.get('scope')) + ':' +
                           str(item.get('relationship'))],
        })
    return {
        'change_id': 'runtime:' + source + ':' + generation + ':' + str(sequence),
        'resources': list(resources.values()),
        'evidence': [{
            'id': evidence_id, 'kind': 'observation',
            'scope': 'runtime:' + source, 'source': source,
            'provenance': 'runtime:' + runtime_identity,
            'status': 'complete', 'valid_from': observed,
            'valid_until': valid_until,
            'content': {'relationships': relationships,
                        'coverage': ownership,
                        'input_observations': {
                            'runtime_sha256': runtime_identity,
                            'config_sha256': discovery.get('config_sha256'),
                            'inventory_revision': hashlib.sha256(
                                canonical(inventory)).hexdigest(),
                            'services': discovery.get('services') or [],
                            'processes': [{key: process[key] for key in
                                ('pid', 'start_ticks', 'executable', 'sha256',
                                 'cgroup', 'privileges') if key in process}
                                for process in discovery.get('processes') or []],
                            'path_access': discovery.get('path_access') or [],
                            'containers': discovery.get('containers') or [],
                            'scheduled_files': discovery.get('scheduled_files') or [],
                            'activated_units': discovery.get('activated_units') or [],
                            'package_evidence': [{key: item.get(key) for key in
                                ('namespace', 'installed', 'slots',
                                 'file_inventory_sha256', 'artifact_profile',
                                 'declared_capabilities', 'execution_domains',
                                 'consumer_coverage_dependencies',
                                 'observations')}
                                for item in discovery.get('package_evidence') or []],
                            'execution_domains': discovery.get('execution_domains') or [],
                            'execution_domain_facts': discovery.get(
                                'execution_domain_facts') or {},
                        },
                        'binary_bindings': binary_bindings,
                        'installation_bindings': installation_bindings,
                        'gaps': discovery.get('gaps') or []}}],
        'assertions': assertions, 'coverage': graph_coverage,
    }


def deliver_pending(path, settings, send=None):
    path = Path(path)
    if not path.exists():
        return
    pending = json.loads(path.read_text())
    snapshot = pending.get('pending')
    if snapshot is None:
        return
    raw = canonical(snapshot)
    if len(raw) > MAX_BYTES:
        raise ValueError('snapshot exceeds source spool limit')
    parts = [raw[i:i+CHUNK_BYTES] for i in range(0, len(raw), CHUNK_BYTES)]
    hashes = [hashlib.sha256(part).hexdigest() for part in parts]
    manifest = {'source': settings['source'], 'generation': settings['generation'],
                'sequence': snapshot['sequence'], 'hashes': hashes, 'sha256': hashlib.sha256(raw).hexdigest()}
    sender = send or post
    for index, part in enumerate(parts):
        sender(settings, {'kind': 'incident_api', 'action': 'chunk', 'manifest': manifest,
                          'index': index, 'data': base64.b64encode(part).decode()})
    sender(settings, {'kind': 'incident_api', 'action': 'commit', 'manifest': manifest})
    # Keep exactly the acknowledged evidence, including every severity. Legacy
    # notification state is severity-filtered and cannot answer incident queries.
    accepted_path = path.with_name(path.stem.removesuffix('.incident-outbox') + '.incident-snapshot.json')
    atomic_json(accepted_path, {'sha256': manifest['sha256'], 'snapshot': snapshot})
    pending['pending'] = None
    atomic_json(path, pending)


def post(settings, payload):
    req = request.Request(settings['url'], data=canonical(payload), headers={
        'Authorization': 'Bearer ' + settings['token'], 'Content-Type': 'application/json',
        'X-Homelab-Incident-API': '1'})
    with request.urlopen(req, timeout=30) as response:
        if response.status != 202:
            raise RuntimeError('incident service did not accept snapshot')


def publish(reports, coverage, inventory, state_path, settings, send=None):
    path = Path(state_path)
    deliver_pending(path, settings, send)
    old = json.loads(path.read_text()) if path.exists() else {'sequence': 0}
    if old.get('generation', settings['generation']) != settings['generation']:
        raise ValueError('source generation changed without spool migration')
    findings, scopes, packages = snapshot_findings(reports, inventory)
    snapshot = {'schema': 1, 'source': settings['source'], 'generation': settings['generation'],
                'sequence': old['sequence']+1, 'observed_at': time.time(),
                'findings': findings, 'packages': packages, 'complete_scopes': scopes, 'coverage': coverage,
                'inventory_revision': hashlib.sha256(canonical(inventory)).hexdigest()}
    accepted_path = path.with_name(
        path.stem.removesuffix('.incident-outbox') + '.incident-snapshot.json')
    previous_graph = None
    if accepted_path.exists():
        try:
            accepted = json.loads(accepted_path.read_text())
            previous_graph = (accepted.get('snapshot') or {}).get('lifecycle_graph')
        except (OSError, json.JSONDecodeError):
            previous_graph = None
    graph_slots = {tuple(item.get(field, '') for field in
                         ('installation', 'ecosystem', 'package', 'location')): item
                   for item in findings}
    # Current installed runtime-language slots reconcile retained findings when
    # an advisory feed stops returning the CVE. Their declared or running
    # deployment identity is evidence; advisory disappearance is not build
    # disposition.
    positive_slots = {canonical(package_slot(slot))
        for item in (coverage.get('discovery') or {}).get('package_evidence') or []
        if (item.get('observations') or item.get('declared_capabilities') or
            (item.get('artifact_profile') or {}).get('kind') == 'development-headers')
        for slot in item.get('slots') or ([item['slot']] if item.get('slot') else [])}
    for package in packages:
        key = tuple(package.get(field, '') for field in
                    ('installation', 'ecosystem', 'package', 'location'))
        if (package.get('consumer_class') != 'runtime-language' and
                canonical(package_slot(package)) not in positive_slots):
            continue
        graph_slots.setdefault(key, package)
    graph = lifecycle_graph(settings['source'], settings['generation'],
                            snapshot['sequence'], snapshot['observed_at'], coverage,
                            inventory, list(graph_slots.values()),
                            previous_graph=previous_graph)
    if graph:
        snapshot['lifecycle_graph'] = graph
    if len(canonical(snapshot)) > MAX_BYTES:
        raise ValueError('snapshot exceeds source spool limit')
    atomic_json(path, {'generation': settings['generation'], 'sequence': snapshot['sequence'], 'pending': snapshot})
    deliver_pending(path, settings, send)
