# Vulnerability investigation

This context gives the investigation agent one vocabulary for scanner input,
deployed risk, and the resulting decision. The distinctions stop a package
match from quietly turning into a claim of exploitable exposure.

## Language

**Alert**:
A notification that starts one investigation and contains one or more finding
groups.

**Finding**:
A scanner claim that a target matches an advisory's affected range. It says
nothing by itself about execution or reachability.
_Avoid_: Vulnerability, exposure

**Advisory**:
The authoritative description of affected behavior, versions, and required
conditions. It describes the general flaw, not this deployment.

**Finding Group**:
Findings with the same advisory, package, severity, and stated fix. Grouping
removes repetitive reporting while preserving each occurrence.

**Occurrence**:
One recorded location of a finding in an artifact, executable, container, or
host.

**Mechanism**:
The affected behavior and the conditions needed to trigger it.

**Precondition**:
A state, input, or configuration required by the mechanism.

**Deployed Path**:
The observed chain of code, execution, configuration, and input that could
satisfy a mechanism's preconditions.

**Triage Evidence**:
A successful, attributable observation from the current investigation. A
failed or unavailable check is a limitation, not negative evidence.
_Avoid_: Scanner output, assumption

**Limitation**:
The boundary of what an observation can establish.

**Reachability**:
The degree to which current evidence connects a mechanism to a deployed path.
It describes the observed deployment, not a possible future configuration.

**Confirmed Reachability**:
Current evidence supports every known precondition through an observed deployed
path.

**Plausible Reachability**:
An observed deployed path supports the mechanism, but one required link cannot
be checked directly and no evidence contradicts it.

**Reachability Not Found**:
The mechanism and relevant deployed paths were checked, but no observed path
satisfied the preconditions within the stated limitations.

**Unknown Reachability**:
The mechanism or deployed path could not be checked well enough to classify.
Unknown does not mean safe or exposed.

**Patched Artifact**:
A verified replacement for the affected running artifact. A fixed dependency release,
source commit, or image label is only a lead until it forms a deployable replacement.

**Operational Decision**:
The current response justified by reachability, impact, limitations, and the
availability of a replacement.

**Targeted Check**:
One bounded observation whose result could change the operational decision.
_Avoid_: Generic follow-up work

## Investigation and alert

The investigation retains separate advisory/package groups and runtime paths.
A container identity is distinct from its image identity: several containers may
share immutable binary analysis while their configuration and input paths differ.
Source occurrence counts remain unchanged when an occurrence maps to several
containers. Incomplete scanner input bounds every conclusion about coverage.

An alert is scoped to the installation that was scanned. A second installation
of the same program needs its own binary and configuration checks. Host OS
package scans do not cover embedded Go dependencies; native Go coverage exists
only for explicitly scanned executables. No alert from another host or service
is not evidence that it is unaffected. A container name identifies a location,
not necessarily the component that contains the affected code.

An empty fixed-version field means the scanner lists no published fix. It does
not reduce the importance of detection or justify waiting without considering
exposure controls. Scanner coverage describes explicit artifacts on one host;
the presence of coverage metadata never implies that other hosts, native
language runtimes, mounted container files, or writable layers were checked.

An observation receipt identifies the operation, runtime/artifact identity,
observation time, success state, result completeness, and limitations. Cite its
ID. Failed, stale, incomplete, or unsupported observations cannot establish
absence. An empty successful observation is different from a failed command.

For each path, explain the material preconditions and mark them supported,
contradicted, or unresolved. Attach successful deployed observations to supported
and contradicted conditions; retain exact unresolved facts as limitations.
The record contains concise causal explanations, not private model reasoning.

The alert presents the decision, its concise causal rationale, and the action.
Write rationale in at most 45 words, including the uncertainty that matters to
the decision. Retain complete technical conditions, failed operations, and
qualifications in the evidence record; do not turn the alert into a tool log.
A short alert does not limit investigation depth. Ordinary maintenance can be
justified by observed operation and impact without proving all hypothetical
attacks impossible. An unresolved question is not evidence of urgent danger.
# Deployment coverage and bounded defense

Use `fleet_deployment_coverage` to correlate an advisory across every system,
including native applications, the controller, and the external LXCs. A label
such as NeroCD identifies an installation; it does not limit the vulnerable
component to that application. Keep the two Caddy installations and their
exposure assessments separate. Missing, failed, stale, and unsupported coverage
remain unknown. Use `deployment_coverage` for the current target's detailed
scan requirements and gaps. Installed dependency matches do not establish an
exploitable route. Declared upstream versions are not runtime observations.

`prepare_defensive_action` and `execute_defensive_action` accept named actions
from root-owned policy only. The initial policy is disabled and empty. Never
invent an action, candidate verification, or recovery receipt to make a gate
pass. Do not edit policy or receipts. Report the concrete blockers when a change
is ineligible. Keep operator alerts short and retain detailed evidence in the
investigation record. Recovery after an interrupted or expired action is handled
by a separate host timer.
