# ErisLITE Roadmap

> Project: ErisLITE — Linux Security Monitoring and Triage Toolkit  
> Current published baseline: v1.6.0  
> Next planned release: v1.7.0 — Competition Readiness  
> Roadmap started: November 23, 2026  
> Status: Planning; milestones and release criteria are proposed until validated.

## Mission

Prepare ErisLITE for dependable, practical use by a defensive Blue Team in the 2027 NCAE Cyber Games without expanding the core detection feature set. Prioritize accurate findings, safe operation, reliable deployment, clear analyst workflows, and reproducible testing.

**Release principle:** Stability and service preservation take precedence over additional features.

## Version strategy

| Release | Focus | Status |
| --- | --- | --- |
| v1.6.0 | Unified findings/evidence, coverage-aware assessment, integrity validation, export improvements | Published baseline |
| **v1.7.0** | **Competition hardening, reliability, deployment, and validation** | **Planned** |
| v1.8.0 | Detection expansion informed by testing and competition gaps | Deferred |
| v1.9.0 | Broader workflow and operational improvements | Tentative |

## v1.7.0 scope

### In scope

- Correct defects in existing checks, scoring, and reporting.
- Harden Rapid Response, audit logging, rollback behavior, and privilege boundaries.
- Improve detection quality, especially false-positive handling and incomplete scan visibility.
- Validate supported deployment and runtime environments, including offline operation.
- Improve operator instructions and evidence handoff using existing reporting capabilities.
- Add only narrowly scoped competition aids that reuse existing systems, subject to review:
  - **Competition sweep preset:** a deliberate selection of existing checks.
  - **Competition safe mode:** guardrails around potentially disruptive response actions.

### Out of scope / deferred

- Entirely new detection subsystems without a demonstrated critical competition gap.
- Major UI redesign or replacement of the existing CLI.
- Distributed controller, cloud dependencies, or new integrations.
- Broad automation or autonomous remediation.
- Major architectural rewrites unless required to resolve a release blocker.

## Workstreams and priorities

| ID | Priority | Workstream | Deliverable | Exit criteria |
| --- | --- | --- | --- | --- |
| EL-COMP-001 | P0 | Safe response | Competition-aware safeguards for live actions | Explicit action selection and confirmation; service-impact guardrails tested |
| EL-COMP-002 | P0 | Audit durability | Stop subsequent live actions after unrecoverable response log failure | Fault-injection tests verify failure behavior and preserved records |
| EL-COMP-003 | P0 | Quarantine recovery | Harden cron quarantine and restore sequencing | Interrupted/failed operations tested; restoration evidence verified |
| EL-COMP-004 | P1 | Sweep workflow | Competition-focused profile using existing checks | Profile scope documented; test coverage and results validated |
| EL-COMP-005 | P1 | Deception safety | Preflight checks for optional Odyssey listeners | No silent port conflicts; operator explicitly opts in |
| EL-COMP-006 | P1 | Findings accuracy | Validate severity, coverage, and prioritization | Seeded test cases have expected findings; failed scans are visible |
| EL-COMP-007 | P1 | Deployment | Document and test clean/offline installation | Repeatable installation and launch on selected Linux targets |
| EL-COMP-008 | P1 | Regression testing | Strengthen tests around critical security and response paths | CI passes; critical negative and error paths covered |
| EL-COMP-009 | P2 | Operator handoff | Quick-start guide and concise reporting workflow | Teammate can deploy, inspect, and export evidence in rehearsal |
| EL-COMP-010 | P2 | Performance | Benchmark quick/competition/full sweeps | Timing and resource usage recorded; bottlenecks triaged |

> P0 = release-blocking safety/reliability. P1 = required readiness improvements. P2 = useful enhancements if schedule permits.

## Schedule and milestones

| Window | Milestone | Expected output |
| --- | --- | --- |
| Nov 23–29, 2026 | M1 — Baseline audit and test inventory | Source audit, issue list, reproducible test baseline |
| Nov 30–Dec 13, 2026 | M2 — Critical hardening | P0 issues addressed and regression tests added |
| Dec 14–20, 2026 | M3 — Integration and deployment validation | Candidate build, install/launch checks, operator documentation |
| **Dec 21–27, 2026** | **M4 — Competition rehearsal** | **Testable candidate on isolated Linux hosts, scenario findings, benchmark records** |
| After rehearsal, before competition | M5 — Release and NCAE submission | Public tagged build, disclosed custom resources, staff approval request |
| After competition | M6 — Retrospective (secondary milestone) | Lessons learned, false-positive and operational findings, v1.8 backlog |

Dates are planning targets, not confirmed competition deadlines.

## Release acceptance criteria

The v1.7.0 candidate is ready for competition submission when all required criteria below are met:

- [ ] P0 issues are closed with regression evidence.
- [ ] Existing quick, standard, and full sweep profiles remain functional.
- [ ] Any new competition preset is tested and documented.
- [ ] Scan failures and permission gaps are reported as incomplete coverage, not clean security results.
- [ ] Live containment safeguards and audit failures are validated using isolated test systems.
- [ ] Restore/undo paths are tested where supported; irreversible actions are clearly identified.
- [ ] CI passes across the maintained Python matrix.
- [ ] Clean installation and offline execution are tested on selected Linux distributions.
- [ ] Findings can be reviewed and exported without exposing unintended sensitive information.
- [ ] The team completes at least one timed defensive rehearsal without unintended service disruption.
- [ ] Documentation reflects shipped behavior, supported environments, and known limitations.
- [ ] Public release contents and the exact submission commit/tag are recorded.

## NCAE custom-resource approval gate

The published NCAE guidance discussed for this project requires custom tools and materials to be publicly accessible and disclosed for staff approval **at least one week before the competition date**. The applicable event date and any current rule revisions must be confirmed before setting the actual submission deadline.

- Resources: <https://gitlab.com/c2-games/blueteam-resources>
- Capture the public repository URL and specific approved version/tag.
- Submit requested documentation and materials through the method specified by competition staff.
- Preserve approval correspondence and avoid unapproved competition-build changes after the approval gate.
- Confirm the individual and team eligibility requirements separately.

## Validation approach

1. **Static checks:** compilation, linting, formatting, dependency and configuration review.
2. **Automated tests:** unit and integration tests, especially failure injection, timeouts, privileges, and audit persistence.
3. **Clean environment:** install and launch on disposable Linux VMs without assuming internet access.
4. **Seeded scenarios:** test unauthorized accounts, suspicious SSH keys, persistence, unusual listeners, altered integrity targets, and blocked/partial inspections.
5. **Operational rehearsal:** timed triage, evidence handoff, explicit authorization for containment, and service-health monitoring.
6. **Post-test review:** categorize detections, missed signals, false positives, resource impact, and operator confusion.

## Risks and dependencies

| Risk | Mitigation |
| --- | --- |
| Remediation disrupts scored services | Default to observation and dry-run; require deliberate live-action approvals |
| Root-only checks fail under restricted privilege | Report coverage explicitly and document required access |
| False positives overwhelm the analyst | Use scenario-based validation and actionable ranking |
| Integrity checks lack a trusted initial baseline | Document baseline creation and limitations on already-compromised hosts |
| Offline competition network lacks dependencies | Validate installed dependencies and offline startup in advance |
| Scope creep threatens Christmas testing | Freeze major feature development for v1.7.0 |
| NCAE approval timing or rules differ | Recheck current guidance and obtain staff confirmation |

## Development and release workflow

- Development and review occur on an appropriate v1.7 development branch.
- Proposed changes must include a problem statement, implementation scope, and validation evidence.
- Git operations—including branch creation, commits, merges, tags, and pushes—remain under the maintainer's control.
- Do not mark a milestone complete solely because code was written; attach evidence from tests or a rehearsal.
- Record deferrals and lessons learned for v1.8.0 rather than silently expanding v1.7.0.

## First session checklist

- [ ] Confirm the working branch and commit match the audited v1.6.0 baseline.
- [ ] Run the existing full test suite and capture measured coverage.
- [ ] Review Rapid Response audit-write failure behavior (EL-COMP-002).
- [ ] Define acceptance tests for interruption-safe cron quarantine (EL-COMP-003).
- [ ] Select the smallest P0 fix for the first v1.7 pull request.

---

_Last updated: November 23, 2026. This roadmap is a working plan and should be revised as tests uncover new evidence._
