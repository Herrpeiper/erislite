# ErisLITE v1.3 Hardening Plan

## Objective

Harden ErisLITE against tampering, execution-environment manipulation, and hostile changes during defensive competition use.

## Threat Model

ErisLITE may be executed on systems where:

- Red Team has compromised a non-privileged user.
- Red Team has modified local configuration files.
- Red Team has altered environment variables.
- Red Team has placed malicious files in writable directories.
- Red Team has modified commands available through `PATH`.
- Red Team may attempt Python module or dependency hijacking.
- Red Team may gain elevated privileges and alter ErisLITE itself.

## Hardening Goals

### 1. Import Security
- Audit Python import behavior.
- Detect or mitigate module shadowing.
- Review use of `PYTHONPATH`.
- Avoid unsafe dynamic imports.
- Verify expected module locations where appropriate.

### 2. Execution Environment
- Audit `PATH` usage.
- Prefer absolute paths for privileged system commands where practical.
- Detect suspicious environment changes.
- Avoid reliance on attacker-writable working directories.

### 3. Self-Integrity
- Create a manifest of critical ErisLITE files.
- Verify hashes of critical files.
- Detect unexpected modification.
- Clearly report integrity failures.

### 4. Filesystem Hardening
- Define expected ownership and permissions.
- Detect writable program files or directories.
- Identify unsafe configuration permissions.

### 5. Privilege Handling
- Review which modules require elevated privileges.
- Avoid unnecessary root execution.
- Separate privileged actions from read-only checks where possible.

### 6. Compiled Deployment
- Evaluate Nuitka standalone builds.
- Test isolated Python execution behavior.
- Compare compiled and source-based deployments.

### 7. Hostile Environment Testing
Test ErisLITE against:

- Module shadowing
- `PYTHONPATH` poisoning
- `PATH` hijacking
- Modified config files
- Replaced internal modules
- Writable install directories
- Unexpected working directories
- Missing dependencies
- Altered system utilities

## Design Principle

ErisLITE should assume that the host it is inspecting may already be partially compromised.

The goal is not to make ErisLITE impossible to modify, but to make unauthorized changes harder to perform, easier to detect, and easier to recover from.