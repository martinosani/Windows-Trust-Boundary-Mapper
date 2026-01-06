# WTBM – Windows Trust Boundary Mapper

## Overview

WTBM (Windows Trust Boundary Mapper) is a command-line tool developed as part of an ongoing,
hands-on study of Windows internals. The project is intentionally practical and exploratory:
the primary goal is to understand how Windows processes, security tokens, privileges, and
inter-process communication (IPC) mechanisms contribute to trust and authority boundaries
inside a Windows system.

Rather than attempting to provide a complete security assessment solution, WTBM focuses on
making these internal concepts observable from user space, using a rule-based approach that
captures and documents specific aspects of system behavior.

The tool is work in progress and evolves alongside the research itself. This repository
documents the current capabilities and the rationale behind them.

---

## Scope and intent

WTBM is designed to support:

- Exploration of Windows process authority levels and token privileges
- Identification of processes running with high-impact or system-level privileges
- Inventory of IPC surfaces (currently named pipes) exposed by high-authority processes
- Study of how trust boundaries emerge from the interaction of privileges, integrity levels,
  and object security descriptors

The output of WTBM should be treated as observational data. Findings are informational by
design and intended to guide further manual analysis and experimentation.

---

## Command syntax

```
WTBM.exe process [options]
```

---

## Command: process

### Purpose

The `process` command enumerates running Windows processes, collects token-related information,
and optionally evaluates one or more rules. Depending on the selected options, it can also
enumerate named pipes observed in the context of specific processes.

---

## Execution flow

When executed, the `process` command follows this high-level flow:

1. Enumerate all running Windows processes.
2. Optionally restrict analysis to a specific process ID.
3. Collect token and privilege information and build process snapshots.
4. Optionally enumerate named pipes observed via handle enumeration.
5. Optionally print a flat enumeration summary.
6. Evaluate selected rules against the collected data.
7. Optionally print detailed explanations for rule findings.
8. Optionally pause before exit.

All operations are local and synchronous.

---

## Options

### --enumeration

Type: boolean  
Default: false  

Enumerates processes and associated token information and named pipes (if enabled) and prints a flat summary.

The `--top` option can be used to limit the number of printed snapshots.

---

### --rule, -r

Type: string  
Default: not set  

Specifies which rule to evaluate. Multiple executions may be required to run different rules.

---

### --process-pid, -pid

Type: integer  
Default: not set  

Restricts enumeration, named pipe collection, and rule evaluation to a specific process ID.

---

### --named-pipes

Type: boolean  
Default: false  

Enables enumeration of named pipes observed through handle enumeration in the selected processes.

Named pipe enumeration is best-effort and may be partially restricted by process protection
mechanisms or access controls enforced by the operating system.

---

### --rule-explain

Type: boolean  
Default: false  

Prints a detailed explanation of the findings produced by the selected rule.

This option is only effective when `--process-pid` is specified, as explanations are scoped
to a single process.

---

### --top

Type: integer  
Default: not set  

Limits the number of process snapshots printed during enumeration.

Effective only when used together with `--enumeration`.

---

### --pause

Type: boolean  
Default: false  

Pauses execution before exit, waiting for user input.

---

## Rules

WTBM uses a rule-based model to express observations about authority and trust boundaries.
Rules do not attempt to determine exploitability; instead, they surface conditions that are
relevant for further investigation.

### PTTBM.PRIV.001 – HighImpactPrivilegeProcessesRule

This rule identifies processes that hold high-impact privileges, i.e. privileges that have
significant influence over system-wide security boundaries.

The rule helps answer questions such as:
- Which processes have privileges that materially affect system isolation?
- Which high-privilege processes are present on the system at runtime?

Findings produced by this rule are informational and process-centric.

---

### PTTBM.PRIV.002 – HighAuthorityNamedPipeInventoryRule

This rule inventories named pipes observed in high-authority processes. It builds on the
results of `PTTBM.PRIV.001` and focuses on IPC surfaces that may represent trust boundary
interfaces between processes of different authority or integrity levels.

The rule produces one informational finding per process, containing an inventory of observed
named pipes and associated security metadata.

#### Privilege requirements

`PTTBM.PRIV.002` must be executed with administrative privileges.

During execution, the tool attempts to enable the `SeDebugPrivilege` privilege in the current
process token in order to duplicate and inspect handles owned by other processes:

```csharp
using var token = NtToken.OpenProcessToken(
    NtProcess.Current,
    TokenAccessRights.AdjustPrivileges | TokenAccessRights.Query
);
token.SetPrivilege(TokenPrivilegeValue.SeDebugPrivilege, PrivilegeAttributes.Enabled);
```

Even with this privilege enabled, named pipe enumeration remains best-effort. Some processes,
such as protected or PPL processes, may still restrict handle duplication or object inspection.

---

## Examples

Enumerate processes and print a flat summary:

```
WTBM.exe process --enumeration
```

Enumerate only the first 20 process snapshots:

```
WTBM.exe process --enumeration --top 20
```

Evaluate the high-impact privilege rule across all processes:

```
WTBM.exe process --rule PTTBM.PRIV.001
```

Evaluate the high-authority named pipe inventory rule for a specific process and explain findings:

```
WTBM.exe process --rule PTTBM.PRIV.002 --process-pid <process_id> --rule-explain
```

---

## Notes

WTBM is a research-driven tool. Its structure, rules, and outputs reflect an evolving
understanding of Windows internals rather than a finalized security model. Design decisions
prioritize clarity, correctness, and traceability over completeness.
