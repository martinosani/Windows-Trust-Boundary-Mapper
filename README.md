# WTBM – Windows Trust Boundary Mapper

## Overview

WTBM is a small command-line tool I am building as part of my study of Windows internals.  
The goal is practical learning: understanding how Windows processes, tokens, and trust boundaries are represented and how they can be inspected from user space.

The current focus of the tool is process enumeration and basic authority classification. By collecting token-related information, WTBM makes it possible to identify processes running with higher authority and to observe how that authority is expressed through the Windows security model. This is treated as a foundational step rather than a complete analysis.

The project is structured to grow incrementally. Future stages are expected to build on the process-level view, using high-authority processes as reference points to study how lower-integrity or lower-privileged processes may interact with them, and where meaningful trust boundaries exist. These extensions are not the focus of the current implementation, but they inform the direction of the work.

WTBM is intentionally simple, exploratory, and work in progress. This repository documents the behavior of the tool as it exists today, with changes reflecting ongoing study and experimentation rather than a finished design.

---

## Command syntax

WTBM.exe process [options]

---

## Command: process

### Purpose

Enumerate Windows processes and optionally evaluate rule sets against their token-related properties.

### Behavior

When invoked, the command:

1. Enumerates running Windows processes.
2. Collects security token information for each process.
3. Builds in-memory process snapshots.
4. Optionally prints a flat enumeration summary.
5. Optionally evaluates rule sets against the collected snapshots.
6. Optionally explains the first rule finding.

All operations are executed locally and synchronously.

---

## Options

### --enumeration

Type: boolean  
Default: false  

Enumerates processes and associated token information and prints a flat summary list.

If --top is provided and greater than zero, only the first N snapshots are printed.

---

### --rule, -r

Type: string  
Default: empty / not set  

Selects which rule set to execute against the collected process snapshots.

If the value is empty or not provided, rule evaluation is skipped.  
If provided, rules are created using the selection string and evaluated against all collected snapshots.

---

### --process-pid, -pid

Type: integer  
Default: -1  

Restricts enumeration and rule evaluation to a specific process ID.

If the PID is not found, execution fails with an error.

---

### --rule-explain

Type: boolean  
Default: false  

Prints a detailed explanation for each rule finding associated with the process specified via `--process-pid`.

This option is intended to be used only when a specific process is selected using `--process-pid`.  
If no process PID is provided, rule explanations are not produced.

When enabled, the tool iterates over all rule findings generated for the selected process and prints an explanation for each of them, based on the collected process snapshots.

---

### --top

Type: integer (nullable)  
Default: not set  

Limits the number of process snapshots printed during enumeration.

This option is effective only when used together with `--enumeration`.  
If `--enumeration` is not specified, this option has no effect.

---

### --pause

Type: boolean  
Default: false  

Enable the interactive pause at the end of execution.

---

## Execution flow

1. Enumerate all running Windows processes.
2. If `--process-pid` is specified, restrict the analysis to the selected process.
3. Collect token-related information and build process snapshots.
4. If `--enumeration` is enabled, print a summary of the collected snapshots.
5. If rule evaluation is enabled, evaluate the selected rules against the process snapshots.
6. If `--rule-explain` is enabled and a process was selected, print an explanation for each rule finding associated with that process.
7. If `--no-pause` is not specified, wait for user input before exiting.

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

Evaluate rules across all processes:
```
WTBM.exe process --rule HighImpactPrivilegeProcesses
```

Evaluate rules for a specific process and explain all findings:
```
WTBM.exe process --process-pid 1234 --rule HighImpactPrivilegeProcesses --rule-explain
```