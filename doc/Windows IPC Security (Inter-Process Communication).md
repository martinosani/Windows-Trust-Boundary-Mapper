# Windows IPC Security (Inter-Process Communication)

This document explains **Windows Inter-Process Communication (IPC)** from a **Windows Internals and security research** perspective.

The goal is not to catalog APIs, but to provide a **mental and analytical framework** for understanding **where trust boundaries actually exist**, how OS and application components cross them, and why IPC is one of the most common roots of real-world Windows vulnerabilities.

In PTTBM, IPC is treated as a **first-class trust-boundary surface**.  
Where IPC reachability/consumption is not evaluated, this is explicitly treated as a **visibility boundary**, not as evidence that the surface does not exist.

---

## 1. Why IPC matters for Windows security

IPC is where Windows security architecture becomes concrete.

At a high level, most modern Windows systems are built around the idea that:
- **low-trust components exist**
- **high-trust components exist**
- lower-trust code must request higher-trust work indirectly

IPC is the mechanism that makes this delegation possible.

As a result, IPC is where:
- sandbox boundaries are enforced (or fail),
- privilege separation succeeds or collapses,
- confused-deputy vulnerabilities emerge,
- local privilege escalation chains are built.

Many severe Windows vulnerabilities are not about memory corruption in isolation, but about **high-trust code acting on lower-trust input**.

---

## 2. IPC as a trust-boundary surface

### IPC is not just “communication”

Every IPC endpoint implicitly answers security questions:

- Who is allowed to reach this endpoint?
- Under what identity does the server execute?
- What privileged actions can the server perform?
- How does the server authenticate and authorize the caller?
- How does the server validate the request (paths, object names, parameters)?
- Does the server re-validate at the use site to prevent TOCTOU?

From a security perspective, an IPC interface is an **API boundary with authority behind it**.

If the authority of the server exceeds the trust of the caller, the IPC boundary becomes a **privilege boundary**.

---

### Trust transitions commonly mediated by IPC

Real-world Windows designs frequently rely on IPC to cross these boundaries:

- **Low Integrity → Medium Integrity** (browser sandboxes, renderers)
- **Medium Integrity → High Integrity** (UAC helpers, elevated components)
- **Medium/High Integrity → SYSTEM** (services)
- **AppContainer → broker** (capability-mediated access)
- **Unprivileged user → service account**

In vulnerability research, these transitions matter more than absolute privilege levels.

---

## 3. IPC risk model: Reachability × Authority

IPC risk can be modeled as the combination of two dimensions.

### 3.1 Reachability

Can a lower-trust subject reach the IPC endpoint at all?

Determined by:
- object DACLs,
- COM/RPC permissions,
- session boundaries,
- integrity level enforcement (MIC/UIPI),
- AppContainer capability checks,
- and “who can open or connect” semantics.

If the endpoint is not reachable, it is not part of that boundary.

### 3.2 Authority

What happens if the endpoint is reached?

Authority is defined by:
- server token (integrity, elevation, privileges),
- impersonation semantics (whether the server acts as itself or as the client),
- and the operations performed on behalf of the caller.

High authority combined with reachability creates high-risk surfaces.

---

## 4. Explicit IPC mechanisms (security-oriented view)

This section focuses on **how IPC mechanisms fail**, not just how they work.

---

### 4.1 Named Pipes

#### What they are
Named pipes are kernel-managed IPC objects that implement a client/server byte-stream or message-based communication model.  
They are exposed through the Windows object namespace (e.g. `\\.\pipe\Name`) and support multiple clients connecting to a single server endpoint.

Named pipes are widely used for **local IPC**, not for networking, and are a foundational building block for many broker and service architectures.

#### Why they matter
They are widely used by:
- Windows services
- security software
- update agents
- enterprise applications
- sandbox brokers

Named pipes are one of the most common **practical** privilege boundaries in Windows userland software.

#### Security properties that matter
- **Pipe object DACL** (who can connect)
- **Impersonation behavior (server-side)** and impersonation level
- **Authorization model** (explicit checks before privileged operations)
- **Protocol design** and parsing correctness
- **Object namespace usage** (global vs session-local; `Global\*` patterns)
- **Instance and lifetime handling** (DoS and race opportunities)

#### Common failure modes
- Pipe connectable by lower-trust callers than intended (overly permissive DACL)
- Server impersonates client but performs actions incorrectly (confused deputy)
- Client-controlled paths/object names used without canonicalization
- Identity not bound to intent (authorization missing or incomplete)
- “Local-only” treated as equivalent to “trusted”
- Pipe squatting / pre-creation patterns (less common, but relevant in named-object contexts)

**Named pipes are one of the most common roots of confused-deputy LPEs.**

---

### 4.2 RPC (Remote Procedure Call)

#### What it is
RPC provides structured request/response IPC, heavily used by Windows itself.  
It provides interface-based calls with marshalling, authentication, and multiple transports (often ALPC locally).

#### Why it matters
Many SYSTEM services and privileged helpers expose RPC endpoints.  
RPC often represents the “official” call surface for privileged operations.

#### Security properties that matter
- **Authentication level** (who is authenticated, and with what guarantees)
- **Authorization checks per method** (not just endpoint-level)
- **Identity binding between caller and request** (authorization must match actual caller)
- **Marshalling/unmarshalling correctness** and structure complexity risk
- **Legacy endpoints / compatibility paths** that keep weak semantics alive

#### Common failure modes
- Methods callable without adequate authorization
- Incorrect assumptions about caller identity (or caller identity persistence across calls)
- Parameter smuggling through optional/nested structures
- Legacy endpoints with overly broad access
- “Authenticated” treated as “authorized”
- Dangerous privileged actions reachable through innocuous-looking methods

RPC vulnerabilities often look benign in code, but catastrophic in effect.

---

### 4.3 COM / DCOM

#### What it is
COM is an object activation and invocation system built on top of RPC.  
It supports:
- in-proc servers (DLL),
- out-of-proc servers (EXE),
- service-hosted COM servers,
and relies heavily on registry configuration.

#### Why it matters
Many brokers and automation components are COM servers.  
COM therefore frequently forms a **cross-integrity or cross-UAC boundary**, especially in desktop software and enterprise environments.

#### Security properties that matter
- **Launch and access permissions**
- **Server identity** (user, elevated, SYSTEM)
- **Activation model** (in-proc vs out-of-proc; affects isolation and trust)
- **Registry-based configuration** (security descriptors and class registration)
- **Caller identity semantics** (what identity the server sees, and how it uses it)

#### Common failure modes
- Privileged COM servers callable by low-trust callers
- Misconfigured activation permissions (too broad)
- Incorrect trust assumptions in broker-like COM servers
- “Same user” treated as “same trust” (ignores IL/UAC boundaries)
- Registry-based configuration misuse leading to redirection/hijack behaviors

COM-related issues are often **design** bugs rather than implementation bugs.

---

### 4.4 Shared Memory / Sections

#### What they are
Memory regions mapped into multiple processes via section objects (file mappings).  
Often used for performance-critical IPC and shared state.

#### Why they matter
Used for performance-critical IPC in:
- browsers
- antivirus engines
- graphics subsystems

Shared memory becomes dangerous when:
- a lower-trust process can write,
- and a higher-trust process consumes that data as trusted input.

#### Security properties that matter
- Who can write to the shared memory (DACL and handle inheritance)
- How data is validated before use (structure integrity, bounds, invariants)
- Lifetime and synchronization semantics (ownership, locking, versioning)
- Concurrency assumptions (race behavior often becomes the bug)

#### Common failure modes
- Writable shared memory consumed as trusted input
- Structure confusion or version mismatches
- Race conditions amplified by shared state
- Partial validation (only header checked, body trusted)
- Shared-memory “signals” treated as authorization

Shared memory is rarely the root cause alone, but often a force multiplier.

---

### 4.5 UI-based IPC (Windows messages, UIPI)

#### What it is
GUI processes communicate via window messages and related UI mechanisms (handles, message loops, accessibility interactions).

#### Why it matters
Historically a rich attack surface (“shatter attacks”) where low-privilege senders could manipulate privileged GUI processes.

#### Modern constraints
- Mandatory Integrity Control (MIC)
- User Interface Privilege Isolation (UIPI)

These mechanisms reduce cross-trust message flows significantly.

#### Remaining risks
- UIAccess tokens (deliberate bypass of UIPI constraints)
- Allowed message types with unsafe handlers
- Indirect UI-to-privileged execution flows (UI triggers privileged actions)
- Accessibility frameworks and privileged UI bridges
- Legacy UI components that still assume “local UI = trusted”

UI IPC is less common today, but still relevant in specific contexts.

---

## 5. Indirect IPC and Delegation Channels

Windows IPC is not limited to explicit transports (pipes/RPC/COM). Many real-world privilege boundaries are crossed through **indirect delegation channels**, where a lower-trust component influences a higher-trust component by writing state into a shared substrate.

These channels are especially important in vulnerability research because they frequently produce:
- **confused-deputy** conditions,
- **canonicalization** mistakes,
- **TOCTOU** races,
- and **object squatting** attacks.

The key mental model is identical to classic IPC:

> A lower-trust actor supplies data; a higher-trust actor consumes it and performs privileged work.

---

### 5.1 Filesystem-based Handoff

#### What it is
Filesystem-based handoff happens when one component writes a file (or a path) and another component later reads, parses, moves, or executes it. This can be intentional (a staging directory) or accidental (a cache, temp file, or log file used as input).

This is effectively IPC because the filesystem becomes the transport layer.

#### Why it matters for security
Filesystem handoff is a high-value vulnerability class because it intersects directly with privileged operations:
- writing into protected locations,
- replacing binaries/configuration read by privileged services,
- loading libraries/plugins,
- updating software,
- scheduled tasks and helper executables.

Even when the consumer process is not “exploited” in the classic sense, **unsafe file consumption** can yield privileged behavior.

#### Common insecure patterns
1) Writable staging locations used by higher-trust consumers  
   Examples: `C:\Temp`, `%TEMP%`, `%LOCALAPPDATA%`, `%APPDATA%`, `%ProgramData%` (depending on permissions)

2) Path canonicalization mismatches  
   String form vs actual target mismatch (`\\?\`, short/long paths, UNC normalization)

3) TOCTOU (Time-of-check to time-of-use)  
   Check happens before use; attacker switches target in the gap

4) Reparse point / junction / symlink / mount point abuse  
   Privileged process follows reparse points into unintended targets

5) Hardlink abuse  
   Privileged writer overwrites protected file through attacker-controlled link

6) Unsafe DLL/plugin loading from user-writable locations  
   Plugin/search paths including user-writable folders; config-driven load without allowlisting

#### Practical research workflow
1) Identify all file inputs the high-trust component consumes (configs, caches, assets, update packages, plugins, temp artifacts)
2) Determine origin: can a lower-trust process write them?
3) Validate enforcement at use sites: canonicalize and re-check permissions
4) Look for race windows: creation then privileged action is a classic TOCTOU structure
5) Pay attention to token context: backup/restore semantics can bypass typical DACL expectations

#### How this maps to token/trust signals
Filesystem handoff becomes especially interesting when the consumer runs with:
- High/System integrity
- elevation semantics (`ElevationType=Full`)
- high-impact privileges (`SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeManageVolumePrivilege`)
- broker/service identity signals (SYSTEM/service accounts)

These signals do not prove a bug, but sharply increase the value of investigating file-based inputs.

---

### 5.2 Registry-based Handoff

#### What it is
Registry-based handoff occurs when a lower-trust component writes data to a registry key and a higher-trust component later reads and acts on it.

This is common because the registry is globally accessible (within ACL constraints), persistent, and used heavily for configuration and activation.

#### Why it matters for security
Registry handoffs frequently show up in:
- COM activation and configuration
- file/protocol handlers
- per-user configuration consumed by elevated helpers
- “recent file / last used path” state crossing trust boundaries

Registry issues are often logic/design vulnerabilities, not memory-safety bugs.

#### Common insecure patterns
1) HKCU data trusted by elevated/System components (“same user” ≠ “same trust”)
2) COM-related hijack primitives via mis-scoped write permissions
3) Handler/shell integration misuse (open commands / protocol handlers)
4) Policy/config injection (assumes registry is admin-only)
5) Registry pointing to filesystem targets (registry + filesystem TOCTOU chains)

#### Practical research workflow
1) Identify keys/hives read by the target (HKLM vs HKCU matters; ACLs matter more)
2) Determine effective write access
3) Track how values are used (paths, command lines, DLL names, CLSIDs, endpoints)
4) Validate canonicalization and use-site re-validation

#### How this maps to token/trust signals
Registry handoff becomes high-value when you see:
- High/System IL processes that are interactive or broker-like
- UAC boundary markers (elevation type, linked token)
- COM usage likelihood
- components acting on behalf of other processes

Registry is often a control plane: writable control plane + privileged consumer = attack surface.

---

### 5.3 Named Object Namespace Abuse

#### What it is
Windows exposes a kernel object namespace used by IPC primitives and coordination:
- Mutexes, Events, Semaphores
- Section objects (shared memory)
- Named pipes (as objects)
- ALPC ports (advanced)

Objects may exist in namespaces such as:
- `Global\...`
- `Local\...`
- `\BaseNamedObjects\...`

This becomes a delegation channel when a higher-trust process assumes:
- a name is unique,
- an existing object is trusted,
- or DACLs are safe by default.

#### Why it matters for security
Named objects frequently become boundary failures because:
- names can be pre-created (“squatted”),
- ACLs can be weak or misapplied,
- global/session namespaces create unintended reachability,
- synchronization/state objects are treated as authenticity signals.

#### Common insecure patterns
1) Object squatting / pre-creation  
   Attacker creates expected object before privileged component; privileged component opens attacker-controlled object.

2) Weak DACL on named objects  
   Low-trust callers can signal events, write shared memory, or disrupt coordination.

3) Cross-session surprises  
   `Global\*` objects visible across sessions; assumptions about isolation break.

4) Confused coordination between components  
   Low-trust side controls synchronization or state consumed by high-trust side.

5) Shared memory poisoning  
   High-trust consumer reads shared memory as trusted and performs privileged work.

#### Practical research workflow
1) Identify named objects used by the target (runtime observation, strings, docs)
2) Check create/open semantics and DACL correctness
3) Assess namespace scope (Global vs session-local)
4) Look for privileged follow-on actions driven by object state/data

#### How this maps to token/trust signals
This class becomes a strong hypothesis when:
- high-trust processes coordinate with lower-trust peers (broker models),
- session boundaries differ (services vs interactive),
- shared memory/synchronization is likely,
- privileges imply high-impact actions if misled.

---

## 6. The confused deputy problem (central failure class)

Most IPC-related vulnerabilities are confused-deputy failures:

- a high-trust component accepts input from a lower-trust caller,
- then performs privileged actions based on that input,
- without correctly binding authorization to identity and intent.

Common patterns:
- incorrect impersonation usage,
- path traversal and TOCTOU issues,
- identity vs privilege confusion (UAC),
- “same user” treated as “same trust”.

This is primarily a logic failure, not an IPC failure.

---

## 7. IPC in sandbox and broker architectures

Modern Windows security relies heavily on broker designs:

1) Low-trust component requests an operation
2) Broker validates identity/capability and parameters
3) Broker performs the operation with higher authority

The broker is therefore the **true security boundary**.

If broker validation fails, the sandbox fails.

---

## 8. IPC enumeration in tooling (PTTBM perspective)

A mapper tool cannot “solve IPC”, but it can build evidence.

### Feasible enrichment steps
- Enumerate named pipe namespaces
- Identify IPC-related modules (RPC/COM indicators)
- Correlate processes by session, logon, and ancestry
- Detect likely broker neighborhoods

### Advanced steps (future)
- Map pipes to owning processes
- Enumerate active RPC endpoints
- Enumerate active COM servers
- ETW-based runtime surface discovery

Each step increases **confidence**, not certainty.

---

## 9. Confidence and visibility boundaries

Without direct reachability validation:
- IPC findings are hypotheses,
- confidence must be explicit,
- assumptions must be documented.

This honesty is critical for research credibility.

---

## 10. Key takeaway

IPC is where **authority meets reachability**.

- Tokens describe *what a process can do*
- IPC determines *who can ask it to do it*

Most Windows vulnerabilities arise when higher-trust components act on lower-trust input across IPC boundaries without correct validation.

Understanding IPC is therefore essential for:
- sandbox escape research,
- local privilege escalation research,
- trust-boundary analysis.

PTTBM treats IPC not as an implementation detail, but as the **core substrate of Windows security design**.
