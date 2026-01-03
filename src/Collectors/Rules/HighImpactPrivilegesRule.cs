using System;
using System.Collections.Generic;
using System.Text;
using PTTBM.Models;
using PTTBM.Models.Rules;

namespace PTTBM.Collectors.Rules
{
    /// <summary>
    /// PTTBM.PRIV.001
    ///
    /// High-impact token privileges marker.
    ///
    /// Goal:
    /// - Surface processes whose effective token carries privileges that materially expand impact
    ///   once control is achieved (memory-safety bug, plugin abuse, confused deputy, IPC misuse, etc.).
    ///
    /// Design:
    /// - Fact-first: privilege presence and privilege state (Enabled / EnabledByDefault / Present / Removed)
    ///   are derived directly from token attributes.
    /// - Conservative severity: Enabled state is the primary driver.
    /// - No role claims: this is a triage/research signal, not proof of exploitability.
    /// </summary>
    ///
    /// TODO: Enrich this rule with IPC surface enumeration.
    /// Rationale:
    /// High-impact privileges (especially SeImpersonatePrivilege) increase real-world risk primarily when the process
    /// exposes reachable server-side surfaces (e.g., named pipes, RPC/COM endpoints, shared memory).
    /// Currently, severity/confidence are derived from token semantics and process context only.
    /// Future work should intersect privilege state with observed IPC endpoints to:
    ///   - reduce false positives on elevated/system host processes,
    ///   - distinguish passive privilege presence from actively reachable attack surfaces,
    ///   - prioritize processes that combine impersonation capability with external input handling.
    internal sealed class HighImpactPrivilegesRule : IProcessRule
    {
        public string RuleId => "PTTBM.PRIV.001";
        public string Title => "High-impact token privileges present";
        public FindingCategory Category => FindingCategory.Privileges;

        // Default baseline; instance severity is computed per snapshot.
        public FindingSeverity BaselineSeverity => FindingSeverity.Medium;

        // Until IPC enumeration exists, surface reachability is not evaluated.
        // We keep this explicit to avoid over-claiming and to support consistent output semantics.
        private const string SurfaceVisibilityConfidence = "Medium";
        private const string SurfaceVisibilityAssumption = "Surface not evaluated (IPC enumeration not implemented).";

        // Host processes often aggregate responsibilities and may inherit privilege sets that reflect hosted components.
        // This is not a suppression mechanism: it is a context hint to reduce misinterpretation.
        private static readonly HashSet<string> HostProcessAllowList = new(StringComparer.OrdinalIgnoreCase)
        {
            "svchost.exe",
            "taskhostw.exe",
            "dllhost.exe",
            "services.exe",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "lsass.exe",
            "smss.exe"
        };

        // "Critical" privileges: widely recognized as enabling powerful primitives when enabled.
        private static readonly HashSet<string> CriticalPrivileges = new(StringComparer.OrdinalIgnoreCase)
        {
            "SeDebugPrivilege",
            "SeTcbPrivilege",
            "SeCreateTokenPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeImpersonatePrivilege",
            "SeLoadDriverPrivilege",
            "SeSecurityPrivilege",
            "SeSystemEnvironmentPrivilege"
        };

        // "Significant" privileges: meaningful security implications; may bypass typical access intent.
        private static readonly HashSet<string> SignificantPrivileges = new(StringComparer.OrdinalIgnoreCase)
        {
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeManageVolumePrivilege",
            "SeCreateGlobalPrivilege",
            "SeRelabelPrivilege"
        };

        public IEnumerable<ProcessFinding> Evaluate(ProcessSnapshot s, RuleContext ctx)
        {
            if (s is null || ctx is null)
                yield break;

            var token = s.Token;
            var privs = token.Privileges;

            // If privileges are not observable, this rule does not emit a finding.
            if (privs is null || privs.Count == 0)
                yield break;

            var matches = CollectHighImpactPrivileges(privs);
            if (matches.Count == 0)
                yield break;

            var groups = GroupByState(matches);

            var isHostProcess = IsHostProcess(s.Process?.Name);

            // Severity is driven primarily by enabled state + context.
            // Requirement: keep Severity=High when any critical privilege is enabled.
            var severityRationale = BuildSeverityRationale(token, groups, isHostProcess);
            var severity = ComputeSeverity(token, groups, isHostProcess);

            var evidence = BuildEvidence(s, groups, isHostProcess, severityRationale);
            var recommendation = BuildRecommendation(s, groups, isHostProcess, severity, severityRationale);

            var tags = new List<string> { "high-impact-privilege" };

            // Facts-only: no correlation in this rule.
            var relatedPids = Array.Empty<int>();

            var conceptRefs = new List<string>
            {
                "docs/concepts/tokens-and-privileges.md"
            };

            var nextSteps = new List<InvestigationStep>
            {
                new(
                    "Validate necessity",
                    "Confirm the privilege set is required for the process role. If not, reduce privileges (least privilege, service hardening, token filtering) or isolate privileged operations into a constrained helper."
                ),
                new(
                    "Determine enablement behavior",
                    "Identify whether privileges are enabled by default or enabled only during specific operations (AdjustTokenPrivileges). Review those code paths and their input validation/authorization."
                ),
                new(
                    "Intersect with reachable surfaces",
                    "Map how untrusted inputs reach privileged operations (IPC endpoints, file/registry handoffs, plugins/extensions, network parsers). High-impact privileges amplify the consequences of bugs in those surfaces."
                )
            };

            // Use positional args to avoid named-parameter mismatches across refactors.
            yield return FindingFactory.Create(
                this,
                s,
                severity,
                BuildTitleSuffix(groups),
                evidence,
                recommendation,
                tags,
                relatedPids,
                conceptRefs,
                nextSteps
            );
        }

        // =========================
        // Collection / grouping
        // =========================

        private static List<PrivMatch> CollectHighImpactPrivileges(IReadOnlyList<TokenPrivilegeInfo> privs)
        {
            var matches = new List<PrivMatch>(capacity: 8);

            foreach (var p in privs)
            {
                var name = p.Name;
                if (string.IsNullOrWhiteSpace(name))
                    continue;

                if (!CriticalPrivileges.Contains(name) && !SignificantPrivileges.Contains(name))
                    continue;

                var tier = CriticalPrivileges.Contains(name) ? PrivTier.Critical : PrivTier.Significant;

                var state = new PrivState(
                    IsEnabled: p.IsEnabled,
                    IsEnabledByDefault: p.IsEnabledByDefault,
                    IsRemoved: p.IsRemoved
                );

                matches.Add(new PrivMatch(name, tier, state));
            }

            return matches;
        }

        private static PrivGroups GroupByState(List<PrivMatch> matches)
        {
            // Stable ordering: critical first, then significant; within each state, alphabetical.
            static IEnumerable<PrivMatch> Order(IEnumerable<PrivMatch> xs) =>
                xs.OrderByDescending(m => m.Tier == PrivTier.Critical)
                  .ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase);

            var enabled = Order(matches.Where(m => m.State.IsEnabled)).ToList();
            var defaultEnabled = Order(matches.Where(m => !m.State.IsEnabled && m.State.IsEnabledByDefault)).ToList();
            var removed = Order(matches.Where(m => m.State.IsRemoved)).ToList();
            var presentOnly = Order(matches.Where(m => !m.State.IsEnabled && !m.State.IsEnabledByDefault && !m.State.IsRemoved)).ToList();

            return new PrivGroups(enabled, defaultEnabled, presentOnly, removed, matches);
        }

        private static bool IsHostProcess(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName))
                return false;

            return HostProcessAllowList.Contains(processName);
        }

        // =========================
        // Severity model (context-aware, conservative)
        // =========================

        private static FindingSeverity ComputeSeverity(TokenInfo token, PrivGroups g, bool isHostProcess)
        {
            bool enabledCritical = g.Enabled.Any(m => m.Tier == PrivTier.Critical);
            bool enabledSignificant = g.Enabled.Any(m => m.Tier == PrivTier.Significant);

            bool defaultCritical = g.DefaultEnabled.Any(m => m.Tier == PrivTier.Critical);
            bool defaultSignificant = g.DefaultEnabled.Any(m => m.Tier == PrivTier.Significant);

            bool anyCriticalPresentOnly = g.PresentOnly.Any(m => m.Tier == PrivTier.Critical);
            bool anySignificantPresentOnly = g.PresentOnly.Any(m => m.Tier == PrivTier.Significant);

            // Requirement: keep Severity=High when a critical privilege is enabled.
            if (enabledCritical)
                return FindingSeverity.High;

            // Default-enabled critical privileges are meaningful (often activated frequently).
            if (defaultCritical)
                return FindingSeverity.Medium;

            // Enabled significant privileges can still be impactful.
            if (enabledSignificant)
            {
                // Context refinement (no IPC):
                // On Medium (especially Limited) this is more interesting than on High/System where many privileges are expected.
                if (token.IntegrityLevel == IntegrityLevel.Medium && token.ElevationType == TokenElevationType.Limited)
                    return FindingSeverity.Medium;

                return FindingSeverity.Medium;
            }

            // High/System: present-only privileges are frequently expected; treat as Low.
            if (token.IntegrityLevel == IntegrityLevel.High || token.IntegrityLevel == IntegrityLevel.System)
            {
                // Host processes are especially prone to privilege “surface reflection”.
                // We do not suppress; we keep Low to reduce noise unless enabled/default-enabled exists (handled above).
                if (anyCriticalPresentOnly || anySignificantPresentOnly || defaultSignificant)
                    return FindingSeverity.Low;

                return FindingSeverity.Low;
            }

            // Medium: present-only critical privileges are uncommon and worth review (Medium).
            if (token.IntegrityLevel == IntegrityLevel.Medium)
            {
                if (anyCriticalPresentOnly)
                    return FindingSeverity.Medium;

                if (anySignificantPresentOnly || defaultSignificant)
                    return FindingSeverity.Low;

                return FindingSeverity.Low;
            }

            // Low: any high-impact privilege is unusual; treat as Medium.
            if (token.IntegrityLevel == IntegrityLevel.Low)
            {
                if (anyCriticalPresentOnly || anySignificantPresentOnly || defaultSignificant)
                    return FindingSeverity.Medium;

                return FindingSeverity.Low;
            }

            // Unknown integrity: conservative default.
            if (anyCriticalPresentOnly || defaultCritical || enabledSignificant || defaultSignificant)
                return FindingSeverity.Medium;

            return FindingSeverity.Low;
        }

        private static string BuildSeverityRationale(TokenInfo token, PrivGroups g, bool isHostProcess)
        {
            // Provide a short and stable "why" for explainability.
            // This is not a proof claim; it explains the rule’s decision inputs.
            var enabledCritical = g.Enabled.Where(m => m.Tier == PrivTier.Critical).Select(m => m.Name).ToList();
            var enabledSignificant = g.Enabled.Where(m => m.Tier == PrivTier.Significant).Select(m => m.Name).ToList();

            if (enabledCritical.Count > 0)
                return $"Critical privilege enabled: {string.Join(", ", enabledCritical)}";

            if (g.DefaultEnabled.Any(m => m.Tier == PrivTier.Critical))
            {
                var names = g.DefaultEnabled.Where(m => m.Tier == PrivTier.Critical).Select(m => m.Name);
                return $"Critical privilege enabled-by-default: {string.Join(", ", names)}";
            }

            if (enabledSignificant.Count > 0)
                return $"Significant privilege enabled: {string.Join(", ", enabledSignificant)}";

            if (token.IntegrityLevel == IntegrityLevel.High || token.IntegrityLevel == IntegrityLevel.System)
            {
                if (isHostProcess)
                    return "Elevated host process with present-only privileges (expected in many configurations)";
                return "Elevated token with present-only privileges (often expected); no enabled critical privileges observed";
            }

            if (token.IntegrityLevel == IntegrityLevel.Medium)
                return "Medium integrity token with high-impact privileges present (not enabled)";

            if (token.IntegrityLevel == IntegrityLevel.Low)
                return "Low integrity token with high-impact privileges present (unusual even when not enabled)";

            return "High-impact privileges present; enablement and surface reachability not fully evaluated";
        }

        private static string BuildTitleSuffix(PrivGroups g)
        {
            int enabled = g.Enabled.Count;
            int def = g.DefaultEnabled.Count;
            int present = g.PresentOnly.Count;

            return $"enabled={enabled}, default={def}, present={present}";
        }

        // =========================
        // Evidence / recommendation
        // =========================

        private static string BuildEvidence(
            ProcessSnapshot s,
            PrivGroups g,
            bool isHostProcess,
            string severityRationale)
        {
            var t = s.Token;
            var sb = new StringBuilder(1024);

            sb.Append($"IL={t.IntegrityLevel}; ");
            sb.Append($"User={RuleHelpers.Safe(t.UserName)}; ");
            sb.Append($"ElevationType={t.ElevationType}; ");
            sb.Append($"IsElevated={RuleHelpers.Safe(t.IsElevated?.ToString())}; ");
            sb.Append($"AppContainer={RuleHelpers.Safe(t.IsAppContainer?.ToString())}; ");
            sb.Append($"Restricted={RuleHelpers.Safe(t.IsRestricted?.ToString())}; ");
            sb.Append($"HostProcess={RuleHelpers.Safe(isHostProcess.ToString())}; ");

            // Explicitly state missing surface visibility as an assumption boundary.
            sb.Append($"Confidence={SurfaceVisibilityConfidence}; ");
            sb.Append($"Assumptions={SurfaceVisibilityAssumption}; ");

            // Explainability: why severity.
            sb.Append($"Why={severityRationale}; ");

            // Evidence emphasizes enabled/default-enabled; present-only summarized.
            sb.Append("Enabled=[");
            sb.Append(string.Join(", ", g.Enabled.Select(m => m.Name)));
            sb.Append("]; ");

            sb.Append("DefaultEnabled=[");
            sb.Append(string.Join(", ", g.DefaultEnabled.Select(m => m.Name)));
            sb.Append("]; ");

            // Extra triage-friendly counts.
            var enabledCritical = g.Enabled.Count(m => m.Tier == PrivTier.Critical);
            var enabledSignificant = g.Enabled.Count(m => m.Tier == PrivTier.Significant);
            var presentCritical = g.PresentOnly.Count(m => m.Tier == PrivTier.Critical);
            var presentSignificant = g.PresentOnly.Count(m => m.Tier == PrivTier.Significant);

            sb.Append($"EnabledCritical={enabledCritical}; ");
            sb.Append($"EnabledSignificant={enabledSignificant}; ");
            sb.Append($"PresentOnlyCritical={presentCritical}; ");
            sb.Append($"PresentOnlySignificant={presentSignificant}; ");
            sb.Append($"RemovedCount={g.Removed.Count}");

            return sb.ToString();
        }

        private static string BuildRecommendation(
            ProcessSnapshot s,
            PrivGroups g,
            bool isHostProcess,
            FindingSeverity severity,
            string severityRationale)
        {
            var t = s.Token;
            var sb = new StringBuilder(2600);

            sb.AppendLine("High-impact privileges were observed on the process token.");
            sb.AppendLine("Token privileges define OS capabilities that can materially change the impact of a vulnerability or a logic flaw once control is achieved.");
            sb.AppendLine();

            sb.AppendLine("Assessment boundaries:");
            sb.AppendLine($"- Confidence: {SurfaceVisibilityConfidence} ({SurfaceVisibilityAssumption})");
            sb.AppendLine($"- Severity rationale: {severityRationale}");
            sb.AppendLine();

            sb.AppendLine("Interpretation notes:");
            sb.AppendLine("- Enabled privileges are the strongest practical signal (immediate leverage).");
            sb.AppendLine("- Present-only privileges can be expected on elevated tokens; treat them primarily as blast-radius indicators unless you can show they become enabled or are exercised by reachable code paths.");
            sb.AppendLine("- Without IPC enumeration, this rule does not validate whether untrusted callers can reach server-side entry points that make these privileges practically exploitable.");
            if (isHostProcess)
            {
                sb.AppendLine("- Host process note: this process is commonly used as a host/container for multiple components. Privilege presence may reflect hosted responsibilities; correlate to hosted modules/tasks/services before drawing conclusions.");
            }

            sb.AppendLine();
            sb.AppendLine("Observed privileges by state:");
            WriteGroup(sb, "Enabled", g.Enabled);
            WriteGroup(sb, "EnabledByDefault (but not currently enabled)", g.DefaultEnabled);
            WriteGroup(sb, "Present (not enabled)", g.PresentOnly);
            if (g.Removed.Count > 0)
                WriteGroup(sb, "Removed", g.Removed);

            sb.AppendLine();
            sb.AppendLine("Investigation guidance (practical):");
            sb.AppendLine("1) Validate necessity: confirm each enabled/default-enabled privilege is required for the component role.");
            sb.AppendLine("2) Determine activation: identify where privileges are enabled (AdjustTokenPrivileges) and what inputs influence those paths.");
            sb.AppendLine("3) Intersect with surfaces: enumerate IPC endpoints and indirect handoffs; prioritize review/fuzzing where untrusted input reaches privileged operations.");
            sb.AppendLine("4) Validate enforcement: authorization, identity binding, canonicalization, and TOCTOU-safe checks at use sites.");

            // Focus notes only for privileges that are actually enabled/default-enabled.
            var highLeverage = g.Enabled.Concat(g.DefaultEnabled).ToList();
            if (highLeverage.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("High-leverage notes (based on enabled/default-enabled privileges):");

                if (highLeverage.Any(m => m.Name.Equals("SeImpersonatePrivilege", StringComparison.OrdinalIgnoreCase)))
                {
                    sb.AppendLine("- SeImpersonatePrivilege: increases the value of server-side impersonation flows (named pipes/RPC/COM). Verify strict client identity binding and authorization before acting on caller-provided inputs. Verify whether this process acts as an IPC server (named pipes/RPC/COM). If it impersonates clients, verify it uses ImpersonateNamedPipeClient/CoImpersonateClient patterns safely and reverts impersonation, and that authorization is done before privileged action.");
                }

                if (highLeverage.Any(m => m.Name.Equals("SeDebugPrivilege", StringComparison.OrdinalIgnoreCase)))
                {
                    sb.AppendLine("- SeDebugPrivilege: enables broad process access. Validate it is not enabled unnecessarily and ensure exposed operations cannot be influenced to open/modify sensitive processes or handles.");
                }

                if (highLeverage.Any(m => m.Name.Equals("SeLoadDriverPrivilege", StringComparison.OrdinalIgnoreCase)))
                {
                    sb.AppendLine("- SeLoadDriverPrivilege: driver loading is a high-impact primitive. Ensure the process cannot be influenced to load attacker-controlled drivers or paths.");
                }

                if (highLeverage.Any(m =>
                        m.Name.Equals("SeBackupPrivilege", StringComparison.OrdinalIgnoreCase) ||
                        m.Name.Equals("SeRestorePrivilege", StringComparison.OrdinalIgnoreCase)))
                {
                    sb.AppendLine("- SeBackupPrivilege / SeRestorePrivilege: can bypass typical file ACL intent via backup/restore semantics. Harden path canonicalization and TOCTOU controls around any privileged file operations.");
                }

                if (highLeverage.Any(m => m.Name.Equals("SeTakeOwnershipPrivilege", StringComparison.OrdinalIgnoreCase)))
                {
                    sb.AppendLine("- SeTakeOwnershipPrivilege: enables ownership takeover of securable objects. Confirm the process cannot be driven to take ownership of attacker-chosen targets.");
                }
            }

            sb.AppendLine();
            sb.AppendLine("Token context:");
            sb.AppendLine($"- IntegrityLevel: {t.IntegrityLevel}");
            sb.AppendLine($"- ElevationType: {t.ElevationType} (IsElevated={RuleHelpers.Safe(t.IsElevated?.ToString())})");
            sb.AppendLine($"- AppContainer: {RuleHelpers.Safe(t.IsAppContainer?.ToString())}, Restricted: {RuleHelpers.Safe(t.IsRestricted?.ToString())}");
            sb.AppendLine($"- HostProcess: {RuleHelpers.Safe(isHostProcess.ToString())}");
            sb.AppendLine($"- ReportedSeverity: {severity}");

            return sb.ToString().TrimEnd();
        }

        private static void WriteGroup(StringBuilder sb, string title, IReadOnlyList<PrivMatch> items)
        {
            sb.AppendLine($"- {title}:");

            if (items.Count == 0)
            {
                sb.AppendLine("  - <empty>");
                return;
            }

            foreach (var m in items)
            {
                sb.AppendLine($"  - {m.Name} ({m.Tier})");
            }
        }

        // =========================
        // Internal types
        // =========================

        private enum PrivTier
        {
            Significant = 1,
            Critical = 2
        }

        private sealed record PrivMatch(
            string Name,
            PrivTier Tier,
            PrivState State);

        private sealed record PrivState(
            bool IsEnabled,
            bool IsEnabledByDefault,
            bool IsRemoved);

        private sealed record PrivGroups(
            IReadOnlyList<PrivMatch> Enabled,
            IReadOnlyList<PrivMatch> DefaultEnabled,
            IReadOnlyList<PrivMatch> PresentOnly,
            IReadOnlyList<PrivMatch> Removed,
            IReadOnlyList<PrivMatch> All);
    }
}
