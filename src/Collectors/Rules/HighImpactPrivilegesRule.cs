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
    /// Purpose:
    /// - Surface processes whose *effective token* carries privileges that materially expand the attack surface
    ///   (lateral influence, security boundary weakening, credential theft pathways, privileged resource access).
    ///
    /// Design principles:
    /// - Fact-driven: reports privileges observed on the token.
    /// - Conservative: excludes low-signal privileges commonly present on most user tokens (e.g., SeChangeNotifyPrivilege).
    /// - Avoids role claims: does not claim exploitation, only flags high-value review targets.
    ///
    /// Notes:
    /// - Many privileges are only meaningful when *enabled* (or enabled-by-default).
    /// - Some environments legitimately run with these privileges; this rule is for triage and research guidance.
    /// </summary>
    internal sealed class HighImpactPrivilegesRule : IProcessRule
    {
        public string RuleId => "PTTBM.PRIV.001";
        public string Title => "High-impact token privileges present";
        public FindingCategory Category => FindingCategory.Privileges;
        public FindingSeverity BaselineSeverity => FindingSeverity.Medium;

        // High impact when present+enabled: historically correlated with powerful primitives.
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

        // Significant privileges: can enable sensitive read/write actions or boundary manipulation.
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

            // If privileges are not observable, we do not emit a finding.
            // Another rule may handle "visibility boundaries" separately if you want.
            var privs = token.Privileges;
            if (privs is null || privs.Count == 0)
                yield break;

            // Collect high-impact privileges found on the token, with best-effort "enabled" semantics.
            var matches = new List<PrivMatch>(capacity: 8);
            foreach (var p in privs)
            {
                var name = GetPrivilegeName(p);
                if (string.IsNullOrWhiteSpace(name))
                    continue;

                if (!CriticalPrivileges.Contains(name) && !SignificantPrivileges.Contains(name))
                    continue;

                var state = GetPrivilegeState(p);
                var tier = CriticalPrivileges.Contains(name) ? PrivTier.Critical : PrivTier.Significant;

                matches.Add(new PrivMatch(name, tier, state));
            }

            if (matches.Count == 0)
                yield break;

            // Severity is based on:
            // - privilege tier (critical vs significant)
            // - whether any critical privilege is enabled (or enabled-by-default)
            // - whether the process is already high trust (SYSTEM/High IL) or is medium/limited (research interest differs)
            var severity = ComputeSeverity(token, matches);

            // Evidence: compact, stable, useful for diffing.
            var evidence = BuildEvidence(s, matches);

            // Recommendation: precise, non-alarmist, focuses on realistic investigation.
            var recommendation = BuildRecommendation(s, matches);

            var tags = new List<string>
            {
                "high-impact-privilege"
            };

            // Keep this rule facts-only: no related PID correlation here.
            var relatedPids = Array.Empty<int>();

            var conceptRefs = new List<string>
            {
                "docs/concepts/tokens-and-privileges.md"
            };

            var nextSteps = new List<InvestigationStep>
            {
                new(
                    "Validate necessity",
                    "Confirm the privilege is required for the process role. If not, reduce privileges (service hardening, token filtering, least privilege) or move the action into a constrained helper."
                ),
                new(
                    "Check enablement paths",
                    "Determine whether the privilege is enabled by default, enabled dynamically, or only enabled during specific operations. Review the code paths that call AdjustTokenPrivileges and their input validation."
                ),
                new(
                    "Assess reachable inputs",
                    "Identify inputs the process consumes (IPC, files, registry, network, plugins/extensions). High-impact privileges raise the consequence of parsing/validation bugs in these surfaces."
                )
            };

            yield return FindingFactory.Create(
                rule: this,
                snapshot: s,
                severity: severity,
                titleSuffix: BuildTitleSuffix(matches),
                evidence: evidence,
                recommendation: recommendation,
                tags: tags,
                relatedPids: relatedPids,
                conceptRefs: conceptRefs,
                nextSteps: nextSteps
            );
        }

        // =========================
        // Severity model (conservative, explainable)
        // =========================

        private static FindingSeverity ComputeSeverity(TokenInfo token, List<PrivMatch> matches)
        {
            // Enabled critical privileges are the strongest signal.
            bool enabledCritical = matches.Any(m => m.Tier == PrivTier.Critical && m.State.IsEnabledByDefault);

            // Enabled significant privileges are meaningful but less direct than critical ones.
            bool enabledSignificant = matches.Any(m => m.Tier == PrivTier.Significant && m.State.IsEnabledByDefault);

            // If the token is SYSTEM or High IL, privilege presence may be expected for some components,
            // but it still expands blast radius. Keep High only when critical privileges are enabled.
            if (token.IntegrityLevel == IntegrityLevel.System || token.IntegrityLevel == IntegrityLevel.High)
            {
                if (enabledCritical) return FindingSeverity.High;
                if (enabledSignificant) return FindingSeverity.Medium;
                return FindingSeverity.Low;
            }

            // For Medium IL processes, enabled critical privileges are particularly interesting (unexpected in many user apps).
            if (token.IntegrityLevel == IntegrityLevel.Medium)
            {
                if (enabledCritical) return FindingSeverity.High;
                if (enabledSignificant) return FindingSeverity.Medium;
                return FindingSeverity.Low;
            }

            // For Low IL processes, high-impact privileges should be rare; treat any match as high review priority.
            if (token.IntegrityLevel == IntegrityLevel.Low)
            {
                return enabledCritical || enabledSignificant ? FindingSeverity.High : FindingSeverity.Medium;
            }

            // Unknown integrity: default to Medium if we found critical, else Low.
            return matches.Any(m => m.Tier == PrivTier.Critical) ? FindingSeverity.Medium : FindingSeverity.Low;
        }

        private static string BuildTitleSuffix(List<PrivMatch> matches)
        {
            var crit = matches.Count(m => m.Tier == PrivTier.Critical);
            var sig = matches.Count(m => m.Tier == PrivTier.Significant);

            if (crit > 0 && sig > 0) return $"{crit} critical, {sig} significant";
            if (crit > 0) return $"{crit} critical";
            return $"{sig} significant";
        }

        // =========================
        // Evidence / Recommendation
        // =========================

        private static string BuildEvidence(ProcessSnapshot s, List<PrivMatch> matches)
        {
            var t = s.Token;

            var sb = new StringBuilder(512);

            sb.Append($"IL={t.IntegrityLevel}; ");
            sb.Append($"User={RuleHelpers.Safe(t.UserName)}; ");
            sb.Append($"ElevationType={t.ElevationType}; ");
            sb.Append($"IsElevated={RuleHelpers.Safe(t.IsElevated?.ToString())}; ");
            sb.Append($"AppContainer={RuleHelpers.Safe(t.IsAppContainer?.ToString())}; ");
            sb.Append($"Restricted={RuleHelpers.Safe(t.IsRestricted?.ToString())}; ");

            // Show privilege list in a stable order: critical first, enabled first.
            var ordered = matches
                .OrderByDescending(m => m.Tier == PrivTier.Critical)
                .ThenByDescending(m => m.State.IsEnabledByDefault)
                .ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            sb.Append("Privs=[");
            sb.Append(string.Join(", ",
                ordered.Select(m => $"{m.Name}:{m.State.ShortLabel}")));
            sb.Append("]");

            return sb.ToString();
        }

        private static string BuildRecommendation(ProcessSnapshot s, List<PrivMatch> matches)
        {
            var t = s.Token;

            var sb = new StringBuilder(2048);

            sb.AppendLine("High-impact privileges were observed on the process token.");
            sb.AppendLine("Token privileges materially affect what the process can do once code execution is achieved (by a bug, plugin abuse, IPC misuse, or other control-flow capture).");
            sb.AppendLine();

            sb.AppendLine("Why this matters (security semantics):");
            sb.AppendLine("- Privileges are distinct from group membership and can grant powerful OS capabilities even at Medium integrity.");
            sb.AppendLine("- If a process exposes reachable inputs (IPC, files, extensions, network parsing), high-impact privileges amplify the impact of any memory-safety or logic bug.");
            sb.AppendLine("- Some privilege-driven actions bypass typical discretionary access expectations (e.g., backup/restore semantics).");
            sb.AppendLine();

            sb.AppendLine("Observed privileges (best-effort state):");
            foreach (var grp in matches
                .OrderByDescending(m => m.Tier == PrivTier.Critical)
                .ThenByDescending(m => m.State.IsEnabledByDefault)
                .ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase))
            {
                sb.AppendLine($"- {grp.Name} ({grp.Tier}, {grp.State.LongLabel})");
            }

            sb.AppendLine();
            sb.AppendLine("Investigation guidance (practical):");
            sb.AppendLine("1) Confirm necessity: verify the process truly needs these privileges for its role. If not, remove or scope them.");
            sb.AppendLine("2) Determine enablement: check whether the privilege is enabled by default or toggled dynamically (AdjustTokenPrivileges).");
            sb.AppendLine("3) Map reachable inputs: enumerate IPC endpoints and parsing surfaces. Prioritize review/fuzzing where untrusted input intersects privileged operations.");
            sb.AppendLine("4) Look for misuse patterns: authorization bypass, path canonicalization errors, object namespace confusion, and TOCTOU races around privileged file/registry operations.");
            sb.AppendLine();

            // Provide concise mapping notes for the most important privileges present.
            var critical = matches.Where(m => m.Tier == PrivTier.Critical).Select(m => m.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var significant = matches.Where(m => m.Tier == PrivTier.Significant).Select(m => m.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (critical.Count > 0 || significant.Count > 0)
            {
                sb.AppendLine("Privilege notes (what to look for):");

                if (critical.Contains("SeImpersonatePrivilege"))
                {
                    sb.AppendLine("- SeImpersonatePrivilege: raises the value of impersonation paths (named pipe/RPC/COM impersonation). Review any server-side impersonation flows for confused-deputy bugs and improper client identity binding.");
                }
                if (critical.Contains("SeAssignPrimaryTokenPrivilege"))
                {
                    sb.AppendLine("- SeAssignPrimaryTokenPrivilege: enables assigning primary tokens to processes. Review any process creation / token management code paths and ensure strict authorization.");
                }
                if (critical.Contains("SeDebugPrivilege"))
                {
                    sb.AppendLine("- SeDebugPrivilege: can allow opening other process handles with broad access, enabling inspection/modification of sensitive processes if reachable. Validate it is not enabled unnecessarily and that related operations are locked down.");
                }
                if (critical.Contains("SeLoadDriverPrivilege"))
                {
                    sb.AppendLine("- SeLoadDriverPrivilege: driver loading is a high-impact primitive. Confirm the process cannot be influenced to load arbitrary drivers and that driver path handling is hardened.");
                }
                if (significant.Contains("SeBackupPrivilege") || significant.Contains("SeRestorePrivilege"))
                {
                    sb.AppendLine("- SeBackupPrivilege / SeRestorePrivilege: can bypass typical file ACL intent via backup/restore semantics. Audit any file operations that use these semantics and ensure canonicalization + TOCTOU controls.");
                }
                if (significant.Contains("SeTakeOwnershipPrivilege"))
                {
                    sb.AppendLine("- SeTakeOwnershipPrivilege: enables ownership takeover of securable objects. Confirm the process cannot be driven to take ownership of attacker-chosen targets.");
                }
            }

            // Include small token context to aid analysts without over-claiming.
            sb.AppendLine();
            sb.AppendLine("Token context:");
            sb.AppendLine($"- IntegrityLevel: {t.IntegrityLevel}");
            sb.AppendLine($"- ElevationType: {t.ElevationType} (IsElevated={RuleHelpers.Safe(t.IsElevated?.ToString())})");
            sb.AppendLine($"- AppContainer: {RuleHelpers.Safe(t.IsAppContainer?.ToString())}, Restricted: {RuleHelpers.Safe(t.IsRestricted?.ToString())}");

            return sb.ToString().TrimEnd();
        }

        // =========================
        // Privilege extraction helpers (robust to model changes)
        // =========================

        private static string? GetPrivilegeName(TokenPrivilegeInfo p)
        {
            // Your model likely exposes Name, but this keeps the rule resilient if you refactor later.
            try
            {
                return p.Name;
            }
            catch
            {
                return null;
            }
        }

        private static PrivState GetPrivilegeState(TokenPrivilegeInfo p)
        {
            return new PrivState(
                IsEnabled: p.IsEnabled,
                IsEnabledByDefault: p.IsEnabledByDefault,
                IsRemoved: p.IsRemoved
            );
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
            bool IsRemoved)
        {
            public bool IsEffectivelyEnabled => IsEnabled || IsEnabledByDefault;

            public string ShortLabel =>
                IsEnabled ? "enabled" :
                IsEnabledByDefault ? "default" :
                IsRemoved ? "removed" :
                "present";

            public string LongLabel =>
                IsEnabled ? "enabled" :
                IsEnabledByDefault ? "enabled by default (but not currently enabled)" :
                IsRemoved ? "removed from token" :
                "present (not enabled)";
        }
    }
}
