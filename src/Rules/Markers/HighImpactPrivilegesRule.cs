using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Core;
using WTBM.Domain.Findings;
using WTBM.Domain.Processes;
using WTBM.Rules.Abstractions;
using WTBM.Rules.Engine;

namespace WTBM.Rules.Markers
{
    internal sealed class HighImpactPrivilegesRule : IRule
    {
        private static readonly HashSet<string> HighImpactPrivileges =
            new(StringComparer.OrdinalIgnoreCase)
            {
                "SeDebugPrivilege",
                "SeTcbPrivilege",
                "SeImpersonatePrivilege",
                "SeAssignPrimaryTokenPrivilege",
                "SeLoadDriverPrivilege",
                "SeRestorePrivilege",
                "SeBackupPrivilege"
            };

        public string RuleId => "PTTBM.PRIV.001";

        public string Title => "High-impact privileges assigned";

        public string Description => "Detects processes running with privileges that significantly increase local attack surface.";

        public RuleKind Kind => RuleKind.Marker;

        public FindingCategory Category => FindingCategory.Privileges;

        public IEnumerable<Finding> Evaluate(RuleContext context)
        {
            if (context is null)
                yield break;

            foreach (var snapshot in context.Snapshots)
            {
                var process = snapshot.Process;
                var token = snapshot.Token;

                if (token is null || token.Privileges is null)
                    continue;

                var enabledHighImpact = token.Privileges
                    .Where(p => p.IsEnabled && !String.IsNullOrEmpty(p.Name) && HighImpactPrivileges.Contains(p.Name))
                    .Select(p => p.Name)
                    .OrderBy(p => p)
                    .ToList();

                if (enabledHighImpact.Count == 0)
                    continue;

                var evidence =
                    $"Enabled high-impact privileges: {string.Join(", ", enabledHighImpact)}";

                yield return FindingFactory.Create(
                    rule: this,
                    severity: FindingSeverity.Info,
                    titleSuffix: string.Join(", ", enabledHighImpact),

                    subjectType: FindingSubjectType.Process,
                    subjectId: process.Pid.ToString(),
                    subjectDisplayName: process.Name,

                    evidence: evidence,
                    recommendation:
                        "Review whether all enabled privileges are strictly required. " +
                        "Excess privileges increase the impact of IPC and trust-boundary violations.",

                    tags:
                    [
                        "high-impact-privilege",
                        "authority-marker"
                    ],

                    relatedPids: Array.Empty<int>(),
                    
                    conceptRefs:
                    [
                        "Windows Access Tokens",
                        "Least Privilege",
                        "Local Privilege Escalation"
                    ],

                    nextSteps:
                    [
                        new InvestigationStep(
                            "Verify privilege necessity",
                            "Confirm whether each enabled privilege is required for the process function.")
                    ]
                );
            }

        }
    }
}