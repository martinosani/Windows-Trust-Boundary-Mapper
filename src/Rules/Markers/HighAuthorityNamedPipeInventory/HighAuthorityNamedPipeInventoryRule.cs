using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.CommandLine.Parsing;
using System.Diagnostics;
using System.Text;
using WTBM.Collectors.IPC;
using WTBM.Core;
using WTBM.Domain.Findings;
using WTBM.Domain.IPC;
using WTBM.Rules.Abstractions;
using WTBM.Rules.Engine;

namespace WTBM.Rules.Markers.HighAuthorityNamedPipeInventory
{
    internal sealed class HighAuthorityNamedPipeInventoryRule : IRule
    {
        public string RuleId => "PTTBM.PRIV.002";
        public string Title => "Named pipe inventory for high-authority processes";
        public string Description =>
            "Enumerates named pipes exposed by high-authority processes and reports their presence and security metadata. " +
            "This rule provides visibility into IPC surfaces without assessing cross-boundary access or exploitability.";
        public RuleKind Kind => RuleKind.Marker;
        public FindingCategory Category => FindingCategory.IPC;

        public IEnumerable<Finding> Evaluate(RuleContext context)
        {
            if (context is null)
                yield break;

            var highAuthorityFindings = context.GetRule("PTTBM.PRIV.001").Evaluate(context);
            var extractor = new NamedPipeExtractor();

            foreach (var baseFinding in highAuthorityFindings)
            {
                if (!int.TryParse(baseFinding.SubjectId, out int pid))
                    continue;

                var pipes = extractor.GetNamedPipesFromProcessHandles(pid).ToList();

                if (pipes.Count == 0)
                    continue;

                Logger.LogDebug(String.Format("[PID:{0}] Found {1} named pipes", pid, pipes.Count));

                var metrics = ComputeMetrics(pipes);

                var evidence = new NamedPipeInventoryEvidence(
                    ProcessPid: pid,
                    ProcessName: baseFinding.SubjectDisplayName,
                    Pipes: pipes,
                    Metrics: metrics
                );

                yield return FindingFactory.Create(
                    rule: this,
                    severity: FindingSeverity.Info,
                    titleSuffix: $"PID {pid}",

                    subjectType: FindingSubjectType.Process,
                    subjectId: pid.ToString(),
                    subjectDisplayName: baseFinding.SubjectDisplayName,

                    evidence: evidence,
                    recommendation: "Use this inventory as input for follow-up checks: identify pipes that are reachable from lower integrity contexts and review their security descriptors and expected callers.",

                    tags: new List<string> { "inventory", "named-pipes", "high-authority" },
                    relatedPids: Array.Empty<int>(),
                    conceptRefs: Array.Empty<string>(),
                    nextSteps: Array.Empty<InvestigationStep>(),

                    // keySuffix not needed for one finding per process
                    keySuffix: null
                );
            }
        }

        private static NamedPipeInventoryMetrics ComputeMetrics(IReadOnlyList<NamedPipeEndpoint> pipes)
        {
            // Security OK/error
            int sdOk = 0, sdErr = 0;

            // “Broad candidates” heuristics based on summary tags produced during SDDL parsing
            int broad = 0;
            int everyoneWrite = 0;
            int usersWrite = 0;
            int authUsersWrite = 0;
            int allAppPackagesAny = 0;

            foreach (var p in pipes)
            {
                var sec = p.Security;
                if (sec is null)
                {
                    sdErr++;
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(sec.Error))
                {
                    sdErr++;
                    continue;
                }

                sdOk++;

                var tags = sec.SddlSummary?.Tags;
                if (tags is null || tags.Count == 0)
                    continue;

                bool isBroad = false;

                // Presence-based signals (your summary already tags these)
                if (tags.Any(t => t.Equals("dacl:everyone-allow", StringComparison.OrdinalIgnoreCase)))
                {
                    isBroad = true;
                    // If you later tag write-vs-read specifically, refine these counters.
                    everyoneWrite++;
                }

                if (tags.Any(t => t.Equals("dacl:users-allow", StringComparison.OrdinalIgnoreCase)))
                {
                    isBroad = true;
                    usersWrite++;
                }

                if (tags.Any(t => t.Equals("dacl:auth-users-allow", StringComparison.OrdinalIgnoreCase)))
                {
                    isBroad = true;
                    authUsersWrite++;
                }

                if (tags.Any(t => t.Equals("dacl:all-app-packages-allow", StringComparison.OrdinalIgnoreCase)))
                {
                    isBroad = true;
                    allAppPackagesAny++;
                }

                if (isBroad) broad++;
            }

            return new NamedPipeInventoryMetrics(
                Total: pipes.Count,
                SecurityOk: sdOk,
                SecurityError: sdErr,
                BroadCandidates: broad,
                EveryoneWrite: everyoneWrite,
                UsersWrite: usersWrite,
                AuthUsersWrite: authUsersWrite,
                AllAppPackagesAny: allAppPackagesAny
            );
        }

    }
}
