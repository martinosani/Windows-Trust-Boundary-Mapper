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

namespace WTBM.Rules.Markers
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

            var findings = context.GetRule("PTTBM.PRIV.001").Evaluate(context);
            var npe = new NamedPipeExtractor();

            foreach (var finding in findings)
            {
                int pid = int.Parse(finding.SubjectId);

                var pipes = npe.GetNamedPipesFromProcessHandles(pid).ToList();

                if (pipes.Count == 0)
                    continue;

                Logger.LogDebug(String.Format("[PID:{0}] Found {1} named pipes", pid, pipes.Count));

                var evidence = BuildEvidence(pid, finding.SubjectDisplayName, pipes);


                yield return FindingFactory.Create(
                    rule: this,
                    severity: FindingSeverity.Info,
                    titleSuffix: $"PID {pid}",

                    subjectType: FindingSubjectType.Process,
                    subjectId: pid.ToString(),
                    subjectDisplayName: finding.SubjectDisplayName,

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

        private static string BuildEvidence(int pid, string? processName, IReadOnlyList<NamedPipeEndpoint> pipes)
        {
            var sb = new System.Text.StringBuilder();

            sb.AppendLine("High-authority process named pipe inventory");
            sb.AppendLine();
            sb.AppendLine("Process:");
            sb.AppendLine($"- PID: {pid}");
            if (!string.IsNullOrWhiteSpace(processName))
                sb.AppendLine($"- Name: {processName}");
            sb.AppendLine();
            sb.AppendLine($"Pipes (total: {pipes.Count}:");

            foreach (var p in pipes)
            {
                var name = p.Pipe?.ToString() ?? "<unknown>";
                sb.AppendLine($"- {name}");

                var ownerName = p.Security?.OwnerName ?? "<unknown>";
                var ownerSid = p.Security?.OwnerSid ?? "<unknown>";
                sb.AppendLine($"  Owner: {ownerName} ({ownerSid})");

                sb.AppendLine($"  Reachable: Medium={p.ReachableFromMedium} Low={p.ReachableFromLow} AppContainer={p.ReachableFromAppContainer}");

                if (p.Tags != null && p.Tags.Count > 0)
                    sb.AppendLine($"  Tags: [{string.Join(", ", p.Tags)}]");
            }

            return sb.ToString();
        }
    }
}
