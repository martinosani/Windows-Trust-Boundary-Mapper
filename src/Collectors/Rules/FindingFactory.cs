using PTTBM.Models;
using PTTBM.Models.Rules;
using System;
using System.Collections.Generic;
using System.Text;

namespace PTTBM.Collectors.Rules
{
    internal static class FindingFactory
    {
        public static ProcessFinding Create(
            IProcessRule rule,
            ProcessSnapshot snapshot,
            FindingSeverity severity,
            string titleSuffix,
            string evidence,
            string recommendation,
            IReadOnlyList<string> tags,
            IReadOnlyList<int> relatedPids,
            IReadOnlyList<string> conceptRefs,
            IReadOnlyList<InvestigationStep> nextSteps,
            int? scoreOverride = null,
            string? keySuffix = null)
        {
            var baseTitle = rule.Title;
            var title = string.IsNullOrWhiteSpace(titleSuffix) ? baseTitle : $"{baseTitle} ({titleSuffix})";

            var key = keySuffix is null
                ? $"{rule.RuleId}:{snapshot.Process.Pid}"
                : $"{rule.RuleId}:{snapshot.Process.Pid}:{keySuffix}";

            var score = scoreOverride ?? ComputeScore(severity, tags, relatedPids);

            return new ProcessFinding(
                severity,
                rule.Category,
                rule.RuleId,
                title,
                snapshot.Process.Pid,
                snapshot.Process.Name,
                evidence,
                recommendation,
                key,
                tags,
                relatedPids,
                conceptRefs,
                nextSteps,
                RuleHelpers.ClampScore(score)
            );
        }

        private static int ComputeScore(FindingSeverity severity, IReadOnlyList<string> tags, IReadOnlyList<int> relatedPids)
        {
            var score = RuleHelpers.ScoreFromSeverity(severity);

            // Simple, explainable scoring adjustments.
            if (relatedPids.Count > 0) score += 15;           // correlation increases review priority
            if (tags.Contains("broker-boundary")) score += 10;
            if (tags.Contains("uac-boundary")) score += 10;
            if (tags.Contains("high-impact-privilege")) score += 10;

            return score;
        }
    }
}
