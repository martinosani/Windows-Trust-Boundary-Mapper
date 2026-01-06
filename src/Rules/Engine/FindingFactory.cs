using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Domain.Processes;
using WTBM.Rules.Abstractions;
using WTBM.Domain.Findings;

namespace WTBM.Rules.Engine
{
    internal static class FindingFactory
    {
        public static Finding Create(
            IRule rule,
            FindingSeverity severity,
            string titleSuffix,

            FindingSubjectType subjectType,
            string subjectId,
            string? subjectDisplayName,

            IFindingEvidence evidence,
            string recommendation,

            IReadOnlyList<string> tags,
            IReadOnlyList<int> relatedPids,
            IReadOnlyList<string> conceptRefs,
            IReadOnlyList<InvestigationStep> nextSteps,

            int? scoreOverride = null,
            string? keySuffix = null)
        {
            if (rule is null) throw new ArgumentNullException(nameof(rule));

            subjectId = (subjectId ?? string.Empty).Trim();
            if (subjectId.Length == 0)
                throw new ArgumentException("subjectId must be non-empty.", nameof(subjectId));

            var baseTitle = rule.Title ?? rule.RuleId;
            var title = string.IsNullOrWhiteSpace(titleSuffix) ? baseTitle : $"{baseTitle} ({titleSuffix})";

            var normalizedKeySuffix = string.IsNullOrWhiteSpace(keySuffix) ? null : keySuffix.Trim();

            // Stable, subject-agnostic key for dedup:
            // RuleId:SubjectType:SubjectId[:KeySuffix]
            var key = normalizedKeySuffix is null
                ? $"{rule.RuleId}:{subjectType}:{subjectId}"
                : $"{rule.RuleId}:{subjectType}:{subjectId}:{normalizedKeySuffix}";

            var score = scoreOverride ?? ComputeScore(severity, tags, relatedPids);

            return new Finding(
                rule.RuleId,
                title,
                severity,
                rule.Category,
                subjectType,
                subjectId,
                subjectDisplayName,
                RuleHelpers.ClampScore(score),
                evidence,
                recommendation ?? string.Empty,
                tags,
                relatedPids,
                conceptRefs,
                nextSteps,
                key
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
