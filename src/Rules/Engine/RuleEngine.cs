using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Core;
using WTBM.Domain.Findings;
using WTBM.Domain.IPC;
using WTBM.Domain.Processes;
using WTBM.Rules.Abstractions;

namespace WTBM.Rules.Engine
{
    internal static class RuleEngine
    {
        public static List<Finding> EvaluateAll(
            IReadOnlyList<ProcessSnapshot> snapshots,
            IReadOnlyList<NamedPipeEndpoint> namedPipes,
            IReadOnlyList<IRule> rules)
        {
            if (snapshots is null) throw new ArgumentNullException(nameof(snapshots));
            if (rules is null) throw new ArgumentNullException(nameof(rules));

            var ctx = new RuleContext(rules, snapshots, namedPipes);

            var results = new List<Finding>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var r in rules)
            {
                IEnumerable<Finding> produced;
                try
                {
                    produced = r.Evaluate(ctx);
                }
                catch (Exception ex)
                {
                    // Best-effort: a rule should never break the run.
                    var evidence = new TextEvidence(
                        KindValue: "engine-error",
                        SummaryValue: $"Rule failed: {r.RuleId} ({ex.GetType().Name})"
                    );

                    var f = new Finding(
                        RuleId: "WTBM.ENGINE.001",
                        Title: "Rule execution failure",
                        Severity: FindingSeverity.Info,
                        Category: FindingCategory.Visibility,
                        SubjectType: FindingSubjectType.Boundary,
                        SubjectId: r.RuleId,
                        SubjectDisplayName: $"Rule failed: {r.RuleId}",
                        Score: 0,
                        Evidence: evidence,
                        Recommendation: "Inspect logs / enable verbose diagnostics.",
                        Tags: Array.Empty<string>(),
                        RelatedPids: Array.Empty<int>(),
                        ConceptRefs: Array.Empty<string>(),
                        NextSteps: Array.Empty<InvestigationStep>(),
                        Key: $"WTBM.ENGINE.001:{r.RuleId}"
                    );

                    if (seen.Add(f.Key))
                        results.Add(f);
                    continue;
                }

                foreach (var f in produced)
                {
                    if (string.IsNullOrWhiteSpace(f.Key))
                        continue;

                    if (seen.Add(f.Key))
                        results.Add(f);
                }
            }

            // Stable ordering for output: score desc, severity desc, category, subject type, subject name/id
            return results
                .OrderByDescending(f => f.Score)
                .ThenByDescending(f => f.Severity)
                .ThenBy(f => f.Category)
                .ThenBy(f => f.SubjectType)
                .ThenBy(f => f.SubjectDisplayName ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.SubjectId, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }
}
