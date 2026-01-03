using PTTBM.Models;
using PTTBM.Models.Rules;
using System;
using System.Collections.Generic;
using System.Text;

namespace PTTBM.Collectors.Rules
{
    internal static class ProcessRuleEngine
    {
        public static List<ProcessFinding> EvaluateAll(
            IReadOnlyList<ProcessSnapshot> snapshots,
            IReadOnlyList<IProcessRule> rules)
        {
            if (snapshots is null) throw new ArgumentNullException(nameof(snapshots));
            if (rules is null) throw new ArgumentNullException(nameof(rules));

            var ctx = new RuleContext(snapshots);

            var results = new List<ProcessFinding>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var s in snapshots)
            {
                foreach (var r in rules)
                {
                    IEnumerable<ProcessFinding> produced;
                    try
                    {
                        produced = r.Evaluate(s, ctx);
                    }
                    catch
                    {
                        // Best-effort: a rule should never break the run.
                        // TODO: log exception + rule id + pid
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
            }

            // Stable ordering for output: score desc, severity desc, process name, pid
            return results
                .OrderByDescending(f => f.Score)
                .ThenByDescending(f => f.Severity)
                .ThenBy(f => f.ProcessName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.Pid)
                .ToList();
        }
    }
}
