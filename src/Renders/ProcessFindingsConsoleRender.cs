using PTTBM.Models.Rules;
using System;
using System.Collections.Generic;
using System.Text;

namespace PTTBM.Renders
{
    internal static class ProcessFindingsConsoleRender
    {
        public static void WriteSummary(IEnumerable<ProcessFinding> findings, int max = 50)
        {
            if (findings is null) throw new ArgumentNullException(nameof(findings));

            Console.WriteLine("=== Findings (summary) ===");
            Console.WriteLine("Severity  Score  RuleId           PID     Process                      Title");
            Console.WriteLine("-------  -----  --------------  ------  ---------------------------  ------------------------------");

            foreach (var f in findings.Take(max))
            {
                Console.WriteLine(
                    $"{f.Severity,-7}  {f.Score,5}  {f.RuleId,-14}  {f.Pid,6}  {TrimTo(f.ProcessName, 27),-27}  {TrimTo(f.Title, 70)}");
            }

            Console.WriteLine();
            Console.WriteLine($"Total findings: {findings.Count()}");
        }

        public static void Explain(ProcessFinding f)
        {
            Console.WriteLine($"=== Finding: {f.RuleId} ===");
            Console.WriteLine($"Severity   : {f.Severity}");
            Console.WriteLine($"Score      : {f.Score}");
            Console.WriteLine($"Category   : {f.Category}");
            Console.WriteLine($"Process    : {f.ProcessName} ({f.Pid})");
            Console.WriteLine();

            Console.WriteLine("Evidence:");
            Console.WriteLine($"  {f.Evidence}");
            Console.WriteLine();

            Console.WriteLine("Recommendation:");
            Console.WriteLine(IndentBlock(f.Recommendation, "  "));
            Console.WriteLine();

            if (f.RelatedPids.Count > 0)
            {
                Console.WriteLine("Related PIDs:");
                Console.WriteLine($"  {string.Join(", ", f.RelatedPids)}");
                Console.WriteLine();
            }

            if (f.ConceptRefs.Count > 0)
            {
                Console.WriteLine("Concept references:");
                foreach (var c in f.ConceptRefs)
                    Console.WriteLine($"  - {c}");
                Console.WriteLine();
            }

            if (f.NextSteps.Count > 0)
            {
                Console.WriteLine("Next steps:");
                foreach (var step in f.NextSteps)
                {
                    Console.WriteLine($"  - {step.Title}");
                    Console.WriteLine($"    {step.Description}");
                }
                Console.WriteLine();
            }

            if (f.Tags.Count > 0)
            {
                Console.WriteLine("Tags:");
                Console.WriteLine($"  {string.Join(", ", f.Tags)}");
                Console.WriteLine();
            }
        }

        private static string TrimTo(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return s;
            if (s.Length <= max) return s;
            return s.Substring(0, max - 1) + "...";
        }

        private static string IndentBlock(string text, string indent)
        {
            var lines = text.Replace("\r\n", "\n").Split('\n');
            return string.Join(Environment.NewLine, lines.Select(l => indent + l));
        }
    }
}
