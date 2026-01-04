using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Domain.Findings;

namespace WTBM.Output.Terminal
{
    internal static class FindingsConsoleWriter
    {
        public static void WriteSummary(IEnumerable<Finding> findings, int max = 50)
        {
            if (findings is null)
                throw new ArgumentNullException(nameof(findings));

            var list = findings.Take(max).ToList();

            Console.WriteLine("=== Findings (summary) ===");
            Console.WriteLine("Severity  Score  Category        RuleId            Subject                         Title");
            Console.WriteLine("-------  -----  --------------  ----------------  ------------------------------  ------------------------------");

            foreach (var f in list)
            {
                var subject = FormatSubject(f, maxLen: 30);

                Console.WriteLine(
                    $"{f.Severity,-7}  " +
                    $"{f.Score,5}  " +
                    $"{f.Category,-14}  " +
                    $"{f.RuleId,-16}  " +
                    $"{subject,-30}  " +
                    $"{TrimTo(f.Title, 60)}");
            }

            Console.WriteLine();
            Console.WriteLine($"Total findings: {findings.Count()}");
            Console.WriteLine();
        }

        public static void Explain(Finding f)
        {
            if (f is null)
                throw new ArgumentNullException(nameof(f));

            Console.WriteLine($"=== Finding: {f.RuleId} ===");
            Console.WriteLine($"Title        : {f.Title}");
            Console.WriteLine($"Severity     : {f.Severity}");
            Console.WriteLine($"Score        : {f.Score}");
            Console.WriteLine($"Category     : {f.Category}");
            Console.WriteLine($"Subject type : {f.SubjectType}");
            Console.WriteLine($"Subject      : {FormatSubject(f, maxLen: 0)}");
            Console.WriteLine();

            Console.WriteLine("Evidence:");
            Console.WriteLine(IndentBlock(f.Evidence, "  "));
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

        // ---------------- helpers ----------------

        private static string FormatSubject(Finding f, int maxLen)
        {
            string subject = f.SubjectType switch
            {
                FindingSubjectType.Process =>
                    f.SubjectDisplayName is not null
                        ? $"{f.SubjectDisplayName} (PID {f.SubjectId})"
                        : $"PID {f.SubjectId}",

                FindingSubjectType.NamedPipe =>
                    f.SubjectDisplayName ?? f.SubjectId,

                FindingSubjectType.Boundary =>
                    f.SubjectDisplayName ?? f.SubjectId,

                _ =>
                    f.SubjectDisplayName ?? f.SubjectId
            };

            return maxLen > 0 ? TrimTo(subject, maxLen) : subject;
        }

        private static string TrimTo(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return s;
            if (s.Length <= max) return s;
            return s.Substring(0, max - 1) + "...";
        }

        private static string IndentBlock(string text, string indent)
        {
            if (string.IsNullOrWhiteSpace(text))
                return string.Empty;

            var lines = text.Replace("\r\n", "\n").Split('\n');
            return string.Join(Environment.NewLine, lines.Select(l => indent + l));
        }
    }

}
