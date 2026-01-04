using WTBM.Collectors;
using WTBM.Renders.OutputWriter;
using System;
using WTBM.Output.Terminal;
using WTBM.Rules.Engine;

namespace WTBM
{
    internal static class Program
    {
        static int Main(string[] args)
        {
            Console.WriteLine("PTTBM - Process & Token Trust Boundary Mapper");
            Console.WriteLine("Initializing...");

            var processes = new ProcessEnumerator().Enumerate();
            Console.WriteLine($"Found {processes.Count} processes.");

            var tokenCollector = new TokenCollector();
            var snapshots = processes.Select(p => tokenCollector.TryCollect(p)).ToList();

            var rules = DefaultRuleSet.Create();
            var findings = RuleEngine.EvaluateAll(snapshots, rules);

            FindingsConsoleWriter.WriteSummary(findings);

            if (findings.Count > 0)
            {
                Console.WriteLine();

                FindingsConsoleWriter.Explain(findings[0]);
            }
           


            return 0;
        }
    }
}
