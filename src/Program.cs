using PTTBM.Collectors;
using PTTBM.Renders.OutputWriter;
using System;

namespace PTTBM
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

            var rules = PTTBM.Collectors.Rules.DefaultRuleSet.Create();
            var findings = PTTBM.Collectors.Rules.ProcessRuleEngine.EvaluateAll(snapshots, rules);

            PTTBM.Renders.ProcessFindingsConsoleRender.WriteSummary(findings);

            if (findings.Count > 0)
            {
                Console.WriteLine();

                var finding = findings.First(f => f.ProcessName.Contains("Avast"));
                //PTTBM.Renders.ProcessFindingsConsoleRender.Explain(finding);

                PTTBM.Renders.ProcessFindingsConsoleRender.Explain(findings[0]);
            }
            
            
            //new FindingConsoleOuputWriter()
            //    .WriteSummary(processes.Select(p => tokenCollector.TryCollect(p)));

            //var consoleOutput = new ProcessSnapshotConsoleTableOutputWriter();
            // consoleOutput.WriteSummary(processes.Select(p => tokenCollector.TryCollect(p)));


            /*
            foreach (var process in processes)
            {
                // var snapshot = tokenCollector.TryCollect(process);

                // Renders.ProcessSnapshotConsoleRenderer.Render(snapshot);

                // Console.WriteLine($"{process.Pid,6} {process.Ppid,6} S:{process.SessionId,2} {process.Name}");
            }*/


            return 0;
        }
    }
}
