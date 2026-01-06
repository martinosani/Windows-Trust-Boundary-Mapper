using System;
using System.Collections;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Threading.Tasks.Sources;
using WTBM.Collectors;
using WTBM.Collectors.IPC;
using WTBM.Domain.IPC;
using WTBM.Domain.Processes;
using WTBM.Output;
using WTBM.Output.OLD.Terminal;
using WTBM.Rules.Engine;

namespace WTBM
{
    internal static class Program
    {
        private enum RunMode { Process, Pipes }

        static async Task<int> Main(string[] args)
        {
            Logger.LogDebug("WTBM - Windows Trust Boundary Mapper");

            return runMainLoop(args);
        }

        private static int runMainLoop(string[] args)
        {
            var root = new RootCommand("WTBM - Windows Trust Boundary Mapper");
            
            var processCommand = new Command("process", "Enumerate processes and run rules");

            var enumerationOption = new Option<bool>("enumeration", "--enumeration")
            {
                Description = "Enumerates processes and associated token information and prints a flat summary list."
            };

            var ruleOption = new Option<string>("rule", "--rule", "-r")
            {
                Description = "Selects which rule set to execute against the collected process snapshots."
            };

            var processPidOption = new Option<int>("process-pid", "--process-pid", "-pid")
            {
                Description = "Restricts enumeration and rule evaluation to a specific process ID.",
                DefaultValueFactory = _ => -1
            };

            var ruleExplainOption = new Option<bool>("rule-explain", "--rule-explain")
            {
                Description = "Prints a detailed explanation for each rule finding associated with the process specified via --process-pid."
            };

            var namedPipesOption = new Option<bool>("named-pipes", "--named-pipes")
            {
                Description = "Enumerates Named Pipes associated with the high authority processes retrieved."
            };

            var topOption = new Option<int?>("top", "--top")
            {
                Description = "Limits the number of process snapshots printed during enumeration."
            };

            var verboseOption = new Option<bool>("verbose", "--verbose", "-v")
            {
                Description = "Verbose output"
            };

            var pauseOption = new Option<bool>("pause", "--pause")
            {
                Description = "Enable the interactive pause at the end of execution.",
                DefaultValueFactory = _ => false
            };

            processCommand.Add(enumerationOption);
            processCommand.Add(ruleOption);
            processCommand.Add(processPidOption);
            processCommand.Add(ruleExplainOption);
            processCommand.Add(namedPipesOption);
            processCommand.Add(topOption);
            processCommand.Add(verboseOption);
            processCommand.Add(pauseOption);

            processCommand.SetAction(result =>
            {
                // ---------------------------
                // 1) Read CLI options
                // ---------------------------
                bool enumeration = result.GetValue(enumerationOption);
                string? ruleSelection = result.GetValue(ruleOption);
                int? processPid = result.GetValue(processPidOption);
                int? top = result.GetValue(topOption);
                bool verbose = result.GetValue(verboseOption);
                bool pause = result.GetValue(pauseOption);
                bool explainRule = result.GetValue(ruleExplainOption);
                bool getNamedPipes = result.GetValue(namedPipesOption);

                // ---------------------------
                // 2) Validate option combinations
                // ---------------------------
                // rule-explain is meaningful only when scoping to a single process
                if (explainRule && processPid <= -1)
                    throw new ArgumentException("--rule-explain requires --process-pid.");

                // If the user asked for rule execution but did not provide a rule selection,
                // we do nothing here (same as before). You could choose to default to "all" later.
                bool runRules = !string.IsNullOrWhiteSpace(ruleSelection);

                // ---------------------------
                // 3) Acquire process records
                // ---------------------------
                var processes = new ProcessEnumerator().Enumerate();

                // Apply PID filter early (reduces work for token collection and IPC enumeration)
                if (processPid > -1)
                {
                    var match = processes.FirstOrDefault(p => p.Pid == processPid);
                    if (match is null)
                        throw new ArgumentException($"Process with PID {processPid} not found.");

                    processes = new List<ProcessRecord> { match };
                }

                // ---------------------------
                // 4) Collect token snapshots (stable input for rules & output)
                // ---------------------------
                var tokenCollector = new TokenCollector();

                var processSnapshots = processes
                    .Select(p => tokenCollector.TryCollect(p))
                    .ToList();

                // Apply --top only to presentation outputs (enumeration / tables),
                // NOT to rule evaluation, unless you explicitly want to restrict evaluation.
                // Here we preserve your current behavior: it only affected enumeration printing.
                var snapshotsForDisplay = processSnapshots;
                if (top.HasValue && top.Value > 0)
                    snapshotsForDisplay = processSnapshots.Take(top.Value).ToList();

                // ---------------------------
                // 5) Optional: enumerate named pipes
                // ---------------------------
                // Named pipes are expensive; do them only if requested OR required by selected rules.
                // You can later implement RuleRegistry.RequiresNamedPipes(ruleSelection).
                var namedPipes = new List<NamedPipeEndpoint>();

                if (getNamedPipes /* || (runRules && RuleRegistry.RequiresNamedPipes(ruleSelection)) */)
                {
                    var extractor = new NamedPipeExtractor();

                    foreach (var p in processes)
                    {
                        // Best-effort: a failure in one process should not stop everything
                        // (you likely already track errors inside NamedPipeEndpoint / ServerQueryError).
                        var pipes = extractor.GetNamedPipesFromProcessHandles(p.Pid);
                        if (pipes is { Count: > 0 })
                            namedPipes.AddRange(pipes);
                    }
                }

                // ---------------------------
                // 6) Optional: print enumeration (process snapshot list)
                // ---------------------------
                // Replace with your new unified writer (recommended).
                var reportWriter = new ConsoleReportWriter(new ConsoleReportOptions
                {
                    Verbosity = verbose ? ConsoleVerbosity.Detailed : ConsoleVerbosity.Normal,
                    MaxRows = null,
                    NamedPipePreviewCount = 10,
                    PrintEvidencePreviewForSingleFinding = true
                });

                if (enumeration)
                {
                    // NOTE: You’ll need a ProcessSnapshot table method on ConsoleReportWriter.
                    // If not implemented yet, keep the legacy call temporarily.
                    reportWriter.WriteProcessSnapshots(snapshotsForDisplay);
                }

                // ---------------------------
                // 7) Optional: print named pipes inventory table
                // ---------------------------
                if (getNamedPipes)
                {
                    // Replace with reportWriter.WriteNamedPipesTable(...) once you add it.
                }

                // ---------------------------
                // 8) Optional: run rules + print findings
                // ---------------------------
                if (runRules)
                {
                    var rules = RuleRegistry.CreateFromSelection(ruleSelection!);

                    // Rules should receive the complete snapshots set (not the display-truncated one),
                    // unless you intentionally want --top to limit evaluation.
                    var findings = RuleEngine.EvaluateAll(processSnapshots, namedPipes, rules);

                    // Recommended: write grouped + detailed with the new writer.
                    reportWriter.WriteFindingsGrouped(findings);
                    reportWriter.WriteFindingsDetailed(findings);

                    // If the user asked for explain and we are scoped to a single process, explain each finding.
                    if (explainRule && processes.Count == 1)
                    {
                        foreach (var finding in findings)
                        {
                            reportWriter.WriteFindingExplain(finding); // recommended
                            //FindingsConsoleWriter.Explain(finding, processSnapshots); // legacy until migrated
                        }
                    }

                    // Evidence preview: if a single finding and you have structured evidence payloads
                    // attached, the new writer can show them immediately.
                    if (findings.Count == 1)
                        reportWriter.WriteEvidencePreviewIfSingleFinding(findings);
                }

                if (pause)
                {
                    Console.WriteLine();
                    Console.WriteLine("Press ENTER to exit ...");
                    Console.ReadLine();
                }



                // Logger.LogDebug(String.Format("enumeration={0} - rule={1} - processPid={2}", enumeration, rule, processPid));

                /*if (processPid != null && processPid > -1)
                {
                    var process = processes.FirstOrDefault(p => p.Pid == processPid);

                    if (process == null)
                        throw new ArgumentException($"Process with PID {processPid} not found.");

                    processes = new List<ProcessRecord>() { process };
                }

                var processSnapshots = processes.Select(p => tokenCollector.TryCollect(p)).ToList();

                var namedPipes = new List<NamedPipeEndpoint>();

                if (getNamedPipes)
                {
                    var npe = new NamedPipeExtractor();

                    foreach (var process in processes)
                    {
                        var pipes = npe.GetNamedPipesFromProcessHandles(process.Pid);
                        namedPipes.AddRange(pipes);
                    }
                    
                    NamedPipesConsoleWriter.WriteSummary(namedPipes);
                }

                if (enumeration)
                {
                    if (top.HasValue && top.Value > 0)
                    {
                        processSnapshots = processSnapshots.Take(top.Value).ToList();
                    }                    

                    ProcessSnapshotConsoleSummaryWriter.WriteSummary(processSnapshots);
                }

                if (!String.IsNullOrEmpty(rule))
                {
                    var rules = RuleRegistry.CreateFromSelection(rule);
                    var findings = RuleEngine.EvaluateAll(processSnapshots, namedPipes, rules);

                    var max = top.HasValue ? top.Value : -1;
                    FindingsConsoleWriter.WriteSummary(findings, processSnapshots);

                    if (explainRule && processes.Count == 1)
                    {
                        foreach (var finding in findings)
                        {
                            FindingsConsoleWriter.Explain(finding, processSnapshots);
                        }
                    }
                }*/



            });

            root.Add(processCommand);
            return root.Parse(args).Invoke();
        }
    }

   
}
