using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using WTBM.Domain.Findings;
using WTBM.Domain.IPC;
using WTBM.Domain.Processes;

namespace WTBM.Output
{
    /// <summary>
    /// Single, structured console report writer for WTBM.
    /// 
    /// Responsibilities:
    /// - Render coverage counters
    /// - Render findings (grouped + detailed)
    /// - Render evidence preview for single-finding flows (e.g., --process-pid)
    /// - Render an explain view (rule-explain) that is data-driven (no parsing)
    /// 
    /// This writer assumes structured evidence through IFindingEvidence.Kind/Summary
    /// and optionally attempts a best-effort preview if the evidence object exposes
    /// a list-like property (e.g., Pipes/Items/Entries).
    /// </summary>
    internal sealed class ConsoleReportWriter
    {
        private readonly ConsoleReportOptions _opt;

        public ConsoleReportWriter(ConsoleReportOptions? options = null)
        {
            _opt = options ?? new ConsoleReportOptions();
        }

        /// <summary>
        /// Writes a research-grade, console-friendly process snapshot table.
        /// This is the primary output for "--enumeration".
        /// </summary>
        public void WriteProcessSnapshots(IReadOnlyList<ProcessSnapshot> snapshots)
        {
            if (snapshots is null)
                throw new ArgumentNullException(nameof(snapshots));

            ConsoleSections.Header("=== Process snapshots ===");
            Console.WriteLine();

            // Coverage counters (best-effort; TokenCollector may still return snapshots with errors)
            int total = snapshots.Count;
            int tokenOk = snapshots.Count(s => string.IsNullOrWhiteSpace(s.Token?.CollectionError));
            int tokenErr = total - tokenOk;

            Console.WriteLine($"Processes enumerated : {total}");
            Console.WriteLine($"Token collected OK   : {tokenOk}");
            Console.WriteLine($"Token failed         : {tokenErr}");
            Console.WriteLine();

            // Prepare rows (keep selectors simple and robust)
            var rows = snapshots
                .OrderByDescending(s => (int)(s.EffectiveIntegrityLevel))
                .ThenBy(s => s.Process?.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                .ThenBy(s => s.Process?.Pid ?? 0)
                .Select(s => new ProcessSnapshotRow(
                    Pid: s.Process.Pid,
                    Ppid: s.Process.Ppid,
                    Name: s.Process.Name,
                    User: BestUser(s.Token),
                    IL: FormatIntegrityLevelShort(s.EffectiveIntegrityLevel),
                    Sess: BestSessionId(s),
                    Elev: FormatElevationShort(s.Token),
                    AppC: Flag(s.Token?.IsAppContainer),
                    Restr: Flag(s.Token?.IsRestricted),
                    Type: FormatTokenTypeShort(s.Token),
                    Imp: FormatImpersonationShort(s.Token),
                    Path: s.Process.ImagePath ?? string.Empty,
                    Error: BestCollectionError(s)
                ))
                .ToList();

            // Table layout depends on verbosity.
            // Compact: core triage fields
            // Normal: adds token characteristics
            // Detailed: adds path + errors in-table (still truncated)
            var table = new ConsoleTable<ProcessSnapshotRow>()
                .AddColumn("PID", r => r.Pid, ConsoleAlignment.Right, maxWidth: 6)
                .AddColumn("PPID", r => r.Ppid, ConsoleAlignment.Right, maxWidth: 6)
                .AddColumn("Process", r => r.Name, maxWidth: 26)
                .AddColumn("User", r => r.User, maxWidth: 20)
                .AddColumn("IL", r => r.IL, maxWidth: 5)
                .AddColumn("Sess", r => r.Sess, ConsoleAlignment.Right, maxWidth: 4);

            if (_opt.Verbosity >= ConsoleVerbosity.Normal)
            {
                table
                    .AddColumn("Elev", r => r.Elev, maxWidth: 8)
                    .AddColumn("AppC", r => r.AppC, maxWidth: 4)
                    .AddColumn("Rstr", r => r.Restr, maxWidth: 4)
                    .AddColumn("TokenType", r => r.Type, maxWidth: 9)
                    .AddColumn("Imp", r => r.Imp, maxWidth: 6);
            }

            if (_opt.Verbosity >= ConsoleVerbosity.Detailed)
            {
                table
                    .AddColumn("Path", r => r.Path, maxWidth: 34)
                    .AddColumn("Error", r => r.Error, maxWidth: 22);
            }

            table.Write(rows, ToTableOptions(trailingBlankLine: true));

            // For non-detailed verbosity, print a short error summary section (high signal).
            if (_opt.Verbosity < ConsoleVerbosity.Detailed && tokenErr > 0)
            {
                ConsoleSections.Header("Token collection failures (top)");
                var failures = rows
                    .Where(r => !string.IsNullOrWhiteSpace(r.Error))
                    .Take(10)
                    .ToList();

                var errTable = new ConsoleTable<ProcessSnapshotRow>()
                    .AddColumn("PID", r => r.Pid, ConsoleAlignment.Right, maxWidth: 6)
                    .AddColumn("Process", r => r.Name, maxWidth: 26)
                    .AddColumn("User", r => r.User, maxWidth: 20)
                    .AddColumn("IL", r => r.IL, maxWidth: 5)
                    .AddColumn("Error", r => r.Error, maxWidth: 46);

                errTable.Write(failures, ToTableOptions(trailingBlankLine: true));
            }
        }

        // ---------------------------
        // Coverage
        // ---------------------------

        public void WriteCoverage(string title, IReadOnlyDictionary<string, int> counters)
        {
            if (string.IsNullOrWhiteSpace(title))
                title = "=== Coverage ===";

            if (counters is null)
                throw new ArgumentNullException(nameof(counters));

            ConsoleSections.Title(title);

            foreach (var kv in counters.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine($"{kv.Key,-24}: {kv.Value}");
            }

            Console.WriteLine();
        }

        // ---------------------------
        // Findings (grouped)
        // ---------------------------

        public void WriteFindingsGrouped(IReadOnlyList<Finding> findings)
        {
            if (findings is null)
                throw new ArgumentNullException(nameof(findings));

            ConsoleSections.Header("=== Findings (grouped) ===");

            if (findings.Count == 0)
            {
                Console.WriteLine("(no findings)");
                Console.WriteLine();
                return;
            }

            // For some rules, grouping by SubjectId (PID) is not useful.
            // We choose a rule-aware strategy to maximize triage signal.

            var grouped = findings
                .GroupBy(f => BuildGroupingKey(f))
                .Select(g =>
                {
                    var sample = g.First();

                    return new FindingGroupRow(
                        Count: g.Count(),
                        Score: g.Max(x => x.Score),
                        Severity: g.Max(x => x.Severity).ToString(),
                        Category: sample.Category.ToString(),
                        RuleId: sample.RuleId,
                        Subject: BuildGroupedSubjectDisplay(sample, g),
                        EvidenceKind: sample.Evidence?.Kind ?? "-",
                        Tags: ShortTags(MergeTagsForGroup(g), 4),
                        Key: sample.Key
                    );
                })
                .OrderByDescending(x => x.Score)
                .ThenByDescending(x => x.Count)
                .ThenBy(x => x.Category, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.RuleId, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Subject, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var table = new ConsoleTable<FindingGroupRow>()
                .AddColumn("Count", r => r.Count, ConsoleAlignment.Right, maxWidth: 5)
                .AddColumn("Score~", r => r.Score, ConsoleAlignment.Right, maxWidth: 6)
                .AddColumn("Severity", r => r.Severity, maxWidth: 8)
                .AddColumn("Category", r => r.Category, maxWidth: 14)
                .AddColumn("RuleId", r => r.RuleId, maxWidth: 18)
                .AddColumn("Subject / Group", r => r.Subject, maxWidth: 46)
                .AddColumn("Evidence", r => r.EvidenceKind, maxWidth: 18)
                .AddColumn("Tags", r => r.Tags, maxWidth: 28);

            table.Write(grouped, ToTableOptions());

        }

        // ---------------------------
        // Findings (detailed)
        // ---------------------------

        public void WriteFindingsDetailed(IReadOnlyList<Finding> findings)
        {
            if (findings is null)
                throw new ArgumentNullException(nameof(findings));

            ConsoleSections.Header("=== Findings (detailed) ===");

            var rows = findings
                .OrderByDescending(f => f.Score)
                .ThenByDescending(f => f.Severity)
                .ThenBy(f => f.Category)
                .ThenBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase)
                .ThenBy(f => f.SubjectType)
                .ThenBy(f => f.SubjectId, StringComparer.OrdinalIgnoreCase)
                .Select(f => new FindingDetailRow(
                    Severity: f.Severity.ToString(),
                    Score: f.Score,
                    Category: f.Category.ToString(),
                    RuleId: f.RuleId,
                    Subject: BuildSubjectDisplay(f),
                    Evidence: f.Evidence?.Summary ?? string.Empty,
                    Tags: ShortTags(f.Tags, 3),
                    Key: f.Key
                ))
                .ToList();

            var table = new ConsoleTable<FindingDetailRow>()
                .AddColumn("Severity", r => r.Severity, maxWidth: 8)
                .AddColumn("Score", r => r.Score, ConsoleAlignment.Right, maxWidth: 5)
                .AddColumn("Category", r => r.Category, maxWidth: 14)
                .AddColumn("RuleId", r => r.RuleId, maxWidth: 18)
                .AddColumn("Subject", r => r.Subject, maxWidth: 40)
                .AddColumn("Evidence", r => r.Evidence, maxWidth: 42)
                .AddColumn("Tags", r => r.Tags, maxWidth: 24);

            table.Write(rows, ToTableOptions());

            Console.WriteLine($"Total findings: {findings.Count}");
            Console.WriteLine();
        }

        // ---------------------------
        // Evidence preview (single finding)
        // ---------------------------

        /// <summary>
        /// Prints a best-effort evidence preview when there is a single finding.
        /// This makes "single PID" flows immediately useful without requiring --rule-explain.
        /// </summary>
        public void WriteEvidencePreviewIfSingleFinding(IReadOnlyList<Finding> findings)
        {
            if (!_opt.PrintEvidencePreviewForSingleFinding)
                return;

            if (findings is null || findings.Count != 1)
                return;

            WriteEvidencePreview(findings[0]);
        }

        /// <summary>
        /// Prints a best-effort evidence preview for a specific finding.
        /// If the evidence object exposes a list-like property (Pipes/Items/Entries/...),
        /// the writer will render a top-N table. Otherwise it prints only Kind/Summary.
        /// </summary>
        public void WriteEvidencePreview(Finding finding)
        {
            if (finding is null)
                throw new ArgumentNullException(nameof(finding));

            ConsoleSections.Header("=== Evidence (preview) ===");
            Console.WriteLine($"{finding.RuleId}: {finding.Title}");
            Console.WriteLine();
            Console.WriteLine($"Subject: {BuildSubjectDisplay(finding)}");
            Console.WriteLine($"Category: {finding.Category} | Severity: {finding.Severity} | Score~: {finding.Score}");
            Console.WriteLine($"Evidence: {finding.Evidence.Kind} | {finding.Evidence.Summary}");
            Console.WriteLine();

            // Try structured preview: extract a list-like payload from the evidence instance.
            var preview = TryExtractPreviewList(finding.Evidence);
            if (preview is null)
            {
                Console.WriteLine("(No structured preview available for this evidence type.)");
                Console.WriteLine("Use --rule-explain for full details.");
                Console.WriteLine();
                return;
            }

            var (label, items) = preview.Value;

            var itemList = items.Cast<object?>().Where(x => x is not null).Cast<object>().ToList();
            Console.WriteLine($"{label}: {itemList.Count} item(s)");
            Console.WriteLine();

            // Render top N items as a table.
            // We avoid hard dependency on specific types; we show a compact set of columns:
            // - Name/Path (best-effort)
            // - Owner (best-effort)
            // - Tags (best-effort)
            // - Error (best-effort)
            var top = itemList.Take(Math.Max(1, _opt.NamedPipePreviewCount)).ToList();

            var rows = top.Select(x => new EvidencePreviewRow(
                Name: GetBestEffortName(x),
                Owner: GetBestEffortOwner(x),
                Tags: GetBestEffortTags(x),
                Error: GetBestEffortError(x)
            )).ToList();

            var table = new ConsoleTable<EvidencePreviewRow>()
                .AddColumn("Item", r => r.Name, maxWidth: 72)
                .AddColumn("Owner", r => r.Owner, maxWidth: 28)
                .AddColumn("Tags", r => r.Tags, maxWidth: 36)
                .AddColumn("Error", r => r.Error, maxWidth: 26);

            table.Write(rows, ToTableOptions(trailingBlankLine: true));

            if (itemList.Count > _opt.NamedPipePreviewCount)
            {
                Console.WriteLine($"(Showing first {_opt.NamedPipePreviewCount} items. Use --rule-explain for full evidence.)");
                Console.WriteLine();
            }
        }

        // ---------------------------
        // Rule-explain view (detailed)
        // ---------------------------

        /// <summary>
        /// Prints a structured "explain" view for a single finding.
        /// This is intended for --rule-explain.
        /// </summary>
        public void WriteFindingExplain(Finding f)
        {
            if (f is null)
                throw new ArgumentNullException(nameof(f));

            ConsoleSections.Title($"=== Finding: {f.RuleId} ===");

            Console.WriteLine($"Title        : {f.Title}");
            Console.WriteLine($"Severity     : {f.Severity}");
            Console.WriteLine($"Score        : {f.Score}");
            Console.WriteLine($"Category     : {f.Category}");
            Console.WriteLine($"Subject type : {f.SubjectType}");
            Console.WriteLine($"Subject      : {BuildSubjectDisplay(f)}");
            Console.WriteLine($"Key          : {f.Key}");
            Console.WriteLine();

            Console.WriteLine("Evidence:");
            Console.WriteLine($"  Kind    : {f.Evidence.Kind}");
            Console.WriteLine($"  Summary : {f.Evidence.Summary}");
            Console.WriteLine();

            // Optional: print tags, related PIDs, refs, next steps.
            if (f.Tags is { Count: > 0 })
            {
                Console.WriteLine("Tags:");
                Console.WriteLine($"  {string.Join(", ", f.Tags)}");
                Console.WriteLine();
            }

            if (f.RelatedPids is { Count: > 0 })
            {
                Console.WriteLine("Related PIDs:");
                Console.WriteLine($"  {string.Join(", ", f.RelatedPids.Distinct().OrderBy(x => x))}");
                Console.WriteLine();
            }

            if (f.ConceptRefs is { Count: > 0 })
            {
                Console.WriteLine("Concept references:");
                foreach (var c in f.ConceptRefs.Distinct(StringComparer.OrdinalIgnoreCase))
                    Console.WriteLine($"  - {c}");
                Console.WriteLine();
            }

            if (f.NextSteps is { Count: > 0 })
            {
                Console.WriteLine("Next steps:");
                foreach (var s in f.NextSteps)
                {
                    Console.WriteLine($"  - {ConsoleText.OneLine(s.Title)}");
                    if (!string.IsNullOrWhiteSpace(s.Description))
                        Console.WriteLine($"    {ConsoleText.OneLine(s.Description)}");
                }
                Console.WriteLine();
            }

            if (!string.IsNullOrWhiteSpace(f.Recommendation))
            {
                Console.WriteLine("Recommendation:");
                Console.WriteLine($"  {ConsoleText.OneLine(f.Recommendation)}");
                Console.WriteLine();
            }
        }

        // ---------------------------
        // Internals: table options + helpers
        // ---------------------------

        private static string BuildGroupingKey(Finding f)
        {
            // Rule-specific grouping for PRIV.001:
            // group by the "signature" of high-impact privileges (enabled vs present/disabled),
            // not by PID.
            if (string.Equals(f.RuleId, "PTTBM.PRIV.001", StringComparison.OrdinalIgnoreCase))
            {
                var sig = TryBuildPrivilegeSignature(f.Evidence?.Summary);
                if (!string.IsNullOrWhiteSpace(sig))
                    return $"{f.RuleId}|{f.Category}|privsig:{sig}";
            }

            // Default grouping: same rule + same subject type + same display name (process name),
            // which groups multiple instances like svchost.exe, mmc.exe, etc.
            var subjName = !string.IsNullOrWhiteSpace(f.SubjectDisplayName)
                ? f.SubjectDisplayName!.Trim()
                : f.SubjectId.Trim();

            return $"{f.RuleId}|{f.Category}|{f.SubjectType}|{subjName}";
        }

        private static string? TryBuildPrivilegeSignature(string? evidenceSummary)
        {
            if (string.IsNullOrWhiteSpace(evidenceSummary))
                return null;

            // Current TextEvidence formats used earlier:
            // - "Enabled high-impact privileges: SeDebugPrivilege, SeTcbPrivilege"
            // - "High-impact privileges present but disabled: SeImpersonatePrivilege, ..."
            //
            // We normalize into: "enabled:<sorted list>" OR "present-disabled:<sorted list>"

            var s = evidenceSummary.Trim();

            string prefix;
            int idx;

            if ((idx = s.IndexOf(':')) <= 0)
                return null;

            var head = s.Substring(0, idx).Trim();
            var tail = s.Substring(idx + 1).Trim();

            if (head.StartsWith("Enabled", StringComparison.OrdinalIgnoreCase))
                prefix = "enabled";
            else if (head.StartsWith("High-impact privileges present but disabled", StringComparison.OrdinalIgnoreCase))
                prefix = "present-disabled";
            else
                prefix = "privs";

            var items = tail
                .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim())
                .Where(x => x.Length > 0)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (items.Length == 0)
                return null;

            return $"{prefix}:{string.Join(",", items)}";
        }

        private static string BuildGroupedSubjectDisplay(Finding sample, IGrouping<string, Finding> group)
        {
            // For privilege signature grouping, show the signature + a short sample of processes.
            if (string.Equals(sample.RuleId, "PTTBM.PRIV.001", StringComparison.OrdinalIgnoreCase))
            {
                var sig = TryBuildPrivilegeSignature(sample.Evidence?.Summary) ?? "privsig:<unknown>";

                // Show up to 3 distinct process names to keep the table readable.
                var procNames = group
                    .Select(x => x.SubjectDisplayName)
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => x!.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                    .Take(3)
                    .ToList();

                var sampleProcs = procNames.Count == 0 ? "" : $" | e.g. {string.Join(", ", procNames)}";
                return $"{sig}{sampleProcs}";
            }

            // Default grouping: show the subject type and stable subject name
            var name = !string.IsNullOrWhiteSpace(sample.SubjectDisplayName)
                ? sample.SubjectDisplayName!.Trim()
                : sample.SubjectId.Trim();

            return $"{sample.SubjectType}:{name}";
        }

        private static IReadOnlyList<string> MergeTagsForGroup(IGrouping<string, Finding> group)
        {
            // Collect distinct tags across the group (best-effort) and keep stable ordering.
            var tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var f in group)
            {
                if (f.Tags is null) continue;
                foreach (var t in f.Tags)
                {
                    if (!string.IsNullOrWhiteSpace(t))
                        tags.Add(t.Trim());
                }
            }

            return tags.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private ConsoleTableOptions ToTableOptions(bool trailingBlankLine = true)
        {
            return new ConsoleTableOptions
            {
                WidthSampleSize = _opt.WidthSampleSize,
                MaxRowsToPrint = _opt.MaxRows,
                TrailingBlankLine = trailingBlankLine
            };
        }

        private static string BuildSubjectDisplay(Finding f)
        {
            // Prefer explicit display name; fall back to subject id.
            // Keep it stable and table-friendly.
            var display = !string.IsNullOrWhiteSpace(f.SubjectDisplayName) ? f.SubjectDisplayName : f.SubjectId;
            return $"{f.SubjectType}:{display}";
        }

        private static string ShortTags(IReadOnlyList<string> tags, int take)
        {
            if (tags is null || tags.Count == 0)
                return "-";

            return string.Join("|", tags.Take(Math.Max(1, take)));
        }

        // ---------------------------
        // Evidence preview extraction (reflection-based, robust)
        // ---------------------------

        private static (string Label, IEnumerable Items)? TryExtractPreviewList(IFindingEvidence evidence)
        {
            // We intentionally avoid relying on concrete evidence types.
            // Strategy:
            // - Look for a public property that is IEnumerable and has a high-probability name:
            //   Pipes, Items, Entries, Endpoints, Records, Objects
            // - Exclude string (string is IEnumerable<char> and would break things)
            var evType = evidence.GetType();
            var props = evType.GetProperties(BindingFlags.Instance | BindingFlags.Public);

            static bool IsEnumerableButNotString(Type t) =>
                typeof(IEnumerable).IsAssignableFrom(t) && t != typeof(string);

            string[] candidates = { "Pipes", "Endpoints", "Items", "Entries", "Records", "Objects" };

            foreach (var name in candidates)
            {
                var p = props.FirstOrDefault(x =>
                    x.CanRead &&
                    string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase) &&
                    IsEnumerableButNotString(x.PropertyType));

                if (p is null) continue;

                var value = p.GetValue(evidence) as IEnumerable;
                if (value is null) continue;

                return ($"{p.Name}", value);
            }

            // Fallback: first enumerable property (excluding strings) if only one is present
            var enumerableProps = props
                .Where(p => p.CanRead && IsEnumerableButNotString(p.PropertyType))
                .ToList();

            if (enumerableProps.Count == 1)
            {
                var p = enumerableProps[0];
                var value = p.GetValue(evidence) as IEnumerable;
                if (value is not null)
                    return ($"{p.Name}", value);
            }

            return null;
        }

        // ---------------------------
        // Best-effort preview fields (works for NamedPipeEndpoint-like objects)
        // ---------------------------

        private static string GetBestEffortName(object item)
        {
            // Tries common shapes:
            // - item.Pipe.Win32Path / NtPath / Name
            // - item.Name / Path / Win32Path / NtPath
            // - item.ToString()
            var pipeObj = GetProp(item, "Pipe");
            if (pipeObj is not null)
            {
                var win32 = GetProp(pipeObj, "Win32Path") as string;
                if (!string.IsNullOrWhiteSpace(win32)) return win32;

                var nt = GetProp(pipeObj, "NtPath") as string;
                if (!string.IsNullOrWhiteSpace(nt)) return nt;

                var name = GetProp(pipeObj, "Name") as string;
                if (!string.IsNullOrWhiteSpace(name)) return name;
            }

            foreach (var p in new[] { "Win32Path", "NtPath", "Path", "Name" })
            {
                var v = GetProp(item, p) as string;
                if (!string.IsNullOrWhiteSpace(v)) return v;
            }

            return ConsoleText.OneLine(item.ToString());
        }

        private static string GetBestEffortOwner(object item)
        {
            // Looks for item.Security.OwnerName / OwnerSid or direct OwnerName/OwnerSid
            var sec = GetProp(item, "Security");
            if (sec is not null)
            {
                var ownerName = GetProp(sec, "OwnerName") as string;
                if (!string.IsNullOrWhiteSpace(ownerName)) return ownerName;

                var ownerSid = GetProp(sec, "OwnerSid") as string;
                if (!string.IsNullOrWhiteSpace(ownerSid)) return ownerSid;
            }

            var directName = GetProp(item, "OwnerName") as string;
            if (!string.IsNullOrWhiteSpace(directName)) return directName;

            var directSid = GetProp(item, "OwnerSid") as string;
            if (!string.IsNullOrWhiteSpace(directSid)) return directSid;

            return "<unknown>";
        }

        private static string GetBestEffortTags(object item)
        {
            // Prefer Security.SddlSummary.Tags, then item.Tags
            var sec = GetProp(item, "Security");
            if (sec is not null)
            {
                var sddlSummary = GetProp(sec, "SddlSummary");
                var tags = GetProp(sddlSummary, "Tags") as IEnumerable;
                var rendered = RenderTags(tags, take: 4);
                if (!string.IsNullOrWhiteSpace(rendered)) return rendered;
            }

            var direct = GetProp(item, "Tags") as IEnumerable;
            var directRendered = RenderTags(direct, take: 4);
            if (!string.IsNullOrWhiteSpace(directRendered)) return directRendered;

            return "-";
        }

        private static string GetBestEffortError(object item)
        {
            // Prefer Security.Error, then item.ServerQueryError / Error
            var sec = GetProp(item, "Security");
            if (sec is not null)
            {
                var err = GetProp(sec, "Error") as string;
                if (!string.IsNullOrWhiteSpace(err)) return err;
            }

            foreach (var p in new[] { "ServerQueryError", "Error" })
            {
                var v = GetProp(item, p) as string;
                if (!string.IsNullOrWhiteSpace(v)) return v;
            }

            return "-";
        }

        private static string RenderTags(IEnumerable? tagsEnumerable, int take)
        {
            if (tagsEnumerable is null) return string.Empty;

            var list = new List<string>();
            foreach (var x in tagsEnumerable)
            {
                if (x is null) continue;
                var s = ConsoleText.OneLine(x.ToString());
                if (!string.IsNullOrWhiteSpace(s))
                    list.Add(s);
                if (list.Count >= take) break;
            }

            return list.Count == 0 ? string.Empty : string.Join("|", list);
        }

        private static object? GetProp(object? obj, string propName)
        {
            if (obj is null) return null;

            var t = obj.GetType();
            var p = t.GetProperty(propName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);
            return p?.CanRead == true ? p.GetValue(obj) : null;
        }

        // ---------------------------
        // Row model
        // ---------------------------

        private sealed record ProcessSnapshotRow(
            int Pid,
            int Ppid,
            string Name,
            string User,
            string IL,
            int Sess,
            string Elev,
            string AppC,
            string Restr,
            string Type,
            string Imp,
            string Path,
            string Error
        );

        // ---------------------------
        // Helpers
        // ---------------------------

        private static string BestUser(TokenInfo? t)
        {
            if (t is null) return "<unknown>";
            if (!string.IsNullOrWhiteSpace(t.UserName)) return t.UserName!;
            if (!string.IsNullOrWhiteSpace(t.UserSid)) return t.UserSid!;
            return "<unknown>";
        }

        private static int BestSessionId(ProcessSnapshot s)
        {
            // Prefer token session if available; fall back to process record
            return s.Token?.SessionId
                ?? s.Process?.SessionId
                ?? -1;
        }

        private static string BestCollectionError(ProcessSnapshot s)
        {
            // Prefer token collection error; fall back to process collection error
            var e = s.Token?.CollectionError;
            if (!string.IsNullOrWhiteSpace(e)) return ConsoleText.OneLine(e);

            e = s.Process?.CollectionError;
            if (!string.IsNullOrWhiteSpace(e)) return ConsoleText.OneLine(e);

            return string.Empty;
        }

        private static string Flag(bool? v) => v == true ? "Y" : "-";

        private static string FormatIntegrityLevelShort(IntegrityLevel il)
        {
            // Keep stable short labels for tables.
            return il switch
            {
                IntegrityLevel.Untrusted => "Untr",
                IntegrityLevel.Low => "Low",
                IntegrityLevel.Medium => "Med",
                IntegrityLevel.High => "High",
                IntegrityLevel.System => "Sys",
                IntegrityLevel.Protected => "Prot",
                _ => "Unk"
            };
        }

        private static string FormatElevationShort(TokenInfo? t)
        {
            if (t is null)
                return "-";

            string et = t.ElevationType switch
            {
                TokenElevationType.Full => "Full",
                TokenElevationType.Limited => "Lim",
                TokenElevationType.Default => "Def",
                _ => "Unk"
            };

            if (t.IsElevated is null)
                return et;

            return $"{et}/{(t.IsElevated == true ? "Y" : "-")}";
        }

        private static string FormatTokenTypeShort(TokenInfo? t)
        {
            if (t is null) return "-";

            return t.TokenType switch
            {
                TokenType.Primary => "Prim",
                TokenType.Impersonation => "Imp",
                _ => "Unk"
            };
        }

        private static string FormatImpersonationShort(TokenInfo? t)
        {
            if (t is null) return "-";
            if (t.TokenType != TokenType.Impersonation) return "-";

            return t.ImpersonationLevel switch
            {
                TokenImpersonationLevel.Anonymous => "Anon",
                TokenImpersonationLevel.Identification => "Ident",
                TokenImpersonationLevel.Impersonation => "Imprs",
                TokenImpersonationLevel.Delegation => "Deleg",
                _ => "Unk"
            };
        }

        // ---------------------------
        // Row types
        // ---------------------------

        private sealed record FindingGroupRow(
                int Count,
                int Score,
                string Severity,
                string Category,
                string RuleId,
                string Subject,
                string EvidenceKind,
                string Tags,
                string Key
            );

        private sealed record FindingDetailRow(
            string Severity,
            int Score,
            string Category,
            string RuleId,
            string Subject,
            string Evidence,
            string Tags,
            string Key
        );

        private sealed record EvidencePreviewRow(
            string Name,
            string Owner,
            string Tags,
            string Error
        );
    }
}

