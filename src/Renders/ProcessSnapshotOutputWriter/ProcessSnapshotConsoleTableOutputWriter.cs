using PTTBM.Models;
using System;
using System.Collections.Generic;
using System.Reflection.PortableExecutable;
using System.Text;

namespace PTTBM.Renders.OutputWriter
{
    internal sealed class ProcessSnapshotConsoleTableOutputWriter : IOutputWriter
    {
        public OutputOptions Options { get; }

        public ProcessSnapshotConsoleTableOutputWriter(OutputOptions? options = null)
        {
            Options = options ?? new OutputOptions();
        }

        public void WriteSummary(IEnumerable<ProcessSnapshot> snapshots)
        {
            if (snapshots is null)
                throw new ArgumentNullException(nameof(snapshots));

            var rows = snapshots.Select(BuildRow).ToList();

            // Header
            var headers = new[]
            {
                "PID",
                "Name",
                "Sess",
                "IL",
                "UAC",
                "AppC",
                "Restr",
                "User",
                Options.IncludeFlags ? "Flags" : null,
                Options.IncludeNotes ? "Notes" : null
            }.Where(h => h is not null).ToArray()!;

            // Column widths (auto)
            var widths = ComputeWidths(headers, rows);

            // Print header
            WriteRow(headers, widths, isHeader: true);

            // Print separator
            WriteSeparator(widths);

            // Print rows
            foreach (var r in rows)
                WriteRow(r, widths, isHeader: false);

            Console.WriteLine();
        }

        // =========================
        // Row building
        // =========================

        private string[] BuildRow(ProcessSnapshot s)
        {
            var p = s.Process;
            var t = s.Token;

            var il = t?.IntegrityLevel.ToString() ?? "?";
            var uac = t?.ElevationType.ToString() ?? "?";
            var appc = BoolShort(t?.IsAppContainer);
            var restr = BoolShort(t?.IsRestricted);

            var user = Shorten(t?.UserName ?? t?.UserSid, Options.MaxColumnWidth);

            var flags = Options.IncludeFlags ? BuildFlags(t) : null;
            var notes = Options.IncludeNotes ? BuildNotes(p, t) : null;

            return new[]
            {
                p.Pid.ToString(),
                Shorten(p.Name, Options.MaxColumnWidth),
                p.SessionId?.ToString() ?? "?",
                il,
                uac,
                appc,
                restr,
                user ?? "?",
                flags,
                notes
            }.Where(v => v is not null).ToArray()!;
        }

        private static string BuildFlags(TokenInfo? t)
        {
            if (t is null)
                return "";

            var flags = new List<string>();

            if (t.HasUIAccess == true) flags.Add("UI");
            if (t.IsVirtualizationEnabled == true) flags.Add("Virt");
            if (t.HasLinkedToken == true) flags.Add("Linked");
            if (t.TokenType == TokenType.Impersonation) flags.Add("Imp");
            if (t.IsMemberOfAdministrators == true) flags.Add("Admin");
            if (t.IsLocalSystem == true) flags.Add("SYSTEM");
            if (t.IsLocalService == true) flags.Add("LS");
            if (t.IsNetworkService == true) flags.Add("NS");
            if (t.CapabilitiesSids is { Count: > 0 }) flags.Add($"Cap:{t.CapabilitiesSids.Count}");
            if (t.Privileges is { Count: > 0 }) flags.Add($"Priv:{t.Privileges.Count}");

            return string.Join(",", flags);
        }

        private static string BuildNotes(ProcessRecord p, TokenInfo? t)
        {
            if (!string.IsNullOrWhiteSpace(p.CollectionError))
                return $"P:{p.CollectionError}";

            if (!string.IsNullOrWhiteSpace(t?.CollectionError))
                return $"T:{t.CollectionError}";

            return "";
        }

        // =========================
        // Rendering helpers
        // =========================

        private static string BoolShort(bool? v) =>
            v switch
            {
                true => "Y",
                false => "N",
                _ => "?"
            };

        private static string? Shorten(string? s, int? max)
        {
            if (string.IsNullOrWhiteSpace(s))
                return s;

            if (max is null || s.Length <= max)
                return s;

            return s.Substring(0, max.Value - 1) + "…";
        }

        private static int[] ComputeWidths(string[] headers, List<string[]> rows)
        {
            var cols = headers.Length;
            var widths = new int[cols];

            for (int c = 0; c < cols; c++)
            {
                widths[c] = headers[c].Length;
                foreach (var r in rows)
                {
                    if (c < r.Length)
                        widths[c] = Math.Max(widths[c], r[c].Length);
                }
            }

            return widths;
        }

        private static void WriteRow(string[] cells, int[] widths, bool isHeader)
        {
            for (int i = 0; i < widths.Length; i++)
            {
                var text = i < cells.Length ? cells[i] : "";
                Console.Write(text.PadRight(widths[i] + 2));
            }
            Console.WriteLine();

            if (isHeader)
            {
                for (int i = 0; i < widths.Length; i++)
                    Console.Write(new string('=', widths[i]) + "  ");
                Console.WriteLine();
            }
        }

        private static void WriteSeparator(int[] widths)
        {
            for (int i = 0; i < widths.Length; i++)
                Console.Write(new string('-', widths[i]) + "  ");
            Console.WriteLine();
        }
    }
}
