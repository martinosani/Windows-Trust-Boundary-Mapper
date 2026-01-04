using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Domain.Processes;

namespace WTBM.Output
{
    internal sealed record CoverageMetrics(
    int ProcessesEnumerated,
    int TokenCollectedOk,
    int TokenFailed,
    IReadOnlyDictionary<string, int> TokenFailuresByReason
);

    internal static class CoverageMetricsBuilder
    {
        public static CoverageMetrics Build(IReadOnlyList<ProcessSnapshot> snapshots)
        {
            if (snapshots is null) throw new ArgumentNullException(nameof(snapshots));

            var processesEnumerated = snapshots.Count;

            int ok = 0;
            int failed = 0;

            var byReason = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            foreach (var s in snapshots)
            {
                // "OK" means: TokenInfo exists and no CollectionError
                if (s.Token is not null && string.IsNullOrWhiteSpace(s.Token.CollectionError))
                {
                    ok++;
                    continue;
                }

                failed++;

                var reasonRaw = s.Token?.CollectionError ?? s.Process.CollectionError ?? "Unknown";
                var reason = NormalizeReason(reasonRaw);

                byReason.TryGetValue(reason, out var cur);
                byReason[reason] = cur + 1;
            }

            return new CoverageMetrics(
                ProcessesEnumerated: processesEnumerated,
                TokenCollectedOk: ok,
                TokenFailed: failed,
                TokenFailuresByReason: byReason
            );
        }

        private static string NormalizeReason(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return "Unknown";

            raw = raw.Trim();

            // Keep these buckets small and stable. Add more only when you see them in real output.
            if (raw.Contains("AccessDenied", StringComparison.OrdinalIgnoreCase))
                return "AccessDenied";

            if (raw.Contains("Protected", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("PPL", StringComparison.OrdinalIgnoreCase))
                return "PPL/Protected";

            if (raw.Contains("NotFound", StringComparison.OrdinalIgnoreCase))
                return "NotFound";

            return raw; // fallback: preserves useful detail without losing signal
        }
    }
}
