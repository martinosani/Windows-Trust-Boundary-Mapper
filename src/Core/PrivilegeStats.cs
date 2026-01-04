using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Domain.Processes;

namespace WTBM.Core
{
    internal sealed class PrivilegeStats
    {
        public int TotalTokens { get; }
        public IReadOnlyDictionary<string, int> ProcessPresenceCount { get; }
        public IReadOnlyDictionary<string, double> PresenceRate { get; }
        public IReadOnlyDictionary<string, double> RarityMultiplier { get; }

        private PrivilegeStats(
            int totalTokens,
            IReadOnlyDictionary<string, int> presenceCount,
            IReadOnlyDictionary<string, double> presenceRate,
            IReadOnlyDictionary<string, double> rarityMultiplier)
        {
            TotalTokens = totalTokens;
            ProcessPresenceCount = presenceCount;
            PresenceRate = presenceRate;
            RarityMultiplier = rarityMultiplier;
        }

        public static PrivilegeStats Build(IReadOnlyList<ProcessSnapshot> snapshots)
        {
            if (snapshots is null) throw new ArgumentNullException(nameof(snapshots));

            // Consider only tokens that were collected successfully and have privilege data.
            var usable = snapshots
                .Where(s =>
                    s.Token is not null &&
                    string.IsNullOrWhiteSpace(s.Token.CollectionError) &&
                    s.Token.Privileges is not null &&
                    s.Token.Privileges.Count > 0)
                .ToList();

            var total = usable.Count;

            // Count "presence" per process/token (not number of entries).
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            foreach (var s in usable)
            {
                // Deduplicate per-token to avoid inflating counts.
                var names = s.Token.Privileges!
                    .Select(p => p.Name)
                    .Where(n => !string.IsNullOrWhiteSpace(n))
                    .Select(n => n!.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase);

                foreach (var n in names)
                {
                    counts.TryGetValue(n, out var cur);
                    counts[n] = cur + 1;
                }
            }

            // Derive rates and rarity multipliers.
            var rates = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
            var multipliers = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);

            foreach (var kv in counts)
            {
                var rate = total == 0 ? 0.0 : (double)kv.Value / total;
                rates[kv.Key] = rate;
                multipliers[kv.Key] = ComputeRarityMultiplier(rate);
            }

            return new PrivilegeStats(total, counts, rates, multipliers);
        }

        public bool TryGetMultiplier(string privilegeName, out double multiplier)
        {
            if (string.IsNullOrWhiteSpace(privilegeName))
            {
                multiplier = 1.0;
                return false;
            }

            return RarityMultiplier.TryGetValue(privilegeName.Trim(), out multiplier);
        }

        public bool TryGetPresence(string privilegeName, out int count, out double rate)
        {
            count = 0;
            rate = 0.0;

            if (string.IsNullOrWhiteSpace(privilegeName))
                return false;

            var key = privilegeName.Trim();

            if (!ProcessPresenceCount.TryGetValue(key, out count))
                return false;

            PresenceRate.TryGetValue(key, out rate);
            return true;
        }

        private static double ComputeRarityMultiplier(double presenceRate)
        {
            // Explainable buckets:
            // - very common privileges are less useful to distinguish (lower multiplier)
            // - rare privileges are stronger triage signals (higher multiplier)
            //
            // You can tune these thresholds once you start collecting empirical output.
            if (presenceRate >= 0.30) return 0.50; // very common
            if (presenceRate >= 0.10) return 0.80; // common
            if (presenceRate >= 0.03) return 1.00; // baseline
            if (presenceRate >= 0.01) return 1.20; // uncommon
            return 1.50;                           // rare
        }
    }
}
