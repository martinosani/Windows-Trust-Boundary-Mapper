using PTTBM.Models;
using PTTBM.Models.Rules;
using System;
using System.Collections.Generic;
using System.Text;

namespace PTTBM.Collectors.Rules
{
    internal static class RuleHelpers
    {
        public static string Safe(string? s) => string.IsNullOrWhiteSpace(s) ? "?" : s;

        public static string BoolStr(bool? v) => v switch { true => "true", false => "false", _ => "?" };

        public static int CountOr0<T>(IReadOnlyList<T>? list) => list?.Count ?? 0;

        public static bool IsInteractiveSession(int? sessionId) => sessionId.HasValue && sessionId.Value > 0;

        public static IEnumerable<string> ExtractPrivilegeNames(TokenInfo token)
            => token.Privileges?.Select(p => p.Name).Where(n => !string.IsNullOrWhiteSpace(n)) ?? Enumerable.Empty<string>();

        public static bool HasAnyHighImpactPrivilege(TokenInfo token, IReadOnlySet<string> names)
        {
            foreach (var n in ExtractPrivilegeNames(token))
            {
                if (names.Contains(n))
                    return true;
            }
            return false;
        }

        public static List<int> DistinctPids(IEnumerable<ProcessSnapshot> snaps)
            => snaps.Select(s => s.Process.Pid).Distinct().OrderBy(x => x).ToList();

        public static int ScoreFromSeverity(FindingSeverity s) => s switch
        {
            FindingSeverity.High => 100,
            FindingSeverity.Medium => 60,
            FindingSeverity.Low => 30,
            _ => 10
        };

        public static int ClampScore(int score) => Math.Max(0, Math.Min(200, score));
    }
}
