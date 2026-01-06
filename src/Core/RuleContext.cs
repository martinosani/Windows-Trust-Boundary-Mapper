using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Domain.IPC;
using WTBM.Domain.Processes;
using WTBM.Rules.Abstractions;
using WTBM.Rules.Engine;

namespace WTBM.Core
{
    internal sealed class RuleContext
    {
        public IReadOnlyList<ProcessSnapshot> Snapshots { get; }

        public PrivilegeStats PrivilegeStats { get; }

        public IReadOnlyList<NamedPipeEndpoint> NamedPipes { get; }
        
        public IReadOnlyDictionary<int, ProcessSnapshot> ByPid { get; }
        
        public IReadOnlyDictionary<int, List<ProcessSnapshot>> ChildrenByPpid { get; }
        
        public IReadOnlyDictionary<string, List<ProcessSnapshot>> ByAuthenticationId { get; }

        public IReadOnlyList<IRule> Rules => _rules;

        private readonly List<IRule> _rules = null;

        public RuleContext(IReadOnlyList<IRule> rules, IReadOnlyList<ProcessSnapshot> snapshots, IReadOnlyList<NamedPipeEndpoint> namedPipes)
        {
            _rules = new List<IRule>(rules) ?? throw new ArgumentNullException(nameof(rules));
            Snapshots = snapshots ?? throw new ArgumentNullException(nameof(snapshots));
            PrivilegeStats = PrivilegeStats.Build(Snapshots);

            NamedPipes = namedPipes ?? Array.Empty<NamedPipeEndpoint>();

            // PID is unique in a point-in-time snapshot (best-effort).
            ByPid = snapshots
                .GroupBy(s => s.Process.Pid)
                .ToDictionary(g => g.Key, g => g.First());

            ChildrenByPpid = snapshots
                .GroupBy(s => s.Process.Ppid)
                .ToDictionary(g => g.Key, g => g.ToList());

            ByAuthenticationId = snapshots
                .Where(s => !string.IsNullOrWhiteSpace(s.Token.AuthenticationId))
                .GroupBy(s => s.Token.AuthenticationId!, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
        }

        public IRule GetRule(string ruleId)
        {
            var rule = Rules.FirstOrDefault(r => string.Compare(r.RuleId, ruleId, StringComparison.OrdinalIgnoreCase) == 0);
            
            if (rule == null)
            {
                foreach (var r in RuleRegistry.CreateFromSelection(ruleId))
                {
                    _rules.Add(r);
                }
            }

            rule = Rules.FirstOrDefault(r => string.Compare(r.RuleId, ruleId, StringComparison.OrdinalIgnoreCase) == 0);

            if (rule == null)
                throw new Exception(String.Format("Rule {0} not found.", ruleId));

            return rule;
        }

        public ProcessSnapshot? TryGetByPid(int pid)
            => ByPid.TryGetValue(pid, out var s) ? s : null;

        public IEnumerable<ProcessSnapshot> GetChildren(int ppid)
            => ChildrenByPpid.TryGetValue(ppid, out var list) ? list : Enumerable.Empty<ProcessSnapshot>();

        public ProcessSnapshot? GetParent(ProcessSnapshot s)
            => TryGetByPid(s.Process.Ppid);

        public IEnumerable<ProcessSnapshot> GetSiblingsByAuthId(ProcessSnapshot s)
        {
            var authId = s.Token.AuthenticationId;
            if (string.IsNullOrWhiteSpace(authId)) return Enumerable.Empty<ProcessSnapshot>();

            return ByAuthenticationId.TryGetValue(authId, out var list)
                ? list
                : Enumerable.Empty<ProcessSnapshot>();
        }

        public IEnumerable<ProcessSnapshot> GetByAuthId(string authId)
            => ByAuthenticationId.TryGetValue(authId, out var list)
                ? list
                : Enumerable.Empty<ProcessSnapshot>();

        
    }
}
