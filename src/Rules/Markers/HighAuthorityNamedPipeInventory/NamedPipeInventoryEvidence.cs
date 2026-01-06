using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Domain.Findings;
using WTBM.Domain.IPC;

namespace WTBM.Rules.Markers.HighAuthorityNamedPipeInventory
{
    internal sealed record NamedPipeInventoryEvidence(
        int ProcessPid,
        string? ProcessName,
        IReadOnlyList<NamedPipeEndpoint> Pipes,
        NamedPipeInventoryMetrics Metrics
    ) : IFindingEvidence
    {
        public string Kind => "named-pipe-inventory";
        public string Summary => $"Named pipes: {Metrics.Total} (SD ok: {Metrics.SecurityOk}, broad: {Metrics.BroadCandidates})";
    }

    internal sealed record NamedPipeInventoryMetrics(
        int Total,
        int SecurityOk,
        int SecurityError,
        int BroadCandidates,
        int EveryoneWrite,
        int UsersWrite,
        int AuthUsersWrite,
        int AllAppPackagesAny
    );
}
