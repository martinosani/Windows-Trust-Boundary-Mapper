using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Domain.Findings
{
    internal enum FindingSeverity { Info = 0, Low = 1, Medium = 2, High = 3 }

    internal enum FindingSubjectType
    {
        Process,
        NamedPipe,
        RpcEndpoint,
        Boundary
    }

    internal enum FindingCategory
    {
        TrustBoundary,
        Sandbox,
        Uac,
        Token,
        Privileges,
        Visibility,
        IPC
    }

    internal sealed record InvestigationStep(string Title, string Description);

    internal sealed record Finding(
        string RuleId,
        string Title,
        FindingSeverity Severity,
        FindingCategory Category,

        FindingSubjectType SubjectType,
        string SubjectId,
        string? SubjectDisplayName,

        int Score,
        string Evidence,
        string Recommendation,

        IReadOnlyList<string> Tags,
        IReadOnlyList<int> RelatedPids,
        IReadOnlyList<string> ConceptRefs,
        IReadOnlyList<InvestigationStep> NextSteps,

        string Key
    );

}
