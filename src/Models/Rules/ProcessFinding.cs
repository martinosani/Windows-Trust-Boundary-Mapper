using System;
using System.Collections.Generic;
using System.Text;

namespace PTTBM.Models.Rules
{
    internal enum FindingSeverity { Info = 0, Low = 1, Medium = 2, High = 3 }

    internal enum FindingCategory
    {
        TrustBoundary,
        Sandbox,
        Uac,
        Token,
        Privileges,
        Visibility
    }

    internal sealed record InvestigationStep(string Title, string Description);

    internal sealed record ProcessFinding(
        FindingSeverity Severity,
        FindingCategory Category,
        string RuleId,
        string Title,
        int Pid,
        string ProcessName,
        string Evidence,
        string Recommendation,
        string Key,
        IReadOnlyList<string> Tags,
        IReadOnlyList<int> RelatedPids,
        IReadOnlyList<string> ConceptRefs,
        IReadOnlyList<InvestigationStep> NextSteps,
        int Score // computed ranking score (higher = more urgent to review)
    );
}
