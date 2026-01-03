using PTTBM.Models;
using PTTBM.Models.Rules;
using System;
using System.Collections.Generic;
using System.Text;

namespace PTTBM.Collectors.Rules
{
    internal interface IProcessRule
    {
        string RuleId { get; }
        string Title { get; }
        FindingCategory Category { get; }

        // A baseline severity. Rules may raise/lower based on context.
        FindingSeverity BaselineSeverity { get; }

        IEnumerable<ProcessFinding> Evaluate(ProcessSnapshot snapshot, RuleContext ctx);
    }
}
