using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Domain.IPC
{
    internal sealed class AceInfo
    {
        public string Sid { get; init; } = string.Empty;
        public string? Principal { get; init; }           // best-effort name
        public string Rights { get; init; } = string.Empty; // es: "RW" or specific pipe rights
        public string AceType { get; init; } = string.Empty; // ALLOW/DENY
        public string? Condition { get; init; }           // per conditional ACE (rare, ma esiste)
    }
}
