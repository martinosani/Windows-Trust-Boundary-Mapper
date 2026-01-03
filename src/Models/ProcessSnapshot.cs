using System;
using System.Collections.Generic;
using System.Text;

namespace PTTBM.Models
{
    internal sealed class ProcessSnapshot
    {
        public required ProcessRecord Process { get; init; }
        public required TokenInfo Token { get; init; }

    }
}
