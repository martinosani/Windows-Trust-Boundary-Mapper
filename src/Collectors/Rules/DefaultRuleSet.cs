using System;
using System.Collections.Generic;
using System.Text;

namespace PTTBM.Collectors.Rules
{
    internal static class DefaultRuleSet
    {
        public static IReadOnlyList<IProcessRule> Create()
            => new IProcessRule[]
            {
                // Sandbox / boundary states
                new LegacySandboxTokenRule(),

                // Trust boundary asymmetry
                //new HighIntegrityInteractiveRule(),
                //new SystemInInteractiveSessionRule(),

                // UAC-related boundary markers
                //new UiAccessEnabledRule(),
                //new LinkedTokenPresentRule(),

                // Token complexity signals
                //new ImpersonationTokenRule(),
                //new SessionMismatchRule(),

                // Privilege leverage indicator
                new HighImpactPrivilegesRule(),

                // Visibility boundaries
                //new VisibilityBoundaryRule()
            };
    }
}
