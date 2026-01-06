using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Output
{
    internal static class ConsoleSections
    {
        public static void Title(string title)
        {
            Console.WriteLine();
            Console.WriteLine(title);
            Console.WriteLine(new string('=', Math.Max(3, title.Length)));
        }

        public static void Header(string header)
        {
            Console.WriteLine();
            Console.WriteLine(header);
        }

        public static void BlankLine() => Console.WriteLine();
    }
}
