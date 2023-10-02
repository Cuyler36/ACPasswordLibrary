using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;

namespace ACPasswordLibrary.CommandLine.DnMPlus
{
    public sealed class ResourceDictionary
    {
        private readonly IReadOnlyDictionary<ushort, string> _dict;

        public ResourceDictionary(string contents)
        {
            var dict = new Dictionary<ushort, string>();
            foreach (var line in Regex.Split(contents, @"\r?\n"))
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("//")) continue;
                dict.Add(ushort.Parse(line[..4], NumberStyles.HexNumber), line[5..]);
            }
            _dict = dict;
        }

        public string this[ushort id]
        {
            get
            {
                if (_dict.TryGetValue(id, out var val))
                {
                    return val;
                }

                return "Unknown";
            }
        }
    }
}
