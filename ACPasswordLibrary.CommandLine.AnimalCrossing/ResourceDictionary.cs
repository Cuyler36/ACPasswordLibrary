using System.Globalization;
using System.Text.RegularExpressions;

namespace ACPasswordLibrary.CommandLine.AnimalCrossing
{
    public sealed partial class ResourceDictionary
    {
        private readonly IReadOnlyDictionary<ushort, string> _dict;

        public ResourceDictionary(string contents)
        {
            var dict = new Dictionary<ushort, string>();
            foreach (var line in LineRegex().Split(contents))
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("//")) continue;
                dict.Add(ushort.Parse(line.Substring(2, 4), NumberStyles.HexNumber), line.Substring(8));
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

        [GeneratedRegex("\\r?\\n")]
        private static partial Regex LineRegex();
    }
}
