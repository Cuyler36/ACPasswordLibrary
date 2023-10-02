using ACPasswordLibrary.CommandLine.AnimalCrossing.Properties;
using ACPasswordLibrary.Core.AnimalCrossing;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using Iced.Intel;
using System.Diagnostics;
using System.Globalization;
using System.Resources;
using System.Runtime.InteropServices;
using System.Threading;

namespace ACPasswordLibrary.CommandLine.AnimalCrossing
{
    internal enum Mode
    {
        Encode = 0,
        Decode = 1,
        MassGenerate = 2,
        MassDecode = 3
    }

    internal enum LayoutRestrictions
    {
        None = 0,
        NoSymbols = 1
    }

    internal enum StringRestrictions
    {
        None = 0,
        No7FBytes = 1
    }

    internal enum AlgorithmMode
    {
        Standard = 0,
        Reverse = 1
    }
    public class Program
    {
        delegate int HandlerFunc(CtrlType sig);

        [DllImport("Kernel32")]
        private static extern bool SetConsoleCtrlHandler(HandlerFunc handler, bool add);

        private static readonly ResourceDictionary itemsDict = new(Resources.AC_Items_en);
        private static readonly ResourceDictionary villagersDict = new(Resources.AC_Villagers_en);
        private static readonly string[] specialVillagers =
        {
            "Tom Nook", "Wendell", "Saharah", "Gracie", "Joan", "Katrina", "Copper", "Jack", "Jingle",
            "Pete", "Pelly", "Phyllis", "Rover", "K.K. Slider", "Chip", "Booker", "Timmy", "Tommy",
            "Redd", "Resetti", "Gulliver", "Porter", "Blathers", "Kapp'n", "Mable", "Sable", "Tortimer",
            "Wisp", "Don", "Blanca", "Franklin", "Farley"
        };

        public static bool IsPasswordValid(Password password)
        {
            if ((int)password.CodeType > 5) return false;

            var checksum = 0;
            for (var i = 0; i < 8; i++)
                checksum += password.String0[i] + password.String1[i];

            checksum += password.ItemId;
            checksum += password.NpcCode;

            return (checksum & 3) == password.Checksum;
        }

        public static string BytesToString(in byte[] data) => data.Aggregate("", (current, b) => current += Common.CharacterSet[b]);

        struct GeneratorInfo
        {
            public Mode GenMode;
            public ushort[] ItemIds;
            public uint Threads;
            public uint MaxPasswords;
            public uint ScoreThreshold;
            public bool OnlyShowBestScore;
            public CodeScorer.Keyboard Keyboard;
            public StringRestrictions StringRestrictions;
            public LayoutRestrictions Restrictions;
            public string StartCode;
            public string Mask;
            public AlgorithmMode Algorithm;
            public int NpcCodeMin;
            public int NpcCodeMax;

            // Code stuff
            public CodeType Type;
            public byte NpcCode;
            public bool IsSpecialNpc;
            public byte HitRateIdx;
            public string String0;
            public string String1;
        }

        static readonly List<Thread> threads = new List<Thread>();
        static readonly List<Tuple<int, string>> scores = new List<Tuple<int, string>>();
        static StreamWriter textWriter;
        static ushort lastItemId;
        static Dictionary<ushort, PasswordEntry> dict;
        static HandlerFunc onShutdownFunc;

        private static bool[] ParseMask(string mask)
        {
            if (mask.Length != 28) throw new ArgumentException($"{nameof(mask)} must be 28 characters!");

            bool[] incrementing = new bool[28];
            for (int i = 0; i < mask.Length; i++)
            {
                incrementing[i] = mask[i] == '?';
            }

            return incrementing;
        }

        private static readonly byte[] mRmTp_birth_type =
        {
            0x05, 0x03, 0x00, 0x01, 0x0f, 0x01, 0x01, 0x02, 0x03, 0x03, 0x01, 0x00, 0x00, 0x03, 0x02, 0x0f, 0x02,
            0x00, 0x03, 0x02, 0x05, 0x03, 0x00, 0x03, 0x03, 0x01, 0x00, 0x00, 0x02, 0x01, 0x02, 0x10, 0x10, 0x10,
            0x02, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x01, 0x00, 0x00, 0x10, 0x10, 0x02, 0x00, 0x10, 0x01, 0x01,
            0x10, 0x10, 0x10, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x07, 0x02, 0x00, 0x00, 0x01, 0x00, 0x07,
            0x02, 0x00, 0x01, 0x01, 0x02, 0x02, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x02, 0x00,
            0x02, 0x07, 0x02, 0x03, 0x00, 0x07, 0x01, 0x07, 0x01, 0x00, 0x02, 0x03, 0x00, 0x01, 0x02, 0x02, 0x01,
            0x02, 0x00, 0x01, 0x07, 0x02, 0x03, 0x02, 0x01, 0x03, 0x02, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x01, 0x02, 0x01, 0x00, 0x01, 0x01, 0x03, 0x10, 0x04, 0x10, 0x10, 0x10, 0x01, 0x02, 0x01, 0x03, 0x02,
            0x10, 0x10, 0x00, 0x01, 0x02, 0x00, 0x01, 0x03, 0x10, 0x10, 0x10, 0x02, 0x10, 0x00, 0x01, 0x02, 0x01,
            0x01, 0x01, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x02, 0x02, 0x03, 0x02, 0x00, 0x01, 0x02, 0x00,
            0x02, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00,
            0x00, 0x10, 0x01, 0x00, 0x01, 0x02, 0x02, 0x02, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x01, 0x07, 0x00,
            0x00, 0x02, 0x03, 0x02, 0x02, 0x10, 0x07, 0x01, 0x02, 0x00, 0x03, 0x00, 0x02, 0x07, 0x01, 0x03, 0x01,
            0x00, 0x00, 0x07, 0x01, 0x02, 0x02, 0x00, 0x02, 0x01, 0x07, 0x00, 0x01, 0x01, 0x01, 0x00, 0x07, 0x01,
            0x00, 0x02, 0x02, 0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x01, 0x03, 0x00, 0x01, 0x02, 0x02, 0x07, 0x10,
            0x10, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x02, 0x10, 0x02, 0x02, 0x01, 0x10, 0x10, 0x10, 0x10,
            0x01, 0x02, 0x07, 0x10, 0x01, 0x10, 0x10, 0x02, 0x10, 0x10, 0x00, 0x01, 0x02, 0x10, 0x02, 0x02, 0x00,
            0x03, 0x01, 0x03, 0x10, 0x00, 0x10, 0x12, 0x10, 0x00, 0x02, 0x01, 0x10, 0x10, 0x10, 0x10, 0x05, 0x12,
            0x05, 0x10, 0x05, 0x05, 0x05, 0x01, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x07, 0x01, 0x02, 0x05, 0x05,
            0x03, 0x01, 0x00, 0x01, 0x02, 0x10, 0x01, 0x10, 0x10, 0x02, 0x00, 0x03, 0x01, 0x07, 0x00, 0x10, 0x10,
            0x10, 0x02, 0x02, 0x05, 0x02, 0x10, 0x01, 0x03, 0x01, 0x10, 0x03, 0x03, 0x00, 0x01, 0x00, 0x00, 0x01,
            0x10, 0x10, 0x00, 0x07, 0x00, 0x01, 0x02, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x1b, 0x1b,
            0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
            0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
            0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
            0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x1b,
            0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x1b, 0x03, 0x03, 0x07, 0x07, 0x03, 0x07, 0x03, 0x1c, 0x1a, 0x1c,
            0x1c, 0x1c, 0x1c, 0x07, 0x1a, 0x18, 0x18, 0x18, 0x18, 0x03, 0x00, 0x03, 0x07, 0x02, 0x01, 0x03, 0x07,
            0x03, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x03, 0x07, 0x03, 0x02, 0x03, 0x00, 0x00, 0x02,
            0x00, 0x01, 0x01, 0x02, 0x02, 0x01, 0x00, 0x10, 0x10, 0x07, 0x10, 0x10, 0x0e, 0x03, 0x03, 0x07, 0x07,
            0x03, 0x03, 0x07, 0x07, 0x03, 0x03, 0x00, 0x01, 0x0e, 0x03, 0x03, 0x00, 0x01, 0x07, 0x01, 0x00, 0x10,
            0x10, 0x02, 0x00, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d,
            0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x16, 0x1e, 0x10,
            0x13, 0x13, 0x16, 0x16, 0x10, 0x15, 0x16, 0x16, 0x15, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x16, 0x16, 0x16, 0x16, 0x13, 0x14, 0x14, 0x15, 0x1d,
            0x16, 0x10, 0x10, 0x10, 0x15, 0x15, 0x15, 0x16, 0x03, 0x10, 0x10, 0x15, 0x16, 0x10, 0x10, 0x1e, 0x19,
            0x20, 0x20, 0x20, 0x15, 0x15, 0x10, 0x15, 0x15, 0x10, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
            0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x00, 0x01, 0x02, 0x01, 0x00, 0x1f,
            0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x21, 0x21, 0x21, 0x21, 0x19, 0x19, 0x19, 0x19, 0x10, 0x19, 0x21, 0x19,
            0x19, 0x19, 0x21, 0x10, 0x10, 0x21, 0x22, 0x00, 0x00, 0x15, 0x01, 0x01, 0x02, 0x00, 0x01, 0x02, 0x01,
            0x15, 0x01, 0x01, 0x10, 0x01, 0x02, 0x10, 0x02, 0x10, 0x00, 0x15, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02,
            0x02, 0x03, 0x07, 0x02, 0x01, 0x01, 0x01, 0x01, 0x07, 0x00, 0x0e, 0x15, 0x02, 0x02, 0x03, 0x01, 0x13,
            0x0e, 0x02, 0x07, 0x00, 0x15, 0x15, 0x02, 0x00, 0x00, 0x03, 0x00, 0x01, 0x03, 0x07, 0x23, 0x07, 0x02,
            0x02, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x22, 0x22, 0x23, 0x22, 0x23, 0x22, 0x23, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x01, 0x22, 0x01, 0x03, 0x02, 0x00, 0x03, 0x07, 0x02, 0x00, 0x00, 0x01, 0x02, 0x25, 0x25,
            0x25, 0x02, 0x25, 0x25, 0x15, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x25, 0x03, 0x25,
            0x25, 0x25, 0x25, 0x15, 0x03, 0x15, 0x21, 0x10
        };

        private readonly struct ACChar
        {
            public readonly string Character;
            public readonly char ACCharacter;

            public ACChar(string c, char ac)
            {
                Character = c;
                ACCharacter = ac;
            }
        }

        private static readonly Dictionary<string, char> acChars = new()
        {
            { "🌢", '\x3B' },
            { "💢", '\x5C' },
            { "a̱", '\x99' },
            { "o̱", '\x9A' },
            { "🌬", '\xAA' },
            { "🗙", '\xB1' },
            { "🍀", '\xB8' },
            { "💀", '\xBA' },
            { "😮", '\xBB' },
            { "😄", '\xBC' },
            { "😣", '\xBD' },
            { "😠", '\xBE' },
            { "😃", '\xBF' },
            { "🔨", '\xC2' },
            { "🎀", '\xC3' },
            { "💰", '\xC5' },
            { "🐾", '\xC6' },
            { "🐶", '\xC7' },
            { "🐱", '\xC8' },
            { "🐰", '\xC9' },
            { "🐦", '\xCA' },
            { "🐮", '\xCB' },
            { "🐷", '\xCC' },
            { "🐟", '\xCE' },
            { "🐞", '\xCF' },
        };

        private static byte[] String2Bytes(in string s, int length)
        {
            var bytes = new byte[length];
            StringInfo stringInfo = new(s);
            int len = stringInfo.LengthInTextElements;

            for (int i = 0; i < length; i++)
            {
                if (i < len)
                {
                    string sub = stringInfo.SubstringByTextElements(i, 1);
                    if (sub.Length == 1)
                    {
                        bytes[i] = (byte)Array.IndexOf(Common.CharacterSet, sub[0]);
                    }
                    else if (acChars.ContainsKey(sub))
                    {
                        bytes[i] = (byte)acChars[sub];
                    }
                    else
                    {
                        bytes[i] = 0x20;
                    }
                }
                else
                {
                    bytes[i] = 0x20;
                }
            }

            return bytes;
        }

        private static bool IsBirthIndexAllowed(ushort itemId)
        {
            int ftrIdx = (itemId >= 0x3000 ? 0x400 : 0x000) | ((itemId & 0xFFF) >> 2);
            return mRmTp_birth_type[ftrIdx] switch
            {
                8 => false,
                9 => false,
                10 => false,
                11 => false,
                16 => false,
                24 => false,
                27 => false,
                28 => false,
                31 => false,
                _ => true
            };
        }

        private static bool IsPresentValid(CodeType type, ushort itemId)
        {
            if (type == CodeType.User)
            {

            }
            else if (type == CodeType.Famicom)
            {
                return itemId >= 0x1DA8 && itemId < 0x1DE4;
            }
            /* others */
            return ((itemId >> 12) & 0xF) switch
            {
                1 => IsBirthIndexAllowed(itemId),
                2 => ((itemId >> 8) & 0xF) switch
                {
                    0x0 => true,
                    0x1 => itemId < 0x2104,
                    0x2 => itemId < 0x225C,
                    0x3 => itemId < 0x2328,
                    0x4 => itemId < 0x24FF,
                    0x5 => itemId < 0x2531,
                    0x6 => itemId < 0x2643,
                    0x7 => itemId < 0x2743,
                    0x8 => itemId < 0x2808,
                    0x9 => itemId < 0x290B,
                    0xA => itemId < 0x2A37,
                    0xB => itemId < 0x2B10,
                    0xC => itemId < 0x2C60,
                    0xD => itemId < 0x2D28,
                    0xE => itemId < 0x2E02,
                    0xF => itemId < 0x2F04,
                    _ => false
                },
                3 => itemId < 0x33C8 && IsBirthIndexAllowed(itemId),
                _ => false
            };
        }

        /*
        private static void PrintInvalidCommonFtrs()
        {
            for (ushort i = 0x1000; i < 0x2000; i += 4)
            {
                if (!IsPresentValid(i))
                {
                    Console.WriteLine($"{i:X4} - {itemsDict[i]}");
                }
            }

            for (ushort i = 0x3000; i < 0x33C8; i += 4)
            {
                if (!IsPresentValid(i))
                {
                    Console.WriteLine($"{i:X4} - {itemsDict[i]}");
                }
            }
        }
        */

        private static void OutputPasswordsForItemsInRange(ushort start, ushort end, string name, ushort increment)
        {
            var basePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "ACPasswordOutputs");
            if (!Directory.Exists(basePath))
                Directory.CreateDirectory(basePath);

            using (var file = File.CreateText(Path.Combine(basePath, $"{name}.txt")))
            {
                byte[] passwordBytes = new byte[28];
                Span<byte> passwordSpan = passwordBytes.AsSpan();

                byte[] str0 = String2Bytes("kipedia ", 8);
                byte[] str1 = String2Bytes("from Noo", 8);

                for (var itemId = start; itemId <= end; itemId += increment)
                {
                    Core.AnimalCrossing.Encoder.MakePassword(ref passwordSpan, CodeType.Card_E_Mini, 1, str0, str1, itemId, 1, 0x00);
                    var password = BytesToString(passwordBytes);
                    file.WriteLine($"{itemId:X4} {password}");
                }
            }
        }

        private static string GetPasswordInfoText(string password, Password decoded)
        {
            return $@"Password Info for password {password}:
    Code Type: {decoded.CodeType}
    Present: {decoded.ItemId:X4} - {itemsDict[decoded.ItemId]}
    Checksum: {decoded.Checksum}
    String0: {decoded.String0.Aggregate("", (cur, b) => cur += Common.CharacterSet[b])}
    String1: {decoded.String1.Aggregate("", (cur, b) => cur += Common.CharacterSet[b])}
    Hit Rate Index: {decoded.HitRateIdx} {((decoded.CodeType == CodeType.Card_E && !decoded.IsSpecialNpc) ? " - " + ((4 - decoded.HitRateIdx) * 20) + "% chance of NES game (if sent to correct villager)" : "")}
    Npc Code: {decoded.NpcCode} - {(decoded.IsSpecialNpc ? specialVillagers[decoded.NpcCode] : villagersDict[(ushort)(decoded.NpcCode | 0xE000)])}
    Is Special Npc: {decoded.IsSpecialNpc}";
        }

        static async Task Main(string[] args)
        {
            //OutputPasswordsForItemsInRange(0x3000, 0x33C0, "Items_2");
            //OutputPasswordsForItemsInRange(0x2600, 0x2642, "Carpets", 1);
            //OutputPasswordsForItemsInRange(0x2700, 0x2742, "Wallpaper", 1);
            /*OutputPasswordsForItemsInRange(0x20C0, 0x20FF, "Stationery", 1);
            OutputPasswordsForItemsInRange(0x2100, 0x2103, "Money", 1);
            OutputPasswordsForItemsInRange(0x2200, 0x225B, "Tools", 1);
            OutputPasswordsForItemsInRange(0x2400, 0x24FE, "Shirts", 1);
            OutputPasswordsForItemsInRange(0x250E, 0x2530, "Items", 1);
            OutputPasswordsForItemsInRange(0x2800, 0x2807, "Fruit & Candy", 1);
            OutputPasswordsForItemsInRange(0x2900, 0x290A, "Seeds & Seedlings", 1);
            OutputPasswordsForItemsInRange(0x2A00, 0x2A36, "Songs", 1);
            OutputPasswordsForItemsInRange(0x2B00, 0x2B0F, "Diaries", 1);
            OutputPasswordsForItemsInRange(0x2E00, 0x2E01, "Grab Bags", 1);*/
            /*var pswd = Decoder.DecodeToPassword("zzUo#JtnxIWsnYw5mksTn5wRJaAf");
            Console.WriteLine($"Code Type: { pswd.CodeType}");
            Console.WriteLine($"Present: { pswd.ItemId:X4} - {itemsDict[pswd.ItemId]}");
            Console.WriteLine($"Checksum: { pswd.Checksum}");
            Console.WriteLine($"String0: { pswd.String0.Aggregate("", (cur, b) => cur += CharacterSet[b])}");
            Console.WriteLine($"String1: { pswd.String1.Aggregate("", (cur, b) => cur += CharacterSet[b])}");
            Console.WriteLine($"Hit Rate Index: { pswd.HitRateIdx}");
            Console.WriteLine($"Npc Code: {pswd.NpcCode} - {villagersDict[(ushort)(pswd.NpcCode | 0xE000)]}");
            Console.WriteLine($"Is Special Npc: { pswd.IsSpecialNpc}");
            return;*/
            //OutputPasswordsForItemsInRange(0x2C00, 0x2C5F, "Nook Tickets", 1);

            //PrintInvalidCommonFtrs();

            //var test = Encoder.MakePassword(CodeType.User, 0, String2Bytes("Test", 8), String2Bytes("Hello", 8), 0x1000, 0, 0).Aggregate("", (cur, b) => cur += CharacterSet[b]);

            //GenerateAllPossibleUserCodes(0x2200, "?", "?");
            //GenerateAllPossibleUserCodes(0x2203, "?", "?");
            //return;

            if (args.Length > 0)
            {
                var info = ParseArguments(args);
                if (info.GenMode == Mode.Decode)
                {
                    string password = args[args.Length - 1];
                    Console.WriteLine($"Decoding password {password}");

                    Password decoded = Core.AnimalCrossing.Decoder.DecodeToPassword(password);
                    Console.WriteLine($@"Password Info for password {password}:
    Valid Password: {IsPasswordValid(decoded)}
    Code Type: {decoded.CodeType}
    Present: {decoded.ItemId:X4} - {itemsDict[(decoded.ItemId & 0xF000) == 0x2000 ? decoded.ItemId : (ushort)(decoded.ItemId & ~3)]}
    Checksum: {decoded.Checksum}
    String0: {decoded.String0.Aggregate("", (cur, b) => cur += b < Common.CharacterSet.Length ? Common.CharacterSet[b] : "?")}
    String1: {decoded.String1.Aggregate("", (cur, b) => cur += b < Common.CharacterSet.Length ? Common.CharacterSet[b] : "?")}
    Hit Rate Index: {decoded.HitRateIdx} {((decoded.CodeType == CodeType.Card_E && !decoded.IsSpecialNpc) ? " - " + ((4 - decoded.HitRateIdx) * 20) + "% chance of NES game (if sent to correct villager)" : "")}
    Npc Code: {decoded.NpcCode} - {(decoded.NpcCode == 0xFF ? "" : (decoded.IsSpecialNpc ? specialVillagers[decoded.NpcCode] : villagersDict[(ushort)(decoded.NpcCode | 0xE000)]))}
    Is Special Npc: {decoded.IsSpecialNpc}");
                }
                else if (info.GenMode == Mode.MassDecode)
                {
                    var file = args[args.Length - 1];
                    if (!File.Exists(file))
                    {
                        Console.WriteLine("Invalid usage. Try -m MassDecode FILE_PATH");
                        return;
                    }

                    using var outFile = File.CreateText(Path.Combine(Path.GetDirectoryName(file), "output.txt"));

                    foreach (var password in File.ReadAllLines(file))
                    {
                        if (string.IsNullOrWhiteSpace(password)) continue;
                        Password decoded = Core.AnimalCrossing.Decoder.DecodeToPassword(password);
                        string text = GetPasswordInfoText(password, decoded);
                        Console.WriteLine(text + "\n");
                        outFile.WriteLine(text + "\n");
                    }
                }
                else if (info.GenMode == Mode.Encode)
                {
                    void Encode()
                    {
                        byte[] passwordBytes = new byte[28];
                        Span<byte> passwordSpan = passwordBytes.AsSpan();
                        foreach (var itemId in info.ItemIds)
                        {
                            Console.WriteLine($"============ Starting Password Generation for {itemId:X4} ============");
                            Core.AnimalCrossing.Encoder.MakePassword(ref passwordSpan, info.Type, info.HitRateIdx, String2Bytes(info.String0, 8), String2Bytes(info.String1, 8), itemId, info.IsSpecialNpc ? (byte)1 : (byte)0, info.NpcCode);
                            Console.WriteLine(passwordBytes.Aggregate("", (cur, b) => cur += Common.CharacterSet[b]).Insert(14, "\n"));
                        }
                    }


                    Encode();
                }
                else // Mode.MassGenerate
                {
                    foreach (var itemId in info.ItemIds)
                    {
                        Console.WriteLine($"============ Starting Password Generation for {itemId:X4} ============");
                        switch (info.Algorithm)
                        {
                            case AlgorithmMode.Reverse:
                                var bytes = new byte[28];
                                for (var i = 0; i < info.StartCode.Length; i++)
                                    bytes[i] = info.StartCode[i] == '?' ? (byte)0x25 : (byte)info.StartCode[i];

                                bool[] fields = ParseMask(info.Mask);
                                await ReverseAlgorithmicGenerator(bytes, 27, itemId, CodeType.Card_E_Mini, info.NpcCodeMin, info.NpcCodeMax, fields, info.StringRestrictions == StringRestrictions.No7FBytes, info.Threads);
                                break;
                            case AlgorithmMode.Standard:
                            default:
                                GenerateCardEMiniPassword(itemId, info.MaxPasswords, info.Threads + 1, info);
                                while (threads.Any(o => o.ThreadState == System.Threading.ThreadState.Running)) Thread.Sleep(100);
                                if (scores.Count > 0)
                                {
                                    if (info.OnlyShowBestScore)
                                    {
                                        Console.ForegroundColor = ConsoleColor.Green;
                                        Tuple<int, string> min = scores[0];
                                        for (var i = 1; i < scores.Count; i++)
                                            if (scores[i].Item1 < min.Item1)
                                                min = scores[i];

                                        Console.WriteLine($"BEST PASSWORD => Item Id: {lastItemId:X4} | Password: {min.Item2} | Score: {min.Item1}");
                                        textWriter?.WriteLine($"BEST PASSWORD => Item Id: {lastItemId:X4} | Password: {min.Item2} | Score: {min.Item1}");
                                        Console.ForegroundColor = ConsoleColor.White;
                                    }
                                    else
                                    {
                                        Console.ForegroundColor = ConsoleColor.Green;
                                        foreach (var score in scores)
                                        {
                                            Console.WriteLine($"BEST PASSWORD => Item Id: {lastItemId:X4} | Password: {score.Item2} | Score: {score.Item1}");
                                            textWriter?.WriteLine($"BEST PASSWORD => Item Id: {lastItemId:X4} | Password: {score.Item2} | Score: {score.Item1}");
                                        }
                                        Console.ForegroundColor = ConsoleColor.White;
                                    }
                                }
                                break;
                        }

                        Console.WriteLine("\n\n");
                    }

                    Console.WriteLine("Done!");
                }
            }
            else
            {
                PrintInstructions();
            }
        }

        static void PrintInstructions()
        {
            Console.WriteLine(@"Animal Crossing Password Generator Usage:
    Single Item Id with 4 threads & max passwords generated:
        Generator.exe -id 3A2C --threads 4 --passwordCount 0

    Item Id Binary File with 8 threads, 1,000,000 passwords per-thread, and restricted to only QWERTY scoring:
        Generator.exe --file C:\ItemIds.bin --threads 8 --passwordCount 1000000 --keyboard QWERTY"
            );
        }

        static GeneratorInfo ParseArguments(string[] args)
        {
            var info = new GeneratorInfo { GenMode = Mode.Decode, Type = CodeType.Card_E_Mini, NpcCode = 0xFF, IsSpecialNpc = false, String0 = "", String1 = "", HitRateIdx = 1, Threads = 1, Keyboard = CodeScorer.Keyboard.Both, Restrictions = LayoutRestrictions.None, StartCode = new string('\x25', 28), Algorithm = AlgorithmMode.Standard, NpcCodeMin = 0, NpcCodeMax = 0, Mask = new string('?', 28) };
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "--mode":
                    case "-m":
                        info.GenMode = (Mode)Enum.Parse(typeof(Mode), args[i + 1]);
                        if (!Enum.IsDefined(typeof(Mode), info.GenMode))
                        {
                            Console.WriteLine($"Bad generator mode: {args[i + 1]}");
                            throw new ArgumentException("Bad mode!");
                        }
                        i++;
                        break;
                    case "--type":
                    case "-t":
                        info.Type = (CodeType)Enum.Parse(typeof(CodeType), args[++i]);
                        break;
                    case "--npccode":
                    case "-n":
                        info.NpcCode = byte.Parse(args[++i]);
                        break;
                    case "--npcmin":
                    case "-nmin":
                        info.NpcCodeMin = byte.Parse(args[++i]);
                        break;
                    case "--npcmax":
                    case "-nmax":
                        info.NpcCodeMax = byte.Parse(args[++i]);
                        break;
                    case "--specialnpc":
                    case "-s":
                        info.IsSpecialNpc = true;
                        break;
                    case "--hitrate":
                    case "-h":
                        info.HitRateIdx = byte.Parse(args[++i]);
                        break;
                    case "--str0":
                    case "-s0":
                        info.String0 = args[++i];
                        break;
                    case "--str1":
                    case "-s1":
                        info.String1 = args[++i];
                        break;
                    case "--itemId":
                    case "-id":
                        if (info.ItemIds == null)
                            info.ItemIds = new[] { ushort.Parse(args[i + 1], System.Globalization.NumberStyles.HexNumber) };
                        else
                        {
                            ushort[] ids = new ushort[info.ItemIds.Length + 1];
                            Buffer.BlockCopy(info.ItemIds, 0, ids, 0, info.ItemIds.Length * sizeof(ushort));
                            ids[ids.Length - 1] = ushort.Parse(args[i + 1], System.Globalization.NumberStyles.HexNumber);
                            info.ItemIds = ids;
                        }
                        i++;
                        break;
                    case "--file":
                    case "-f":
                        using (var file = new FileStream(args[i + 1], FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (var reader = new BinaryReader(file))
                        {
                            var list = new List<ushort>();

                            while (file.Position < file.Length)
                            {
                                var itemId = (ushort)((file.ReadByte() << 8) | file.ReadByte());
                                if (itemId != 0) list.Add(itemId);
                            }

                            info.ItemIds = list.ToArray();
                            i++;
                        }
                        break;
                    case "--threads":
                    case "-th":
                        info.Threads = uint.Parse(args[i + 1]);
                        i++;
                        break;
                    case "--passwordcount":
                    case "-c":
                        info.MaxPasswords = uint.Parse(args[i + 1]);
                        i++;
                        break;
                    case "--score":
                        info.ScoreThreshold = uint.Parse(args[i + 1]);
                        i++;
                        break;
                    case "--best":
                    case "-b":
                        info.OnlyShowBestScore = true;
                        break;
                    case "--keyboard":
                    case "-k":
                        switch (args[i + 1].ToLower())
                        {
                            case "qwerty":
                                info.Keyboard = CodeScorer.Keyboard.QWERTY;
                                break;
                            case "alpha":
                            case "alphabetical":
                                info.Keyboard = CodeScorer.Keyboard.Alphabetical;
                                break;
                            case "both":
                            case "all":
                            default:
                                info.Keyboard = CodeScorer.Keyboard.Both;
                                break;
                        }

                        i++;
                        break;
                    case "--out":
                    case "-o":
                        textWriter?.Dispose();
                        textWriter = File.CreateText(args[i + 1]);
                        i++;
                        break;
                    case "--restriction":
                    case "-r":
                        switch (args[i + 1])
                        {
                            case "symbols":
                                info.Restrictions = LayoutRestrictions.NoSymbols;
                                break;
                            default:
                                Console.WriteLine($"Unknown restriction type {args[i + 1]}");
                                break;
                        }
                        i++;
                        break;
                    case "--stringrestriction":
                    case "-sr":
                        info.StringRestrictions = args[i + 1] switch
                        {
                            "on" => StringRestrictions.No7FBytes,
                            _ => StringRestrictions.None,
                        };
                        i++;
                        break;
                    case "--startcode":
                    case "-sc":
                        {
                            var str = args[i + 1];
                            if (str.Length != 28)
                                throw new ArgumentException($"Expected default string to be 28 characters! Got {str.Length} characters instead.");
                            info.StartCode = str;
                            i++;
                        }
                        break;
                    case "--codemask":
                    case "-cm":
                        {
                            var str = args[i + 1];
                            if (str.Length != 28)
                                throw new ArgumentException($"Expected codemask string to be 28 characters! Got {str.Length} characters instead.");
                            info.Mask = str;
                            i++;
                        }
                        break;
                    case "--algorithm":
                    case "-a":
                        if (!Enum.TryParse<AlgorithmMode>(args[i + 1], out var algoMode))
                            throw new ArgumentOutOfRangeException("Bad algorithm mode! Please select between: Standard OR Reverse.");
                        info.Algorithm = algoMode;
                        i++;
                        break;

                    default:
                        //Console.WriteLine($"Unknown argument {args[i]}");
                        break;
                }
            }

            return info;
        }

        private struct PasswordEntry
        {
            public string Password;
            public int Score;
            public PasswordEntry(string password, int score)
            {
                Password = password;
                Score = score;
            }
        }

        enum CtrlType
        {
            CTRL_C_EVENT = 0,
            CTRL_BREAK_EVENT = 1,
            CTRL_CLOSE_EVENT = 2,
            CTRL_LOGOFF_EVENT = 5,
            CTRL_SHUTDOWN_EVENT = 6
        }

        private static int OnExitReverseAlgorithmic(CtrlType sig)
        {
            Debug.WriteLine("Exiting!");
            if (textWriter != null && dict != null)
            {
                lock (dict)
                {
                    foreach (var pair in dict.OrderBy(o => o.Key))
                        textWriter.WriteLine($"Password [{pair.Key:X4}]:\n{pair.Value.Password}\nScore: {pair.Value.Score}\n"); // {itemsDict[(pair.Key & 0xF000) == 0x2000 ? pair.Key : (ushort)(pair.Key & ~3)]} - 
                    textWriter.Flush();
                }
            }
            Environment.Exit(0);
            return 1;
        }

        private static async Task ReverseAlgorithmicGenerator(byte[] endCharacters, int startIdx, int _itemId, CodeType type, int npcMin, int npcMax, bool[] fields, bool no7F, uint threads = 1)
        {
            // set any 'unknown' bytes to 0x25 (%)
            for (int i = 0; i < fields.Length; i++)
            {
                if (fields[i])
                {
                    endCharacters[i] = 0x25;
                }
            }

            dict = new Dictionary<ushort, PasswordEntry>();
            onShutdownFunc = OnExitReverseAlgorithmic;
            SetConsoleCtrlHandler(onShutdownFunc, true);
            var numGenerated = 0ul;
            void ReverseAlgorithmSubRoutine(byte[] currentPass, int idx, in bool[] fields, int startIdx, byte end, int threadId)
            {
                if (idx < 0)
                {
                    var decodeBuffer = new byte[28];
                    for (var i = 0; i < 28; i++)
                        decodeBuffer[i] = currentPass[i];
                    var result = Core.AnimalCrossing.Decoder.DecodeToPassword(decodeBuffer); // TODO: maybe move to bytes buffer & check type in buffer before allocating password
                    numGenerated++;

                    if (result.String0 != null)
                    {
                        if (IsPasswordValid(result))
                        {
                            // (result.HitRateIdx == 1 && result.CodeType == CodeType.Card_E_Mini)
                            if ((result.CodeType == CodeType.Popular || result.CodeType == CodeType.Magazine) && result.HitRateIdx == 4 && IsPresentValid(result.CodeType, result.ItemId))
                            {
                                // Check String0 & String1 do not contain 0x7F characters
                                if (no7F)
                                {
                                    for (int i = 0; i < 8; i++)
                                    {
                                        if (result.String0[i] == 0x7F || result.String1[i] == 0x7F)
                                        {
                                            Debug.WriteLine("contained 7F");
                                            return;
                                        }
                                    }
                                }
                                var currentPassword = currentPass.Aggregate("", (current, s) => current += Common.CharacterSet[s]);
                                var score = CodeScorer.ScoreCode(currentPassword);

                                var itemId = result.ItemId;
                                var upperValue = (itemId >> 12) & 0xF;
                                if (upperValue != 2) // since only 1 - 3 are valid this is more performant.
                                    itemId &= 0xFFFC; // mask out rotation bits

                                if (!dict.TryGetValue(itemId, out var currentEntry) || score < currentEntry.Score)
                                {
                                    dict[itemId] = new PasswordEntry(currentPassword, score);

                                    //Console.WriteLine("Valid password! Info:");
                                    Console.WriteLine($"{{Thread #{threadId}}} Password: {currentPassword}\n\tItemId: {itemId:X4} | Type: {result.CodeType} | Score: {score}");
                                    //Console.WriteLine($"Hit Rate Idx: {result.HitRateIdx}");
                                    //Console.WriteLine(result.CodeType.ToString());
                                    //Console.WriteLine($"ItemId: {itemId:X4} | Type: {result.CodeType} | Score: {score}");
                                }
                            }
                            /*else
                            {
                                Console.WriteLine($"Password decoded properly but wasn't valid. Password: {currentPass.Aggregate("", (current, s) => current += (char)s)}");
                                Console.WriteLine($"Hit Rate Idx: {result.HitRateIdx}");
                                Console.WriteLine(result.CodeType.ToString());
                                Console.WriteLine(result.ItemId.ToString("X4"));
                            }*/
                        }
                    }
                }
                else
                {
                    do
                    {

                        ReverseAlgorithmSubRoutine(currentPass, idx - 1, fields, startIdx, end, threadId);
                        if (idx == startIdx && currentPass[startIdx] == end)
                        {
                            return;
                        }

                        if (fields[idx])
                        {
                            currentPass[idx]++;
                            switch (currentPass[idx])
                            {
                                case 0x27: // after &
                                    currentPass[idx] = 0x32; // Skip rest of 2X range, we skip 0 & 1 because O and 0, l & 1 are interchangele
                                    break;
                                case 0x3A: // after 9
                                    currentPass[idx] = 0x40; // skip rest of unused values in 3X range
                                    break;
                                case 0x5B: // after Z
                                    currentPass[idx] = 0x61; // skip rest of 5X range
                                    break;
                                case 0x7B: // after z
                                    currentPass[idx] = 0xD1;
                                    break;
                            }
                        }
                    } while (currentPass[idx] < 0xD2u || !fields[idx]);

                    if (fields[idx])
                    {
                        currentPass[idx] = 0x25; // %
                    }
                }
            }

            byte spacing = (byte)(64 / threads);
            int set = 0;

            Debug.WriteLine($"spacing={spacing}");
            List<Task> tasks = new List<Task>();
            for (int i = 0; i < threads; i++)
            {
                int threadId = i;
                byte[] ourCharacters = new byte[endCharacters.Length];
                Array.Copy(endCharacters, ourCharacters, endCharacters.Length);

                int maxEditPos = 0;
                for (int z = 0; z < fields.Length; z++)
                {
                    if (fields[z])
                    {
                        maxEditPos = z;
                    }
                }

                // Adjust placement of characters now

                if (i == threads - 1)
                {
                    endCharacters[maxEditPos] = 0xFF;
                }
                else
                {
                    // 0x25 0x26 0x32 0x33 0x34 0x35 0x36 0x37
                    // 0x38 0x39 0x40 0x41 0x42 0x43 0x44 0x45
                    // 0x46 0x47 0x48 0x49 0x4A 0x4B 0x4C 0x4D
                    // 0x4E 0x4F 0x50 0x51 0x52 0x53 0x54 0x55
                    // 0x56 0x57 0x58 0x59 0x5A 0x61 0x62 0x63
                    // 0x64 0x65 0x66 0x67 0x68 0x69 0x6A 0x6B
                    // 0x6C 0x6D 0x6E 0x6F 0x70 0x71 0x72 0x73
                    // 0x74 0x75 0x76 0x77 0x78 0x79 0x7A 0xD1

                    int b = ourCharacters[maxEditPos] + spacing;
                    if (b >= 0x27 && set == 0)
                    {
                        set = 1;
                        b += 11; // -> 0x32
                    }

                    if (b >= 0x3A && set == 1)
                    {
                        set = 2;
                        b += 6; // -> 0x40
                    }

                    if (b >= 0x5B && set == 2)
                    {
                        set = 3;
                        b += 6;
                    }

                    if (b >= 0x7B)
                    {
                        b = 0xD1;
                    }

                    endCharacters[maxEditPos] = (byte)b;
                }

                Debug.WriteLine($"Thread #{threadId}: {ourCharacters.Aggregate("", (curr, b) => curr += $"{b:X2} ")}");
                tasks.Add(Task.Run(() => {
                    Console.WriteLine($"Thread #{threadId} is starting...");
                    ReverseAlgorithmSubRoutine(ourCharacters, startIdx, fields, startIdx, endCharacters[maxEditPos], threadId);
                }));
            }

            await Task.WhenAll(tasks);
            Console.WriteLine($"Passwords Generated: {numGenerated}");
        }

        static void GenerateCardEMiniPasswordThread(ushort itemId, int start, int end, int threadId, uint numPasswords, GeneratorInfo info)
        {
            var count = 0ul;
            var bestScore = int.MaxValue;
            var bestPassword = "";
            CodeType codeType = info.Type;

            var str0 = new byte[8];
            var str1 = new byte[8];

            byte[] passwordBytes = new byte[28];
            Span<byte> passwordSpan = passwordBytes.AsSpan();

            // Initialize str0's first byte
            str0[0] = (byte)start;

            // String0
            for (var char0 = start; char0 < end; char0++, str0[0]++)
            {
                for (var char1 = 0; char1 < 256; char1++, str0[1]++)
                {
                    for (var char2 = 0; char2 < 256; char2++, str0[2]++)
                    {
                        for (var char3 = 0; char3 < 256; char3++, str0[3]++)
                        {
                            for (var char4 = 0; char4 < 256; char4++, str0[4]++)
                            {
                                for (var char5 = 0; char5 < 256; char5++, str0[5]++)
                                {
                                    for (var char6 = 0; char6 < 256; char6++, str0[6]++)
                                    {
                                        for (var char7 = 0; char7 < 256; char7++, str0[7]++)
                                        {
                                            for (var char8 = 0; char8 < 256; char8++, str1[0]++)
                                            {
                                                for (var char9 = 0; char9 < 256; char9++, str1[1]++)
                                                {
                                                    for (var char10 = 0; char10 < 256; char10++, str1[2]++)
                                                    {
                                                        for (var char11 = 0; char11 < 256; char11++, str1[3]++)
                                                        {
                                                            for (var char12 = 0; char12 < 256; char12++, str1[4]++)
                                                            {
                                                                for (var char13 = 0; char13 < 256; char13++, str1[5]++)
                                                                {
                                                                    for (var char14 = 0; char14 < 256; char14++, str1[6]++)
                                                                    //for (var char15 = 0; char15 < 256; char15++, str1[7]++)
                                                                    {
                                                                        for (int npcCode = info.NpcCodeMin; npcCode <= info.NpcCodeMax; npcCode++)
                                                                        {
                                                                            Core.AnimalCrossing.Encoder.MakePassword(ref passwordSpan, codeType, 1, str0, str1, itemId, 1, (byte)npcCode);
                                                                            if (info.Restrictions == LayoutRestrictions.NoSymbols && passwordBytes.Any(o => o == '!' || o == 0xD1 || o == '@' || o == '&' || o == '%')) continue;

                                                                            var password = BytesToString(passwordBytes);
                                                                            var thisScore = CodeScorer.ScoreCode(password, info.Keyboard);
                                                                            if (thisScore < bestScore)
                                                                            {
                                                                                bestScore = thisScore;
                                                                                bestPassword = password;
                                                                                if (info.OnlyShowBestScore == false)
                                                                                    Console.WriteLine($"Thread #{threadId} => Item Id: {itemId:X4} | Password: {password} | Score: {bestScore} | Passwords Generated: {count}");
                                                                            }

                                                                            count++;

                                                                            if ((numPasswords > 0 && count >= numPasswords) || (info.ScoreThreshold > 0 && bestScore <= info.ScoreThreshold))
                                                                            {
                                                                                if (bestScore <= info.ScoreThreshold)
                                                                                    for (var i = 0; i < threads.Count; i++)
                                                                                        if (i != threadId)
                                                                                            threads[i].Abort(); // Stop other threads.

                                                                                scores.Add(new Tuple<int, string>(bestScore, bestPassword));
                                                                                return;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        static void GenerateCardEMiniPasswordThreadNo7F(ushort itemId, int start, int end, int threadId, uint numPasswords, GeneratorInfo info)
        {
            var count = 0ul;
            var bestScore = int.MaxValue;
            var bestPassword = "";
            CodeType codeType = info.Type;

            var str0 = new byte[8];
            var str1 = new byte[8];

            byte[] passwordBytes = new byte[28];
            Span<byte> passwordSpan = passwordBytes.AsSpan();

            // Initialize str0's first byte
            str0[0] = (byte)start;

            // String0
            for (var char0 = start; char0 < end; char0++, str0[0]++)
            {
                if (char0 == 0x7F) continue;
                for (var char1 = 0; char1 < 256; char1++, str0[1]++)
                {
                    if (char1 == 0x7F) continue;
                    for (var char2 = 0; char2 < 256; char2++, str0[2]++)
                    {
                        if (char2 == 0x7F) continue;
                        for (var char3 = 0; char3 < 256; char3++, str0[3]++)
                        {
                            if (char3 == 0x7F) continue;
                            for (var char4 = 0; char4 < 256; char4++, str0[4]++)
                            {
                                if (char4 == 0x7F) continue;
                                for (var char5 = 0; char5 < 256; char5++, str0[5]++)
                                {
                                    if (char5 == 0x7F) continue;
                                    for (var char6 = 0; char6 < 256; char6++, str0[6]++)
                                    {
                                        if (char6 == 0x7F) continue;
                                        for (var char7 = 0; char7 < 256; char7++, str0[7]++)
                                        {
                                            if (char7 == 0x7F) continue;
                                            for (var char8 = 0; char8 < 256; char8++, str1[0]++)
                                            {
                                                if (char8 == 0x7F) continue;
                                                for (var char9 = 0; char9 < 256; char9++, str1[1]++)
                                                {
                                                    if (char9 == 0x7F) continue;
                                                    for (var char10 = 0; char10 < 256; char10++, str1[2]++)
                                                    {
                                                        if (char10 == 0x7F) continue;
                                                        for (var char11 = 0; char11 < 256; char11++, str1[3]++)
                                                        {
                                                            if (char11 == 0x7F) continue;
                                                            for (var char12 = 0; char12 < 256; char12++, str1[4]++)
                                                            {
                                                                if (char12 == 0x7F) continue;
                                                                for (var char13 = 0; char13 < 256; char13++, str1[5]++)
                                                                {
                                                                    if (char13 == 0x7F) continue;
                                                                    for (var char14 = 0; char14 < 256; char14++, str1[6]++)
                                                                    //for (var char15 = 0; char15 < 256; char15++, str1[7]++)
                                                                    {
                                                                        if (char14 == 0x7F) continue;
                                                                        for (int npcCode = info.NpcCodeMin; npcCode <= info.NpcCodeMax; npcCode++)
                                                                        {
                                                                            Core.AnimalCrossing.Encoder.MakePassword(ref passwordSpan, codeType, 1, str0, str1, itemId, 1, (byte)npcCode);
                                                                            if (info.Restrictions == LayoutRestrictions.NoSymbols && passwordBytes.Any(o => o == '!' || o == 0xD1 || o == '@' || o == '&' || o == '%')) continue;

                                                                            var password = BytesToString(passwordBytes);
                                                                            var thisScore = CodeScorer.ScoreCode(password, info.Keyboard);
                                                                            if (thisScore < bestScore)
                                                                            {
                                                                                bestScore = thisScore;
                                                                                bestPassword = password;
                                                                                if (info.OnlyShowBestScore == false)
                                                                                    Console.WriteLine($"Thread #{threadId} => Item Id: {itemId:X4} | Password: {password} | Score: {bestScore} | Passwords Generated: {count}");
                                                                            }

                                                                            count++;

                                                                            if ((numPasswords > 0 && count >= numPasswords) || (info.ScoreThreshold > 0 && bestScore <= info.ScoreThreshold))
                                                                            {
                                                                                if (bestScore <= info.ScoreThreshold)
                                                                                    for (var i = 0; i < threads.Count; i++)
                                                                                        if (i != threadId)
                                                                                            threads[i].Abort(); // Stop other threads. TODO: change

                                                                                scores.Add(new Tuple<int, string>(bestScore, bestPassword));
                                                                                return;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        static void GenerateCardEMiniPassword(ushort itemId, uint passCount, uint numThreads, GeneratorInfo info)
        {
            threads.Clear();
            scores.Clear();

            lastItemId = itemId;
            int numPerThread = 256 / (int)numThreads;
            var total = 0;
            Action<ushort, int, int, int, uint, GeneratorInfo> threadType = info.StringRestrictions == StringRestrictions.No7FBytes ? GenerateCardEMiniPasswordThreadNo7F : GenerateCardEMiniPasswordThread;

            for (var i = 0; i < numThreads; i++)
            {
                var x = i;
                var tempTotal = total;
                var t = new Thread(() => threadType(itemId, tempTotal, x == numThreads - 1 ? 256 - tempTotal : (tempTotal + numPerThread), x, passCount, info));
                total += numPerThread;
                threads.Add(t);
                t.Start();
            }
        }

        static void GenerateAllPossibleUserCodes(ushort itemId, string player_name, string town_name)
        {
            byte[] passwordBytes = new byte[28];
            Span<byte> passwordSpan = passwordBytes.AsSpan();

            byte[] str0 = String2Bytes(player_name, 8);
            byte[] str1 = String2Bytes(town_name, 8);

            int bestScore = int.MaxValue;
            string bestPassword = "";

            int bestScoreQwerty = int.MaxValue;
            string bestPasswordQwerty = "";

            int bestScoreAlpabetical = int.MaxValue;
            string bestPasswordAlphabetical = "";

            for (int special = 0; special < 2; special++)
            {
                for (int npc = 0; npc < 256; npc++)
                {
                    Core.AnimalCrossing.Encoder.MakePasswordForced(ref passwordSpan, CodeType.User, 1, str0, str1, itemId, (byte)special, (byte)npc);
                    var password = BytesToString(passwordBytes);
                    var thisScore = CodeScorer.ScoreCode(password, CodeScorer.Keyboard.Both);
                    if (thisScore < bestScore)
                    {
                        bestScore = thisScore;
                        bestPassword = password;
                        //Console.WriteLine($"Item Id: {itemId:X4} | Password: {password} | Score: {bestScore}");
                    }

                    var qwertyScore = CodeScorer.ScoreCode(password, CodeScorer.Keyboard.QWERTY);
                    if (qwertyScore <  bestScoreQwerty)
                    {
                        bestScoreQwerty = qwertyScore;
                        bestPasswordQwerty = password;
                    }

                    var alphabeticalScore = CodeScorer.ScoreCode(password, CodeScorer.Keyboard.Alphabetical);
                    if (alphabeticalScore < bestScoreAlpabetical)
                    {
                        bestScoreAlpabetical = alphabeticalScore;
                        bestPasswordAlphabetical = password;
                    }
                }
            }

            Console.WriteLine($"\n======== Best Passwords for {itemsDict[itemId]} ========");
            Console.WriteLine($"Both - {bestPassword} - {bestScore}");
            Console.WriteLine($"QWERTY - {bestPasswordQwerty} - {bestScoreQwerty}");
            Console.WriteLine($"Alphabetical - {bestPasswordAlphabetical} - {bestScoreAlpabetical}");
        }
    }
}