namespace ACPasswordLibrary.Core.DnMPlus
{
    public static class Common
    {
        public const int PASSWORD_STRING_SIZE = 22;
        public const int PASSWORD_DATA_SIZE = 17;

        public const int PASSWORD_BITS_COUNT = PASSWORD_STRING_SIZE * 6;
        public const int PASSWORD_DATA_SCRAMBLE_BITS = (PASSWORD_DATA_SIZE - 1) * 8;

        public const int PRESENT_FTR_START = 0;
        public const int PRESENT_FTR_COUNT = 0x5DC;
        public const int PRESENT_CPT_START = PRESENT_FTR_START + PRESENT_FTR_COUNT;
        public const int PRESENT_CPT_COUNT = 0x40;
        public const int PRESENT_WAL_START = 0x7D0;
        public const int PRESENT_WAL_COUNT = 0x40;
        public const int PRESENT_CLO_START = 0x9C4;
        public const int PRESENT_CLO_COUNT = 0xFF;

        public static readonly string[] usable_to_fontnum = new string[64]
        {
            "あ", "い", "う", "え", "お", "か", "き", "く", "け", "こ", "さ", "し", "す", "せ", "そ", "た",
            "ち", "つ", "て", "と", "な", "に", "ぬ", "ね", "の", "は", "ひ", "ふ", "へ", "ほ", "ま", "み",
            "む", "め", "も", "や", "ゆ", "よ", "ら", "り", "る", "れ", "ろ", "わ", "を", "ん", "が", "ぎ",
            "ぐ", "げ", "ご", "ざ", "じ", "ず", "ぜ", "ぞ", "だ", "ぢ", "づ", "で", "ど", "び", "ぶ", "べ"
        };

        public static readonly string[] CharacterSet = new string[256]
        {
            "あ", "い", "う", "え", "お", "か", "き", "く", "け", "こ", "さ", "し", "す", "せ", "そ", "た",
            "ち", "つ", "て", "と", "な", "に", "ぬ", "ね", "の", "は", "ひ", "ふ", "へ", "ほ", "ま", "み",
            " ", "!", "\"", "む", "め", "%", "&", "'", "(", ")", "~", "♥", ", ", "-", ".", "♪",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", "🌢", "<", "+", ">", "?",
            "@", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
            "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "も", "💢", "や", "ゆ", "_",
            "よ", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
            "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "ら", "り", "る", "れ", "�",
            "□", "。", "｢", "｣", "、", "･", "ヲ", "ァ", "ィ", "ゥ", "ェ", "ォ", "ャ", "ュ", "ョ", "ッ",
            "ー", "ア", "イ", "ウ", "エ", "オ", "カ", "キ", "ク", "ケ", "コ", "サ", "シ", "ス", "セ", "ソ",
            "タ", "チ", "ツ", "テ", "ト", "ナ", "ニ", "ヌ", "ネ", "ノ", "ハ", "ヒ", "フ", "ヘ", "ホ", "マ",
            "ミ", "ム", "メ", "モ", "ヤ", "ユ", "ヨ", "ラ", "リ", "ル", "レ", "ロ", "ワ", "ン", "ヴ", "☺",
            "ろ", "わ", "を", "ん", "ぁ", "ぃ", "ぅ", "ぇ", "ぉ", "ゃ", "ゅ", "ょ", "っ", "\n", "ガ", "ギ",
            "グ", "ゲ", "ゴ", "ザ", "ジ", "ズ", "ゼ", "ゾ", "ダ", "ヂ", "ヅ", "デ", "ド", "バ", "ビ", "ブ",
            "ベ", "ボ", "パ", "ピ", "プ", "ペ", "ポ", "が", "ぎ", "ぐ", "げ", "ご", "ざ", "じ", "ず", "ぜ",
            "ぞ", "だ", "ぢ", "づ", "で", "ど", "ば", "び", "ぶ", "べ", "ぼ", "ぱ", "ぴ", "ぷ", "ぺ", "ぽ"
        };

        public static readonly byte[] HitRateValues =
        {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
        };


        public static readonly ushort[] pswd_famicom_list =
        {
            0x36A, 0x36B, 0x36C, 0x36D,
            0x36E, 0x36F, 0x370, 0x371,
            0x372, 0x373, 0x374, 0x375,
            0x376, 0x377, 0x378, 0x379,
            0x37A, 0x37B, 0x37C
        };

        public static readonly ushort[] pswd_present_list =
        {
            0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
            0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
            0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
            0x0018, 0x0019, 0x001a, 0x001b, 0x001c, 0x001d, 0x001e, 0x001f,
            0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0028,
            0x0029, 0x002a, 0x002b, 0x002e, 0x002f, 0x0030, 0x0031, 0x0032,
            0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003a,
            0x003b, 0x003c, 0x003d, 0x003e, 0x003f, 0x0040, 0x0041, 0x0042,
            0x0043, 0x0044, 0x0045, 0x0046, 0x0047, 0x0048, 0x0049, 0x004a,
            0x004b, 0x004c, 0x004d, 0x004e, 0x004f, 0x0050, 0x0051, 0x0052,
            0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059, 0x005a,
            0x005b, 0x005c, 0x005d, 0x005e, 0x005f, 0x0060, 0x0061, 0x0062,
            0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006a,
            0x006b, 0x006c, 0x006d, 0x006e, 0x006f, 0x0070, 0x0071, 0x0072,
            0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078, 0x0079, 0x007a,
            0x007b, 0x007c, 0x007d, 0x007f, 0x0080, 0x0081, 0x0082, 0x0083,
            0x0084, 0x0085, 0x0086, 0x0087, 0x0088, 0x0089, 0x008a, 0x008b,
            0x008c, 0x008d, 0x008e, 0x008f, 0x0090, 0x0091, 0x0092, 0x0093,
            0x0094, 0x0095, 0x0096, 0x0097, 0x0098, 0x0099, 0x009a, 0x009b,
            0x009c, 0x009d, 0x009e, 0x009f, 0x00a0, 0x00a1, 0x00a2, 0x00a3,
            0x00a4, 0x00a5, 0x00a6, 0x00a7, 0x00a8, 0x00a9, 0x00aa, 0x00ab,
            0x00ac, 0x00ad, 0x00ae, 0x00af, 0x00b0, 0x00b1, 0x00b2, 0x00b3,
            0x00b4, 0x00b5, 0x00b6, 0x00b7, 0x00b8, 0x00b9, 0x00ba, 0x00bb,
            0x00bd, 0x00be, 0x00bf, 0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4,
            0x00c6, 0x00c7, 0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd,
            0x00ce, 0x00cf, 0x00d0, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6,
            0x00d7, 0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de,
            0x00df, 0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6,
            0x00e7, 0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee,
            0x00ef, 0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6,
            0x00f7, 0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe,
            0x00ff, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106,
            0x0107, 0x0108, 0x0109, 0x010a, 0x010b, 0x010c, 0x010d, 0x010e,
            0x010f, 0x0110, 0x0111, 0x0112, 0x0113, 0x0114, 0x0115, 0x0116,
            0x0117, 0x0118, 0x0119, 0x011a, 0x011b, 0x011c, 0x011d, 0x011e,
            0x011f, 0x0120, 0x0121, 0x0122, 0x0123, 0x0124, 0x0125, 0x0126,
            0x0127, 0x0128, 0x0129, 0x012a, 0x012b, 0x012c, 0x012d, 0x012e,
            0x012f, 0x0130, 0x0131, 0x0132, 0x0134, 0x0135, 0x0136, 0x0137,
            0x0138, 0x0139, 0x013a, 0x013b, 0x013c, 0x013d, 0x013e, 0x013f,
            0x0140, 0x0141, 0x0142, 0x0143, 0x0144, 0x0145, 0x0146, 0x0147,
            0x0148, 0x0149, 0x014a, 0x014b, 0x014c, 0x014d, 0x014e, 0x014f,
            0x0150, 0x0151, 0x0152, 0x0153, 0x0154, 0x0155, 0x0156, 0x0157,
            0x0158, 0x0159, 0x015a, 0x015b, 0x015c, 0x015d, 0x015e, 0x015f,
            0x0160, 0x0161, 0x0162, 0x0163, 0x0164, 0x0165, 0x0166, 0x0167,
            0x0168, 0x0169, 0x016a, 0x016b, 0x037d, 0x037e, 0x037f, 0x0380,
            0x0381, 0x0382, 0x0383, 0x0384, 0x0385, 0x0386, 0x0387, 0x0388,
            0x0389, 0x038a, 0x038b, 0x038c, 0x038d, 0x038e, 0x038f, 0x0390,
            0x0391, 0x0392, 0x0393, 0x0394, 0x0395, 0x0396, 0x0397, 0x0398,
            0x0399, 0x039a, 0x039b, 0x039c, 0x039d, 0x039e, 0x039f, 0x03a0,
            0x03a1, 0x03a2, 0x03a3, 0x03a4, 0x03a5, 0x03a6, 0x03a7, 0x03a8,
            0x03a9, 0x03aa, 0x03ab, 0x03ac, 0x03ad, 0x03ae, 0x03af, 0x03b0,
            0x03b1, 0x03b2, 0x03b3, 0x03b4, 0x03b5, 0x03b6, 0x03b7, 0x03b8,
            0x03b9, 0x03ba, 0x03bb, 0x03bc, 0x03bd, 0x03be, 0x03bf, 0x03c0,
            0x03c1, 0x03c2, 0x03c3, 0x03c4, 0x03c5, 0x03c6, 0x03c7, 0x03c8,
            0x03c9, 0x03ca, 0x03cb, 0x03cc, 0x03cd, 0x03ce, 0x03cf, 0x03d0,
            0x03d1, 0x03d2, 0x03d3, 0x03d4, 0x03d5, 0x03d6, 0x03d7, 0x03d8,
            0x03d9, 0x03da, 0x03db, 0x03dc, 0x03dd, 0x03de, 0x03e8, 0x03e9,
            0x03ea, 0x03eb, 0x03ec, 0x03ed, 0x03ee, 0x03f0, 0x03f1, 0x03f2,
            0x03f3, 0x03f4, 0x03f5, 0x03f6, 0x03f7, 0x03f8, 0x03f9, 0x03fa,
            0x03fb, 0x0404, 0x0405, 0x0406, 0x0407, 0x0408, 0x0409, 0x040a,
            0x040b, 0x040c, 0x040d, 0x040e, 0x040f, 0x0410, 0x0411, 0x0412,
            0x0413, 0x0414, 0x0415, 0x0416, 0x0417, 0x0418, 0x0419, 0x041a,
            0x041b, 0x041c, 0x041d, 0x041e, 0x041f, 0x0420, 0x0421, 0x0422,
            0x0423, 0x0424, 0x0425, 0x0426, 0x0427, 0x0428, 0x0429, 0x042a,
            0x042b, 0x042c, 0x042d, 0x042e, 0x042f, 0x0430, 0x0431, 0x0432,
            0x0433, 0x0434, 0x0435, 0x0436, 0x0437, 0x0438, 0x0439, 0x043a,
            0x043b, 0x043c, 0x043d, 0x043e, 0x0467, 0x0468, 0x0469, 0x046a,
            0x046b, 0x046c, 0x046d, 0x046e, 0x046f, 0x0470, 0x0471, 0x0472,
            0x0473, 0x0474, 0x0475, 0x0478, 0x0479, 0x047a
        };

        public static ushort GetPresentItemNo(ushort present)
        {
            if (present == 0xFFFF) return 0xFFFF;
            if (present < PRESENT_CPT_START)
            {
                return present < 0x400 ? (ushort)(0x1000 | (present << 2)) : (ushort)(0x3000 | ((present - 0x400) << 2));
            }
            else if (present < PRESENT_WAL_START)
            {
                return (ushort)(0x2600 + (present - PRESENT_CPT_START));
            }
            else if (present < PRESENT_CLO_START)
            {
                return (ushort)(0x2700 + (present - PRESENT_WAL_START));
            }
            else
            {
                return (ushort)(0x2400 + (present - PRESENT_CLO_START));
            }
        }

        public static bool CheckHPMail_presentlist(ushort present_idx)
        {
            if (present_idx == 0xFFFF) return true;
            if (Array.IndexOf(pswd_present_list, present_idx) != -1) return true;
            if ((ushort)(present_idx - PRESENT_CPT_START) < PRESENT_CPT_COUNT) return true;
            if ((ushort)(present_idx - PRESENT_WAL_START) < PRESENT_WAL_COUNT) return true;

            ushort shirt_idx = (ushort)(present_idx - PRESENT_CLO_START);
            if ((shirt_idx < 18 || shirt_idx > 25) && shirt_idx < PRESENT_CLO_COUNT) return true;
            return false;
        }

        /// <summary>
        /// Shifts bits in an array by a given amount and count
        /// </summary>
        /// <param name="bits">Source bits array</param>
        /// <param name="count">Number of bits to shift</param>
        /// <param name="shift_amount">Shift offset</param>
        internal static void mMpswd_shift(in byte[] bits, int count, int shift_amount)
        {
            byte[] temp_bits = new byte[Common.PASSWORD_BITS_COUNT];
            int shift_pos = -shift_amount;

            for (int i = 0; i < count; i++)
            {
                if (shift_pos >= count)
                {
                    shift_pos = 0;
                }
                if (shift_pos < 0)
                {
                    shift_pos += count;
                }

                temp_bits[i] = bits[shift_pos++];
            }

            Buffer.BlockCopy(temp_bits, 0, bits, 0, Common.PASSWORD_BITS_COUNT);
        }

        /// <summary>
        /// Reverses bits in an array
        /// </summary>
        /// <param name="bits">The bit array</param>
        /// <param name="count">The number of bits to reverse</param>
        internal static void mMpswd_reverse(in byte[] bits, int count)
        {
            byte[] temp_bits = new byte[Common.PASSWORD_BITS_COUNT];

            for (int i = 0; i < count; i++)
            {
                temp_bits[i] = bits[count - (i + 1)];
            }

            Buffer.BlockCopy(temp_bits, 0, bits, 0, Common.PASSWORD_BITS_COUNT);
        }

        /// <summary>
        /// Flips bits in an array for a given count
        /// </summary>
        /// <param name="bits">The bit array</param>
        /// <param name="count">The number of bits to flip</param>
        internal static void mMpswd_hanten(in byte[] bits, int count)
        {
            byte[] temp_bits = new byte[Common.PASSWORD_BITS_COUNT];

            for (int i = 0; i < count; i++)
            {
                temp_bits[i] = (byte)((~bits[i]) & 1); // an xor would've sufficied but the devs did it this way lol
            }

            Buffer.BlockCopy(temp_bits, 0, bits, 0, Common.PASSWORD_BITS_COUNT);
        }
    }
}