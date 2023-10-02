using System.Runtime.CompilerServices;

namespace ACPasswordLibrary.Core.AnimalCrossing
{
    public enum CodeType : byte
    {
        Famicom = 0, // NES
        Popular = 1, // Popularity Contest
        Card_E = 2, // NOTE: This can only be sent to villagers in a letter.
        Magazine = 3, // Contest?
        User = 4, // Player-to-Player
        Card_E_Mini = 5, // Only one data strip? Hit rate index must be set to 4.
    }

    public static class Common
    {
        public const int PasswordLength = 28;
        public const int PasswordDataLength = 21;

        public static readonly char[] CharacterSet = {
            '¡', '¿', 'Ä', 'À', 'Á', 'Â', 'Ã', 'Å', 'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î',
            'Ï', 'Ð', 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', 'Ø', 'Ù', 'Ú', 'Û', 'Ü', 'ß', 'Þ', 'à',
            ' ', '!', '\"', 'á', 'â', '%', '&', '\'', '(', ')', '~', '♥', ',', '-', '.', '♪',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', '\x3B', '<', '=', '>', '?',
            '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
            'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'ã', '\x5C', 'ä', 'å', '_',
            'ç', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
            'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'è', 'é', 'ê', 'ë', '□',
            '�', 'ì', 'í', 'î', 'ï', '•', 'ð', 'ñ', 'ò', 'ó', 'ô', 'õ', 'ö', '⁰', 'ù', 'ú',
            '–', 'û', 'ü', 'ý', 'ÿ', 'þ', 'Ý', '¦', '§', '\x99', '\x9A', '‖', 'µ', '³', '²', '¹',
            '¯', '¬', 'Æ', 'æ', '„', '»', '«', '☀', '☁', '☂', '\xAA', '☃', '∋', '∈', '/', '∞',
            '○', '\xB1', '□', '△', '+', '⚡', '♂', '♀', '\xB8', '★', '\xBA', '\xBB', '\xBC', '\xBD', '\xBE', '\xBF',
            '×', '÷', '\xC2', '\xC3', '✉', '\xC5', '\xC6', '\xC7', '\xC8', '\xC9', '\xCA', '\xCB', '\xCC', '\n', '\xCE', '\xCF',
            ';', '#', '\xD2', '\xD3', '⚷', '\xD5', '\xD6', '\xD7', '\xD8', '\xD9', '\xDA', '\xDB', '\xDC', '\xDD', '\xDE', '\xDF',
            '\xE0', '\xE1', '\xE2', '\xE3', '\xE4', '\xE5', '\xE6', '\xE7', '\xE8', '\xE9', '\xEA', '\xEB', '\xEC', '\xED', '\xEE', '\xEF',
            '\xF0', '\xF1', '\xF2', '\xF3', '\xF4', '\xF5', '\xF6', '\xF7', '\xF8', '\xF9', '\xFA', '\xFB', '\xFC', '\xFD', '\xFE', '\xFF'
        };

        public static readonly byte[] Usable2FontNum =
        {
            0x62, 0x4b, 0x7a, 0x35, 0x63, 0x71, 0x59, 0x5a, 0x4f, 0x64, 0x74, 0x36, 0x6e, 0x6c, 0x42, 0x79,
            0x6f, 0x38, 0x34, 0x4c, 0x6b, 0x25, 0x41, 0x51, 0x6d, 0x44, 0x50, 0x49, 0x37, 0x26, 0x52, 0x73,
            0x77, 0x55, 0xd1, 0x72, 0x33, 0x45, 0x78, 0x4d, 0x43, 0x40, 0x65, 0x39, 0x67, 0x76, 0x56, 0x47,
            0x75, 0x4e, 0x69, 0x58, 0x57, 0x66, 0x54, 0x4a, 0x46, 0x53, 0x48, 0x70, 0x32, 0x61, 0x6a, 0x68
        };

        public static readonly byte[] ChangeCodeTable =
        {
            0xF0,0x83,0xFD,0x62,0x93,0x49,0x0D,0x3E,0xE1,0xA4,0x2B,0xAF,0x3A,0x25,0xD0,0x82,
            0x7F,0x97,0xD2,0x03,0xB2,0x32,0xB4,0xE6,0x09,0x42,0x57,0x27,0x60,0xEA,0x76,0xAB,
            0x2D,0x65,0xA8,0x4D,0x8B,0x95,0x01,0x37,0x59,0x79,0x33,0xAC,0x2F,0xAE,0x9F,0xFE,
            0x56,0xD9,0x04,0xC6,0xB9,0x28,0x06,0x5C,0x54,0x8D,0xE5,0x00,0xB3,0x7B,0x5E,0xA7,
            0x3C,0x78,0xCB,0x2E,0x6D,0xE4,0xE8,0xDC,0x40,0xA0,0xDE,0x2C,0xF5,0x1F,0xCC,0x85,
            0x71,0x3D,0x26,0x74,0x9C,0x13,0x7D,0x7E,0x66,0xF2,0x9E,0x02,0xA1,0x53,0x15,0x4F,
            0x51,0x20,0xD5,0x39,0x1A,0x67,0x99,0x41,0xC7,0xC3,0xA6,0xC4,0xBC,0x38,0x8C,0xAA,
            0x81,0x12,0xDD,0x17,0xB7,0xEF,0x2A,0x80,0x9D,0x50,0xDF,0xCF,0x89,0xC8,0x91,0x1B,
            0xBB,0x73,0xF8,0x14,0x61,0xC2,0x45,0xC5,0x55,0xFC,0x8E,0xE9,0x8A,0x46,0xDB,0x4E,
            0x05,0xC1,0x64,0xD1,0xE0,0x70,0x16,0xF9,0xB6,0x36,0x44,0x8F,0x0C,0x29,0xD3,0x0E,
            0x6F,0x7C,0xD7,0x4A,0xFF,0x75,0x6C,0x11,0x10,0x77,0x3B,0x98,0xBA,0x69,0x5B,0xA3,
            0x6A,0x72,0x94,0xD6,0xD4,0x22,0x08,0x86,0x31,0x47,0xBE,0x87,0x63,0x34,0x52,0x3F,
            0x68,0xF6,0x0F,0xBF,0xEB,0xC0,0xCE,0x24,0xA5,0x9A,0x90,0xED,0x19,0xB8,0xB5,0x96,
            0xFA,0x88,0x6E,0xFB,0x84,0x23,0x5D,0xCD,0xEE,0x92,0x58,0x4C,0x0B,0xF7,0x0A,0xB1,
            0xDA,0x35,0x5F,0x9B,0xC9,0xA9,0xE7,0x07,0x1D,0x18,0xF3,0xE3,0xF1,0xF4,0xCA,0xB0,
            0x6B,0x30,0xEC,0x4B,0x48,0x1C,0xAD,0xE2,0x21,0x1E,0xA2,0xBD,0x5A,0xD8,0x43,0x7A
        };

        public static readonly int[] PrimeNumbers =
        {
            0x011, 0x013, 0x017, 0x01D, 0x01F, 0x025, 0x029, 0x02B, 0x02F, 0x035, 0x03B, 0x03D, 0x043, 0x047, 0x049, 0x04F,
            0x053, 0x059, 0x061, 0x065, 0x067, 0x06B, 0x06D, 0x071, 0x07F, 0x083, 0x089, 0x08B, 0x095, 0x097, 0x09D, 0x0A3,
            0x0A7, 0x0AD, 0x0B3, 0x0B5, 0x0BF, 0x0C1, 0x0C5, 0x0C7, 0x0D3, 0x0DF, 0x0E3, 0x0E5, 0x0E9, 0x0EF, 0x0F1, 0x0FB,
            0x101, 0x107, 0x10D, 0x10F, 0x115, 0x119, 0x11B, 0x125, 0x133, 0x137, 0x139, 0x13D, 0x14B, 0x151, 0x15B, 0x15D,
            0x161, 0x167, 0x16F, 0x175, 0x17B, 0x17F, 0x185, 0x18D, 0x191, 0x199, 0x1A3, 0x1A5, 0x1AF, 0x1B1, 0x1B7, 0x1BB,
            0x1C1, 0x1C9, 0x1CD, 0x1CF, 0x1D3, 0x1DF, 0x1E7, 0x1EB, 0x1F3, 0x1F7, 0x1FD, 0x209, 0x20B, 0x21D, 0x223, 0x22D,
            0x233, 0x239, 0x23B, 0x241, 0x24B, 0x251, 0x257, 0x259, 0x25F, 0x265, 0x269, 0x26B, 0x277, 0x281, 0x283, 0x287,
            0x28D, 0x293, 0x295, 0x2A1, 0x2A5, 0x2AB, 0x2B3, 0x2BD, 0x2C5, 0x2CF, 0x2D7, 0x2DD, 0x2E3, 0x2E7, 0x2EF, 0x2F5,
            0x2F9, 0x301, 0x305, 0x313, 0x31D, 0x329, 0x32B, 0x335, 0x337, 0x33B, 0x33D, 0x347, 0x355, 0x359, 0x35B, 0x35F,
            0x36D, 0x371, 0x373, 0x377, 0x38B, 0x38F, 0x397, 0x3A1, 0x3A9, 0x3AD, 0x3B3, 0x3B9, 0x3C7, 0x3CB, 0x3D1, 0x3D7,
            0x3DF, 0x3E5, 0x3F1, 0x3F5, 0x3FB, 0x3FD, 0x407, 0x409, 0x40F, 0x419, 0x41B, 0x425, 0x427, 0x42D, 0x43F, 0x443,
            0x445, 0x449, 0x44F, 0x455, 0x45D, 0x463, 0x469, 0x47F, 0x481, 0x48B, 0x493, 0x49D, 0x4A3, 0x4A9, 0x4B1, 0x4BD,
            0x4C1, 0x4C7, 0x4CD, 0x4CF, 0x4D5, 0x4E1, 0x4EB, 0x4FD, 0x4FF, 0x503, 0x509, 0x50B, 0x511, 0x515, 0x517, 0x51B,
            0x527, 0x529, 0x52F, 0x551, 0x557, 0x55D, 0x565, 0x577, 0x581, 0x58F, 0x593, 0x595, 0x599, 0x59F, 0x5A7, 0x5AB,
            0x5AD, 0x5B3, 0x5BF, 0x5C9, 0x5CB, 0x5CF, 0x5D1, 0x5D5, 0x5DB, 0x5E7, 0x5F3, 0x5FB, 0x607, 0x60D, 0x611, 0x617,
            0x61F, 0x623, 0x62B, 0x62F, 0x63D, 0x641, 0x647, 0x649, 0x64D, 0x653, 0x655, 0x65B, 0x665, 0x679, 0x67F, 0x683
        };

        private static readonly int[] key_idx = { 0x12, 0x09 };

        private static readonly string[] mMpswd_transposition_cipher_char0_table = new string[16]
        {
            "NiiMasaru", // Animal Crossing programmer (worked on the original N64 title)
            "KomatsuKunihiro", // Animal Crossing programmer (AF, AF+, AC, AFe+)
            "TakakiGentarou", // Animal Crossing programmer
            "MiyakeHiromichi", // Animal Crossing programmer
            "HayakawaKenzo", // Animal Crossing programmer
            "KasamatsuShigehiro", // Animal Crossing programmer
            "SumiyoshiNobuhiro", // Animal Crossing programmer
            "NomaTakafumi", // Animal Crossing programmer
            "EguchiKatsuya", // Animal Crossing director
            "NogamiHisashi", // Animal Crossing director
            "IidaToki", // Animal Crossing screen designer
            "IkegawaNoriko", // Animal Crossing character design
            "KawaseTomohiro", // Animal Crossing NES/Famicom emulator programmer
            "BandoTaro", // Animal Crossing Sound Effects programmer
            "TotakaKazuo", // Animal Crossing Sound Director (Kazumi Totaka)
            "WatanabeKunio" // Animal Crossing Script member (made text?)
        };

        private static readonly string[] mMpswd_transposition_cipher_char1_table = new string[16]
        {
            "RichAmtower", // Localization Manager @ Nintendo of America https://www.linkedin.com/in/rich-amtower-83222a1, https://nintendo.fandom.com/wiki/Rich_Amtower
            "KyleHudson", // Former Product Testing Manager @ Nintendo of America https://metroid.fandom.com/wiki/Kyle_Hudson
            "MichaelKelbaugh", // Debugger & Beta Tester @ Nintendo of America https://nintendo.fandom.com/wiki/Michael_Kelbaugh
            "RaycholeLAneff", // Raychole L'Anett - Director of Engineering Services @ Nintendo of America https://metroid.fandom.com/wiki/Raychole_L%27Anett
            "LeslieSwan", // Senior Editor @ Nintendo Power, VA, Nintendo of America localization manager @ Treehouse. https://www.mariowiki.com/Leslie_Swan
            "YoshinobuMantani", // Nintendo of America employee (QA, Debugger) https://www.imdb.com/name/nm1412191/
            "KirkBuchanan", // Senior Product Testing Manager @ Nintendo of America https://leadferret.com/directory/person/kirk-buchanan/16977208
            "TimOLeary", // Localization Manager & Translator @ Nintendo of America https://nintendo.fandom.com/wiki/Tim_O%27Leary
            "BillTrinen", // Senior Product Marketing Manager, Translator, & Interpreter @ Nintendo of America https://en.wikipedia.org/wiki/Bill_Trinen
            "nAkAyOsInoNyuuSankin", // Translates to "good bacteria" (善玉菌)
            "zendamaKINAKUDAMAkin", // Translates to "bad bacteria" (悪玉菌)
            "OishikutetUYOKUNARU", // Translates to "It's becoming really delicious." "It's becoming strongly delicious."
            "AsetoAminofen", // Translates to Acetaminophen. Like the drug.
            "fcSFCn64GCgbCGBagbVB", // fc = Famicom | SFC = Super Famicom | n64 = Nintendo 64 | GC = GameCube | gb = GameBoy | CGB = GameBoy Color | agb = GameBoy Advance | VB = Virtual Boy
            "YossyIsland", // Yoshi's Island. The game.
            "KedamonoNoMori" // Translates to "Animal Forest" or "Beast Forest"
        };

        private static readonly string[][] mMpswd_transposition_cipher_char_table =
            new string[2][] { mMpswd_transposition_cipher_char0_table, mMpswd_transposition_cipher_char1_table };

        public static readonly int[][] mMpswd_select_idx_table = {
            new[] {0x11, 0x0B, 0x00, 0x0A, 0x0C, 0x06, 0x08, 0x04},
            new[] {0x03, 0x08, 0x0B, 0x10, 0x04, 0x06, 0x09, 0x13},
            new[] {0x09, 0x0E, 0x11, 0x12, 0x0B, 0x0A, 0x0C, 0x02},
            new[] {0x00, 0x02, 0x01, 0x04, 0x12, 0x0A, 0x0C, 0x08},
            new[] {0x11, 0x13, 0x10, 0x07, 0x0C, 0x08, 0x02, 0x09},
            new[] {0x10, 0x03, 0x01, 0x08, 0x12, 0x04, 0x07, 0x06},
            new[] {0x13, 0x06, 0x0A, 0x11, 0x03, 0x10, 0x08, 0x09},
            new[] {0x11, 0x07, 0x12, 0x10, 0x0C, 0x02, 0x0B, 0x00},
            new[] {0x06, 0x02, 0x0C, 0x01, 0x08, 0x0E, 0x00, 0x10},
            new[] {0x13, 0x10, 0x0B, 0x08, 0x11, 0x03, 0x06, 0x0E},
            new[] {0x12, 0x0C, 0x02, 0x07, 0x0A, 0x0B, 0x01, 0x0E},
            new[] {0x08, 0x00, 0x0E, 0x02, 0x07, 0x0B, 0x0C, 0x11},
            new[] {0x09, 0x03, 0x02, 0x00, 0x0B, 0x08, 0x0E, 0x0A},
            new[] {0x0A, 0x0B, 0x0C, 0x10, 0x13, 0x07, 0x11, 0x08},
            new[] {0x13, 0x08, 0x06, 0x01, 0x11, 0x09, 0x0E, 0x0A},
            new[] {0x09, 0x07, 0x11, 0x0C, 0x13, 0x0A, 0x01, 0x0B}
        };

        public static void Change8BitsCode(in ReadOnlySpan<byte> password, ref Span<byte> condensedPassword)
        {
            int passwordIdx = 0;
            int bitCount = 0;

            for (int i = 0; i < PasswordDataLength * 8; i++)
            {
                int sourceByteIdx = i / 6;
                int sourceBitIdx = i % 6;

                byte bit = (byte)((password[sourceByteIdx] >> sourceBitIdx) & 1);
                condensedPassword[passwordIdx] |= (byte)(bit << bitCount);

                bitCount++;
                if (bitCount == 8)
                {
                    bitCount = 0;
                    passwordIdx++;
                }
            }
        }

        public static void TranspositionCipher(ref Span<byte> password, bool negate, int keyIndex)
        {
            int modifier = negate ? -1 : 1;
            ReadOnlySpan<char> cipher = mMpswd_transposition_cipher_char_table[keyIndex][password[key_idx[keyIndex]] & 0xF];

            int cipherIdx = 0;

            for (int i = 0; i < 21; i++)
            {
                if (i == key_idx[keyIndex]) continue;
                password[i] = (byte)(password[i] + (byte)cipher[cipherIdx++] * modifier);

                if (cipherIdx >= cipher.Length)
                    cipherIdx = 0;
            }
        }

        public static void TranspositionCipher2(ref Span<byte> password, bool negate, int keyIndex)
        {
            int modifier = negate ? -1 : 1;
            ReadOnlySpan<char> cipher = mMpswd_transposition_cipher_char_table[keyIndex][password[key_idx[keyIndex]] & 0xF];

            int cipherIdx = 0;
            int cipherLength = cipher.Length;

            // Process elements before key_idx[keyIndex]
            for (int i = 0; i < key_idx[keyIndex]; i++)
            {
                password[i] = (byte)(password[i] + (byte)cipher[cipherIdx] * modifier);
                cipherIdx = (cipherIdx + 1) % cipherLength;
            }

            // Process elements after key_idx[keyIndex]
            for (int i = key_idx[keyIndex] + 1; i < 21; i++)
            {
                password[i] = (byte)(password[i] + (byte)cipher[cipherIdx] * modifier);
                cipherIdx = (cipherIdx + 1) % cipherLength;
            }
        }


        public static void BitReverse(ref Span<byte> password)
        {
            for (int i = 0; i < 21; i++)
            {
                if (i != 1)
                {
                    password[i] ^= 0xFF;
                }
            }
        }

        public static void BitReverse2(ref Span<byte> password)
        {
            // Process elements before index 1
            for (int i = 0; i < 1; i++)
            {
                password[i] ^= 0xFF;
            }

            // Skip index 1

            // Process elements after index 1
            for (int i = 2; i < 21; i++)
            {
                password[i] ^= 0xFF;
            }
        }


        public static void BitArrangeReverse(ref Span<byte> password)
        {
            Span<byte> data = stackalloc byte[20];
            Span<byte> outputData = stackalloc byte[20];

            password[..1].CopyTo(data[..1]);
            password.Slice(2, 19).CopyTo(data.Slice(1, 19));

            int outIdx = 0;
            for (int i = 19; i > -1; i--, outIdx++)
            {
                for (int b = 7; b > -1; b--)
                {
                    outputData[outIdx] |= (byte)(((data[i] >> b) & 1) << (7 - b));
                }
            }

            outputData[..1].CopyTo(password[..1]);
            outputData.Slice(1, 19).CopyTo(password.Slice(2, 19));
        }

        /// <summary>
        /// Reverses the order of bits in a given password span, while ignoring the bit at index 1.
        /// This version of the function is optimized for performance, and it is faster than the previous implementation.
        /// </summary>
        /// <param name="password">The input password span to process.</param>
        public static void BitArrangeReverse2(ref Span<byte> password)
        {
            Span<byte> data = stackalloc byte[21];
            password.CopyTo(data);

            // Helper function to reverse bits in a byte
            static byte ReverseBits(byte b)
            {
                b = (byte)((b & 0xF0) >> 4 | (b & 0x0F) << 4);
                b = (byte)((b & 0xCC) >> 2 | (b & 0x33) << 2);
                return (byte)((b & 0xAA) >> 1 | (b & 0x55) << 1);
            }

            // Process elements before index 1 & at index 20
            password[0] = ReverseBits(data[20]);
            password[20] = ReverseBits(data[0]);

            // Skip index 1

            // Process elements after index 1
            for (int i = 2, j = 19; i < 20; i++, j--)
            {
                password[i] = ReverseBits(data[j]);
            }
        }


        public static void BitArrangeReverse3(ref Span<byte> password)
        {
            // Helper function to reverse bits in a byte
            static byte ReverseBits(byte b)
            {
                b = (byte)((b & 0xF0) >> 4 | (b & 0x0F) << 4);
                b = (byte)((b & 0xCC) >> 2 | (b & 0x33) << 2);
                return (byte)((b & 0xAA) >> 1 | (b & 0x55) << 1);
            }

            // Swap the corresponding bytes in the span, ignoring password[1]
            for (int i = 0, j = 20; i < j; i++, j--)
            {
                if (i == 1)
                {
                    i++;
                }

                byte temp = password[i];
                password[i] = ReverseBits(password[j]);
                password[j] = ReverseBits(temp);
            }

            // Reverse the bits for the middle byte, which is password[10]
            password[10] = ReverseBits(password[10]);
        }



        public static void BitShift(ref Span<byte> password, int shift)
        {
            Span<byte> data = stackalloc byte[20];
            Span<byte> outData = stackalloc byte[20];

            password[..1].CopyTo(data[..1]);
            password.Slice(2, 19).CopyTo(data.Slice(1, 19));

            if (shift > 0)
            {
                int dstPosition = shift / 8;
                int dstOffset = shift % 8;

                for (int i = 0; i < 20; i++)
                {
                    outData[(i + dstPosition) % 20] = (byte)((data[i] << dstOffset) | (data[(i + 19) % 20] >> (8 - dstOffset)));
                }

                outData[..1].CopyTo(password[..1]);
                outData.Slice(1, 19).CopyTo(password.Slice(2, 19));
            }
            else if (shift < 0)
            {
                for (int i = 0; i < 20; i++)
                {
                    outData[i] = data[19 - i];
                }

                shift = -shift;
                int dstPosition = shift / 8;
                int dstOffset = shift % 8;

                for (int i = 0; i < 20; i++)
                {
                    data[(i + dstPosition) % 20] = outData[i];
                }

                for (int i = 0; i < 20; i++)
                {
                    outData[i] = (byte)((data[i] >> dstOffset) | ((data[(i + 19) % 20]) << (8 - dstOffset)));
                }

                // Copy reversed to password.
                for (int i = 0, idx = 0; i < 20; i++)
                {
                    if (i == 1) idx++;
                    password[idx++] = outData[19 - i];
                }
            }
        }

        /// <summary>
        /// Shifts the bits of the password Span by the specified amount.
        /// </summary>
        /// <param name="password">The input Span<byte> containing the password. The length of password must be 21, and the second element (index 1) is ignored.</param>
        /// <param name="shift">The number of bits to shift. Positive values shift the bits to the right, while negative values shift the bits to the left. The shift value must be one of -5, -3, 3, or 5.</param>
        /// <remarks>
        /// This function performs a bitwise shift on the input password Span. The shift amount can be positive or negative, with positive values shifting bits to the right and negative values shifting bits to the left. The second element of the password Span (index 1) is ignored during the shift operation.
        /// </remarks>
        public static void BitShift2(ref Span<byte> password, int shift)
        {
            Span<byte> data = stackalloc byte[20];

            // Copy password data, ignoring index 1
            password[..1].CopyTo(data[..1]);
            password.Slice(2, 19).CopyTo(data.Slice(1, 19));

            // Adjust shift for negative values
            shift = (shift < 0) ? (160 + shift) : shift;

            // Calculate shift values
            int dstPosition = (shift / 8) % 20;
            int dstOffset = shift % 8;

            // Perform bit shift
            for (int i = 0; i < 20; i++)
            {
                int outIdx = (i + dstPosition) % 20;
                password[outIdx == 0 ? 0 : outIdx + 1] = (byte)((data[i] << dstOffset) | (data[(i + 19) % 20] >> (8 - dstOffset)));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void mMpswd_get_RSA_key_code(out int p, out int q, out int prime2, out ReadOnlySpan<int> selectTable, in ReadOnlySpan<byte> password)
        {
            int bits01 = password[15] & 3;
            int bits23 = (password[15] >> 2) & 3;

            if (bits01 == 3)
            {
                bits01 ^= bits23;
                if (bits01 == 3) bits01 = 0;
            }

            if (bits23 == 3)
            {
                bits23 = (bits01 + 1) & 3;
                if (bits23 == 3) bits23 = 1;
            }
            else if (bits01 == bits23)
            {
                bits23 = (bits01 + 1) & 3;
                if (bits23 == 3) bits23 = 1;
            }

            p = PrimeNumbers[bits01];
            q = PrimeNumbers[bits23];
            prime2 = PrimeNumbers[password[5]];
            selectTable = mMpswd_select_idx_table[(password[15] >> 4) & 0xF];
        }
    }
}