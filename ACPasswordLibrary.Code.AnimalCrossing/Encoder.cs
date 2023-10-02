using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using static ACPasswordLibrary.Core.AnimalCrossing.Common;

namespace ACPasswordLibrary.Core.AnimalCrossing
{
    public static class Encoder
    {
        // Constants
        private const int PrimeNumbersLength = 256;
        private const int NumPrimes = 4;

        // Lookup table with precomputed values for all possible bytes (0-255)
        private static readonly int[][][][] PrecomputedValues;

        static Encoder()
        {
            // Initialize prime lookup table. This makes ChangeRSACipher O(1) rather than O(n).
            int[] primes = { 17, 19, 23, 29 };
            PrecomputedValues = new int[NumPrimes][][][];

            for (int p = 0; p < NumPrimes; p++)
            {
                PrecomputedValues[p] = new int[NumPrimes][][];

                for (int q = 0; q < NumPrimes; q++)
                {
                    if (primes[p] == primes[q]) continue;
                    int primeProduct = primes[p] * primes[q];
                    PrecomputedValues[p][q] = new int[PrimeNumbers[^1] + 1][]; // Make array hold all possible numbers between 0 and biggest prime
                    for (int prime2 = 0; prime2 < PrimeNumbers.Length; prime2++)
                    {
                        int prime = PrimeNumbers[prime2];
                        PrecomputedValues[p][q][prime] = new int[256];
                        for (int byteValue = 0; byteValue < 256; byteValue++)
                        {
                            int value = byteValue;

                            for (int x = 0; x < prime - 1; x++)
                                value = (value * byteValue) % primeProduct;

                            PrecomputedValues[p][q][prime][byteValue] = value;
                        }
                    }
                }
            }
        }


        private static void MakePasscode(ref Span<byte> output, CodeType codeType, uint hitRateIndex, ReadOnlySpan<char> string0, ReadOnlySpan<char> string1, ushort itemId, byte npcType, byte npcCode, bool force = false)
        {
            if (!force)
            {
                switch (codeType)
                {
                    case CodeType.Famicom:
                    case CodeType.User:
                    case CodeType.Card_E_Mini:
                        hitRateIndex = 1;
                        npcCode = 0xFF;
                        break;

                    case CodeType.Popular:
                        hitRateIndex = 4;
                        break;

                    case CodeType.Magazine:
                        hitRateIndex &= 3;
                        npcType = (byte)((hitRateIndex >> 2) & 1);
                        npcCode = 0xFF;
                        break;
                    default:
                        codeType = CodeType.User;
                        break;
                }
            }

            uint byte0 = ((uint)codeType & 7) << 5;
            byte0 |= hitRateIndex << 1;
            byte0 |= (uint)npcType & 1;
            output[0] = (byte)byte0;
            output[1] = npcCode;

            CopyStringToOutput(string0, output.Slice(2, 8));
            CopyStringToOutput(string1, output.Slice(10, 8));

            output[0x12] = (byte)(itemId >> 8);
            output[0x13] = (byte)itemId;

            int checksum = Sum(output.Slice(2, 8)) + Sum(output.Slice(10, 8)) + itemId;

            if (force && (codeType == CodeType.Famicom || codeType == CodeType.User || codeType == CodeType.Card_E_Mini || codeType == CodeType.Magazine))
            {
                checksum += 0xFF;
            }
            else
            {
                checksum += npcCode;
            }

            output[0] |= (byte)((checksum & 3) << 3);

            static int Sum(ReadOnlySpan<byte> span)
            {
                int sum = 0;
                foreach (byte b in span)
                {
                    sum += b;
                }
                return sum;
            }
        }

        private static void MakePasscode(ref Span<byte> output, CodeType codeType, uint hitRateIndex, in ReadOnlySpan<byte> string0, in ReadOnlySpan<byte> string1, ushort itemId, byte npcType, byte npcCode)
        {
            int checksum;

            switch (codeType)
            {
                case CodeType.Famicom:
                case CodeType.User:
                case CodeType.Card_E_Mini:
                    hitRateIndex = 1;
                    npcCode = 0xFF;
                    checksum = 0xFF;
                    break;

                case CodeType.Popular:
                    hitRateIndex = 4;
                    checksum = npcCode;
                    break;

                case CodeType.Magazine:
                    hitRateIndex &= 3;
                    npcType = (byte)((hitRateIndex >> 2) & 1);
                    npcCode = 0xFF;
                    checksum = 0xFF;
                    break;
                default:
                    codeType = CodeType.User;
                    checksum = npcCode;
                    break;
            }

            uint byte0 = ((uint)codeType & 7) << 5;
            byte0 |= hitRateIndex << 1;
            byte0 |= (uint)npcType & 1;
            output[0] = (byte)byte0;
            output[1] = npcCode;

            Span<byte> s0 = output.Slice(2, 8);
            Span<byte> s1 = output.Slice(10, 8);

            for (int i = 0; i < 8; i++)
            {
                s0[i] = string0[i];
                s1[i] = string1[i];
                checksum += string0[i] + string1[i];
            }

            output[0x12] = (byte)(itemId >> 8);
            output[0x13] = (byte)itemId;

            checksum += itemId;
            output[0] |= (byte)((checksum & 3) << 3);
        }

        private static void MakePasscodeForced(ref Span<byte> output, CodeType codeType, uint hitRateIndex, in ReadOnlySpan<byte> string0, in ReadOnlySpan<byte> string1, ushort itemId, byte npcType, byte npcCode)
        {
            var checksum = codeType switch
            {
                CodeType.Card_E or CodeType.Popular => npcCode,
                _ => 0xFF,
            };

            uint byte0 = ((uint)codeType & 7) << 5;

            switch (codeType)
            {
                case CodeType.Magazine:
                    npcType = (byte)((hitRateIndex >> 2) & 1);
                    hitRateIndex &= 3;
                    break;
            }

            byte0 |= hitRateIndex << 1;
            byte0 |= (uint)npcType & 1;
            output[0] = (byte)byte0;
            output[1] = npcCode;

            Span<byte> s0 = output.Slice(2, 8);
            Span<byte> s1 = output.Slice(10, 8);

            for (int i = 0; i < 8; i++)
            {
                s0[i] = string0[i];
                s1[i] = string1[i];
                checksum += string0[i] + string1[i];
            }

            output[0x12] = (byte)(itemId >> 8);
            output[0x13] = (byte)itemId;

            checksum += itemId;
            output[0] |= (byte)((checksum & 3) << 3);
        }

        private static void CopyStringToOutput(in ReadOnlySpan<char> input, in Span<byte> output)
        {
            for (int i = 0; i < output.Length; i++)
            {
                if (i >= input.Length)
                {
                    output[i] = 0x20;
                }
                else
                {
                    int charIdx = Array.IndexOf(CharacterSet, input[i]);
                    if (charIdx < 0)
                    {
                        charIdx = 0x20;
                        Console.WriteLine($"Encountered an invalid character in the input string at string offset: {i}");
                    }
                    output[i] = (byte)charIdx;
                }
            }
        }

        private static void CopyStringToOutput(in ReadOnlySpan<byte> input, ref Span<byte> output)
        {
            for (int i = 0; i < output.Length; i++)
            {
                if (i >= input.Length)
                {
                    output[i] = 0x20;
                }
                else
                {
                    output[i] = input[i];
                }
            }
        }


        private static void SubstitutionCipher(ref Span<byte> password)
        {
            for (var i = 0; i < 21; i++)
                password[i] = ChangeCodeTable[password[i]];
        }

        private static void BitShuffle(ref Span<byte> password, int key)
        {
            int keyIdx = key == 0 ? 13 : 2;
            int count = key == 0 ? 19 : 20;

            Span<byte> outData = stackalloc byte[20];
            outData.Clear();

            ReadOnlySpan<int> selectTable = mMpswd_select_idx_table[password[keyIdx] & 3].AsSpan();

            for (int i = 0; i < count; i++)
            {
                int sourceIndex = i < keyIdx ? i : i + 1;
                byte selectedByte = password[sourceIndex];

                for (int x = 0; x < selectTable.Length; x++)
                {
                    int outputOffset = selectTable[x] + i;
                    if (outputOffset >= count)
                        outputOffset -= count;

                    byte shiftedByte = (byte)((selectedByte & (1 << x)) >> x);
                    outData[outputOffset] |= (byte)(shiftedByte << x);
                }
            }

            outData[..keyIdx].CopyTo(password);
            outData[keyIdx..20].CopyTo(password[(keyIdx + 1)..]);
        }

        /*
        private static void ChangeRSACipher(ref Span<byte> password)
        {
            mMpswd_get_RSA_key_code(out int prime0, out int prime1, out int prime2, out ReadOnlySpan<int> selectTable, password);

            byte rsaKey = 0;
            int PrimeProduct = prime0 * prime1;

            for (int i = 0; i < 8; i++)
            {
                int value = password[selectTable[i]];
                int currentValue = value;

                for (int x = 0; x < prime2 - 1; x++)
                    value = (value * currentValue) % PrimeProduct;

                password[selectTable[i]] = (byte)value;
                value = (value >> 8) & 1;
                rsaKey |= (byte)(value << i);
            }

            password[20] = rsaKey;
        }
        */

        public static void ChangeRSACipher(ref Span<byte> password)
        {
            // Inline mMpswd_get_RSA_key_code
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

            //int[] primes = { 17, 19, 23, 29 };
            //int p = primes[bits01];
            //int q = primes[bits23];
            int prime2 = PrimeNumbers[password[5]];
            ReadOnlySpan<int> selectTable = mMpswd_select_idx_table[(password[15] >> 4) & 0xF];

            // Continue with ChangeRSACipher
            byte rsaKey = 0;

            for (int i = 0; i < 8; i++)
            {
                int originalValue = password[selectTable[i]];
                int val = PrecomputedValues[bits01][bits23][prime2][originalValue];
                password[selectTable[i]] = (byte)val;
                int value = (val >> 8) & 1;
                rsaKey |= (byte)(value << i);
            }

            password[20] = rsaKey;
        }


        private static void BitMixCode(ref Span<byte> password)
        {
            var code = password[1] & 0xF;
            if (code < 0xD)
            {
                if (code < 0x9)
                {
                    if (code < 0x5)
                    {
                        BitShift(ref password, code * 3);
                        //Debug.WriteLine($"BitShift: {password.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
                        BitArrangeReverse(ref password);
                    }
                    else
                    {
                        BitShift(ref password, code * -5);
                        BitReverse(ref password);
                    }
                }
                else
                {
                    BitArrangeReverse(ref password);
                    BitShift(ref password, code * -5);
                }
            }
            else
            {
                BitArrangeReverse(ref password);
                BitReverse(ref password);
                BitShift(ref password, code * 3);
            }
        }

        private static void Change6BitsCode(in ReadOnlySpan<byte> passwordInfo, in Span<byte> password)
        {
            for (int byte6Idx = 0; byte6Idx < 28; byte6Idx++)
            {
                int bit6Start = byte6Idx * 6;
                int byte8Idx = bit6Start / 8;
                int bit8Idx = bit6Start % 8;

                int value = passwordInfo[byte8Idx] >> bit8Idx;
                if (bit8Idx + 6 > 8)
                {
                    value |= passwordInfo[byte8Idx + 1] << (8 - bit8Idx);
                }
                value &= 0b00111111;

                password[byte6Idx] = (byte)value;
            }
        }


        private static void ChangeCommonFontCode(ref Span<byte> password)
        {
            for (var i = 0; i < 28; i++)
                password[i] = Usable2FontNum[password[i]];
        }

        /*
        public static byte[] MakePassword(CodeType codeType, uint hitRateIndex, string string0, string string1, ushort itemId, byte npcType, byte npcCode, bool force = false)
        {
            var passwordInfo = MakePasscode(codeType, hitRateIndex, string0, string1, itemId, npcType, npcCode, force);
            SubstitutionCipher(ref passwordInfo);
            TranspositionCipher(ref passwordInfo, true, 0);
            BitShuffle(ref passwordInfo, 0);
            ChangeRSACipher(ref passwordInfo);
            BitMixCode(ref passwordInfo);
            BitShuffle(ref passwordInfo, 1);
            TranspositionCipher(ref passwordInfo, false, 1);
            var password = Change6BitsCode(passwordInfo);
            ChangeCommonFontCode(ref password);
            return password;
        }
        */

#if DEBUG
        public static void MakePassword(ref Span<byte> password, CodeType codeType, uint hitRateIndex, byte[] string0, byte[] string1, ushort itemId, byte npcType, byte npcCode)
        {
            Span<byte> passwordData = stackalloc byte[PasswordDataLength];

            Stopwatch sw = Stopwatch.StartNew();
            MakePasscode(ref passwordData, codeType, hitRateIndex, string0, string1, itemId, npcType, npcCode);
            sw.Stop();

            Console.WriteLine($"{nameof(MakePasscode)} took {sw.ElapsedTicks / (double)TimeSpan.TicksPerMillisecond} ms");

            sw = Stopwatch.StartNew();
            //Debug.WriteLine($"MakePasscode: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            SubstitutionCipher(ref passwordData);
            sw.Stop();

            Console.WriteLine($"{nameof(SubstitutionCipher)} took {sw.ElapsedTicks / (double)TimeSpan.TicksPerMillisecond} ms");

            sw = Stopwatch.StartNew();
            //Debug.WriteLine($"SubstitutionCipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            TranspositionCipher(ref passwordData, true, 0);
            sw.Stop();

            Console.WriteLine($"{nameof(TranspositionCipher)} took {sw.ElapsedTicks / (double)TimeSpan.TicksPerMillisecond} ms");

            sw = Stopwatch.StartNew();
            //Debug.WriteLine($"TranspositionCipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            BitShuffle(ref passwordData, 0);
            sw.Stop();

            Console.WriteLine($"{nameof(BitShuffle)} took {sw.ElapsedTicks / (double)TimeSpan.TicksPerMillisecond} ms");

            sw = Stopwatch.StartNew();
            //Debug.WriteLine($"BitShuffle: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            ChangeRSACipher(ref passwordData);
            sw.Stop();
            Debug.WriteLine($"{passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");

            Console.WriteLine($"{nameof(ChangeRSACipher)} took {sw.ElapsedTicks / (double)TimeSpan.TicksPerMillisecond} ms");

            sw = Stopwatch.StartNew();
            //Debug.WriteLine($"ChangeRSACipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            BitMixCode(ref passwordData);
            sw.Stop();

            Console.WriteLine($"{nameof(BitMixCode)} took {sw.ElapsedTicks / (double)TimeSpan.TicksPerMillisecond} ms");

            sw = Stopwatch.StartNew();
            //Debug.WriteLine($"BitMixCode: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            BitShuffle(ref passwordData, 1);
            sw.Stop();

            Console.WriteLine($"{nameof(BitShuffle)} took {sw.ElapsedTicks / (double)TimeSpan.TicksPerMillisecond} ms");

            sw = Stopwatch.StartNew();
            //Debug.WriteLine($"BitShuffle: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            TranspositionCipher(ref passwordData, false, 1);
            sw.Stop();

            Console.WriteLine($"{nameof(TranspositionCipher)} took {sw.ElapsedTicks / (double)TimeSpan.TicksPerMillisecond} ms");

            sw = Stopwatch.StartNew();
            //Debug.WriteLine($"TranspositionCipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");

            //Span<byte> password = stackalloc byte[PasswordLength];
            Change6BitsCode(passwordData, password);
            sw.Stop();

            Console.WriteLine($"{nameof(Change6BitsCode)} took {sw.ElapsedTicks / (double)TimeSpan.TicksPerMillisecond} ms");

            sw = Stopwatch.StartNew();
            ChangeCommonFontCode(ref password);
            sw.Stop();

            Console.WriteLine($"{nameof(ChangeCommonFontCode)} took {sw.ElapsedTicks / (double)TimeSpan.TicksPerMillisecond} ms");
            //return password.ToArray();
        }
#else
        public static void MakePassword(ref Span<byte> password, CodeType codeType, uint hitRateIndex, byte[] string0, byte[] string1, ushort itemId, byte npcType, byte npcCode)
        {
            Span<byte> passwordData = stackalloc byte[PasswordDataLength];
            
            MakePasscode(ref passwordData, codeType, hitRateIndex, string0, string1, itemId, npcType, npcCode);
            //Debug.WriteLine($"MakePasscode: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            SubstitutionCipher(ref passwordData);
            //Debug.WriteLine($"SubstitutionCipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            TranspositionCipher(ref passwordData, true, 0);
            //Debug.WriteLine($"TranspositionCipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            BitShuffle(ref passwordData, 0);
            //Debug.WriteLine($"BitShuffle: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            ChangeRSACipher(ref passwordData);
            //Debug.WriteLine($"ChangeRSACipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            BitMixCode(ref passwordData);
            //Debug.WriteLine($"BitMixCode: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            BitShuffle(ref passwordData, 1);
            //Debug.WriteLine($"BitShuffle: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            TranspositionCipher(ref passwordData, false, 1);
            //Debug.WriteLine($"TranspositionCipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");

            //Span<byte> password = stackalloc byte[PasswordLength];
            Change6BitsCode(passwordData, password);
            ChangeCommonFontCode(ref password);
            //return password.ToArray();
        }
#endif

        public static void MakePasswordForced(ref Span<byte> password, CodeType codeType, uint hitRateIndex, byte[] string0, byte[] string1, ushort itemId, byte npcType, byte npcCode)
        {
            Span<byte> passwordData = stackalloc byte[PasswordDataLength];

            MakePasscodeForced(ref passwordData, codeType, hitRateIndex, string0, string1, itemId, npcType, npcCode);
            //Debug.WriteLine($"MakePasscode: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            SubstitutionCipher(ref passwordData);
            //Debug.WriteLine($"SubstitutionCipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            TranspositionCipher(ref passwordData, true, 0);
            //Debug.WriteLine($"TranspositionCipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            BitShuffle(ref passwordData, 0);
            //Debug.WriteLine($"BitShuffle: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            ChangeRSACipher(ref passwordData);
            //Debug.WriteLine($"ChangeRSACipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            BitMixCode(ref passwordData);
            //Debug.WriteLine($"BitMixCode: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            BitShuffle(ref passwordData, 1);
            //Debug.WriteLine($"BitShuffle: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
            TranspositionCipher(ref passwordData, false, 1);
            //Debug.WriteLine($"TranspositionCipher: {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");

            //Span<byte> password = stackalloc byte[PasswordLength];
            Change6BitsCode(passwordData, password);
            ChangeCommonFontCode(ref password);
            //return password.ToArray();
        }
    }
}
