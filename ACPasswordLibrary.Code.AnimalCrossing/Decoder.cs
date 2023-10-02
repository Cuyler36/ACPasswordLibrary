using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static ACPasswordLibrary.Core.AnimalCrossing.Common;

namespace ACPasswordLibrary.Core.AnimalCrossing
{
    public readonly struct Password
    {
        public readonly ushort ItemId;
        public readonly bool IsSpecialNpc;
        public readonly byte NpcCode; // NPC Id
        public readonly CodeType CodeType;
        public readonly byte HitRateIdx; // Index for the hit rate (win percentage) for Magazine codes. 0 - 4
        public readonly byte Checksum;
        public readonly ImmutableArray<byte> String0;
        public readonly ImmutableArray<byte> String1;

        public Password(in ReadOnlySpan<byte> input)
        {
            //if (input.Length != 21) throw new ArgumentException("Password data must be 21 bytes!");
            Checksum = (byte)((input[0] >> 3) & 3);

            String0 = input.Slice(2, 8).ToImmutableArray();
            String1 = input.Slice(10, 8).ToImmutableArray();

            ItemId = (ushort)((input[18] << 8) | input[19]);
            CodeType = (CodeType)(input[0] >> 5);

            switch (CodeType)
            {
                case CodeType.Popular:
                case CodeType.Card_E:
                    HitRateIdx = (byte)((input[0] >> 1) & 3);
                    IsSpecialNpc = (input[0] & 1) != 0;
                    NpcCode = input[1];
                    break;
                case CodeType.Magazine:
                    HitRateIdx = (byte)(((input[0] >> 1) & 3) | ((input[0] & 1) << 2));
                    IsSpecialNpc = true;
                    NpcCode = 0xFF;
                    break;
                default: // User & CardE_Mini
                    HitRateIdx = (byte)((input[0] >> 1) & 3);
                    IsSpecialNpc = true;
                    NpcCode = 0xFF;
                    break;
            }
        }
    }


    public static class Decoder
    {
        // Constants
        private const int PrimeNumbersLength = 256;
        private const int NumPrimes = 4;

        private static readonly byte[] ChangeCodeTableReverse = new byte[256];
        private static readonly Dictionary<char, byte> CharacterSetDict = new();
        private static readonly int[][][][] PrecomputedDecodeValues;

        static Decoder()
        {
            for (int i = 0; i < 256; i++)
            {
                ChangeCodeTableReverse[Common.ChangeCodeTable[i]] = (byte)i;
            }

            for (int i = 0; i < Common.CharacterSet.Length; i++)
            {
                CharacterSetDict[Common.CharacterSet[i]] = (byte)i;
            }

            int[] primes = { 17, 19, 23, 29 };
            PrecomputedDecodeValues = new int[NumPrimes][][][];

            for (int p = 0; p < NumPrimes; p++)
            {
                PrecomputedDecodeValues[p] = new int[NumPrimes][][];

                for (int q = 0; q < NumPrimes; q++)
                {
                    if (primes[p] == primes[q]) continue;
                    int primeProduct = primes[p] * primes[q];
                    PrecomputedDecodeValues[p][q] = new int[PrimeNumbers[^1] + 1][];

                    for (int prime2 = 0; prime2 < PrimeNumbers.Length; prime2++)
                    {
                        int prime = PrimeNumbers[prime2];
                        PrecomputedDecodeValues[p][q][prime] = new int[512];

                        for (int byteValue = 0; byteValue < 512; byteValue++)
                        {
                            // Calculate decoding value
                            int even_product = (primes[p] - 1) * (primes[q] - 1);
                            int d, modCount = 0;
                            do
                            {
                                d = (++modCount * even_product + 1) / prime;
                            } while ((modCount * even_product + 1) % prime != 0);

                            int decodeValue = byteValue;
                            for (int x = 1; x < d; x++)
                                decodeValue = (decodeValue * byteValue) % primeProduct;

                            PrecomputedDecodeValues[p][q][prime][byteValue] = (byte)decodeValue;
                        }
                    }
                }
            }
        }

        private static void AdjustLetter(ref Span<byte> password)
        {
            for (var i = 0; i < PasswordLength; i++)
            {
                if (password[i] == '1')
                    password[i] = (byte)'l';
                else if (password[i] == '0')
                    password[i] = (byte)'O';
            }
        }

        private static byte ChangePasswordFontCodeSubroutine(in ReadOnlySpan<byte> usable2FontNum, byte character)
        {
            int index = usable2FontNum.IndexOf(character);
            return index == -1 ? (byte)0xFF : (byte)index;
        }

        private static bool ChangePasswordFontCode(ref Span<byte> password)
        {
            ReadOnlySpan<byte> usable2FontNum = Common.Usable2FontNum;
            for (var i = 0; i < password.Length; i++)
            {
                var fontCode = ChangePasswordFontCodeSubroutine(usable2FontNum, password[i]);
                if (fontCode == 0xFF)
                    return false;

                password[i] = fontCode;
            }

            return true;
        }

        private static void DecodeBitShuffle(ref Span<byte> password, int keyIndex)
        {
            int count, key;
            if (keyIndex == 0)
            {
                count = 19;
                key = 13;
            }
            else
            {
                count = 20;
                key = 2;
            }

            Span<byte> data = stackalloc byte[20];
            password[..key].CopyTo(data);
            password.Slice(key + 1, 20 - key).CopyTo(data[key..]);

            var selectTable = Common.mMpswd_select_idx_table[password[key] & 3];

            for (int i = 0; i < count; i++)
            {
                byte temp = 0;
                for (int b = 0; b < 8; b++)
                {
                    int outputOffset = selectTable[b] + i;
                    if (outputOffset >= count)
                        outputOffset -= count;

                    temp |= (byte)(((data[outputOffset] >> b) & 1) << b);
                }

                if (i < key)
                    password[i] = temp;
                else if (i >= key)
                    password[i + 1] = temp;
            }

            /* HACK */
            if (keyIndex == 0)
            {
                password[20] = 0;
            }
        }

        private static void DecodeBitCode(ref Span<byte> password)
        {
            var code = password[1] & 0xF;
            if (code < 0xD)
            {
                if (code < 0x9)
                {
                    if (code < 0x5)
                    {
                        Common.BitArrangeReverse2(ref password);
                        Common.BitShift2(ref password, code * -3);
                    }
                    else
                    {
                        Common.BitReverse2(ref password);
                        Common.BitShift2(ref password, code * 5);
                    }
                }
                else
                {
                    Common.BitShift2(ref password, code * 5);
                    Common.BitArrangeReverse2(ref password);
                }
            }
            else
            {
                Common.BitShift2(ref password, code * -3);
                Common.BitReverse2(ref password);
                Common.BitArrangeReverse2(ref password);
            }
        }

        /**
         * TODO: Optimize by making lookup table for values for O(1) time-complexity.
         * Needs:
         *     - Table[p][q][prime2][byteValue]
         * 
         */
        public static void DecodeRSACipher(ref Span<byte> password)
        {
            int modCount = 0;

            mMpswd_get_RSA_key_code(out var p, out var q, out var prime2, out var selectTable, password);

            int n = p * q;
            int even_product = (p - 1) * (q - 1);
            int d;

            // Calculate exponent d for decryption
            do
            {
                d = (++modCount * even_product + 1) / prime2;
            } while ((modCount * even_product + 1) % prime2 != 0);

            for (var i = 0; i < 8; i++)
            {
                int value = password[selectTable[i]];
                value |= ((password[20] >> i) & 1) << 8;

                /* Do decryption c^d = (m^e)^d = m (% n) */
                int originalValue = value;
                for (var x = 1; x < d; x++)
                    value = (value * originalValue) % n;

                password[selectTable[i]] = (byte)value;
            }
        }

        public static void DecodeRSACipherFAST(ref Span<byte> password)
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

            int prime2 = PrimeNumbers[password[5]];
            ReadOnlySpan<int> selectTable = mMpswd_select_idx_table[(password[15] >> 4) & 0xF];

            for (var i = 0; i < 8; i++)
            {
                int value = password[selectTable[i]];
                value |= ((password[20] >> i) & 1) << 8; /* 9 bits, 0-511 */

                password[selectTable[i]] = (byte)PrecomputedDecodeValues[bits01][bits23][prime2][value];
            }
        }

        /**
         * This is a slightly faster way to decode the RSA cipher.
         */
        public static void DecodeRSACipher2(ref Span<byte> password)
        {
            int modCount = 0;

            mMpswd_get_RSA_key_code(out var prime0, out var prime1, out var prime2, out var selectTable, password);

            int odd_product = prime0 * prime1;
            int even_product = (prime0 - 1) * (prime1 - 1);
            int roll_count;

            // Search for a value that can be wholly divided by prime2.
            do
            {
                roll_count = (++modCount * even_product + 1) / prime2;
            } while ((modCount * even_product + 1) % prime2 != 0);

            for (var i = 0; i < 8; i++)
            {
                int value = password[selectTable[i]];
                value |= ((password[20] >> i) & 1) << 8;

                value = ModularExponentiation(value, roll_count, odd_product);

                password[selectTable[i]] = (byte)value;
            }
        }

        private static int ModularExponentiation(int baseValue, int exponent, int modulus)
        {
            int result = 1;
            baseValue %= modulus;

            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                    result = (result * baseValue) % modulus;

                exponent >>= 1;
                baseValue = (baseValue * baseValue) % modulus;
            }

            return result;
        }

        private static void DecodeSubstitutionCipher(ref Span<byte> password)
        {
            for (var x = 0; x < 21; x++)
            {
                password[x] = ChangeCodeTableReverse[password[x]];
            }
        }

        private static bool Decode(ref Span<byte> password, Span<byte> passwordData)
        {
            AdjustLetter(ref password);
            if (ChangePasswordFontCode(ref password))
            {
                // Debug.WriteLine($"{password.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
                Common.Change8BitsCode(password, ref passwordData);
                // Debug.WriteLine($"{passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
                Common.TranspositionCipher(ref passwordData, true, 1);
                // Debug.WriteLine($"{passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
                DecodeBitShuffle(ref passwordData, 1);
                // Debug.WriteLine($"{passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
                DecodeBitCode(ref passwordData);
                // Debug.WriteLine($"{passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
                DecodeRSACipherFAST(ref passwordData);
                // Debug.WriteLine($"{passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
                DecodeBitShuffle(ref passwordData, 0);
                // Debug.WriteLine($"DecodeBitShuffle(ref passwordData, 0) = {passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
                Common.TranspositionCipher(ref passwordData, false, 0);
                // Debug.WriteLine($"{passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");
                DecodeSubstitutionCipher(ref passwordData);
                // Debug.WriteLine($"{passwordData.ToArray().Aggregate("", (c, b) => c += $"{b},")}");

                return true;
            }

            passwordData = Array.Empty<byte>();
            return false;
        }

        public static Password DecodeToPassword(in byte[] password)
        {
            Span<byte> passwordBytes = password.AsSpan();
            byte[] tempPasswordData = new byte[PasswordDataLength];
            Span<byte> passwordData = tempPasswordData.AsSpan();
            //passwordData.Clear();

            if (!Decode(ref passwordBytes, passwordData))
                return default;

            return new Password(tempPasswordData);
        }

        public static void DecodeToBytes(string password, in byte[] passwordBuffer)
        {
            Span<byte> passwordBytes = stackalloc byte[PasswordLength];
            for (int i = 0; i < PasswordLength; i++)
            {
                if (!CharacterSetDict.TryGetValue(password[i], out byte byteValue))
                {
                    throw new ArgumentException($"Invalid character '{password[i]}' found in the password string.", nameof(password));
                }
                passwordBytes[i] = byteValue;
            }

            Span<byte> passwordData = passwordBuffer;
            Decode(ref passwordBytes, passwordData);

        }

        public static Password DecodeToPassword(string password)
        {
            if (password.Length != PasswordLength)
                throw new ArgumentOutOfRangeException(nameof(password), "password expected to have 28 characters!");

            Span<byte> passwordBytes = stackalloc byte[PasswordLength];

            for (int i = 0; i < PasswordLength; i++)
            {
                if (!CharacterSetDict.TryGetValue(password[i], out byte byteValue))
                {
                    throw new ArgumentException($"Invalid character '{password[i]}' found in the password string.", nameof(password));
                }
                passwordBytes[i] = byteValue;
            }

            Span<byte> passwordData = stackalloc byte[PasswordDataLength];
            if (Decode(ref passwordBytes, passwordData))
                return new Password(passwordData);
            return default;
        }

    }
}
