namespace ACPasswordLibrary.Core.DnMPlus
{
    public static class Decoder
    {
        private static byte[] mMpswd_chg_password_font_code(string password_str)
        {
            byte[] bytes = new byte[password_str.Length];

            for (int i = 0; i < bytes.Length; i++)
            {
                string c = password_str.Substring(i, 1);
                byte val = 0xFF;
                for (int f = 0; f < Common.usable_to_fontnum.Length; f++)
                {
                    if (c == Common.usable_to_fontnum[f])
                    {
                        val = (byte)f;
                        break;
                    }
                }

                if (val == 0xFF)
                {
                    throw new Exception($"Invalid password character: {c}!");
                }

                bytes[i] = val;
            }

            return bytes;
        }

        public static byte[] mMpswd_decode_code(string password_str)
        {
            if (password_str.Length != Common.PASSWORD_STRING_SIZE)
            {
                throw new Exception($"Expected password length to be {Common.PASSWORD_STRING_SIZE} characters, but got {password_str.Length} characters!");
            }

            // Convert the password's characters into their password index value (0-63, or 6 bits)
            byte[] str_data = mMpswd_chg_password_font_code(password_str);

            // Break out bits into singular bytes
            byte[] bits = new byte[Common.PASSWORD_BITS_COUNT];
            for (int i = 0; i < Common.PASSWORD_STRING_SIZE; i++)
            {
                for (int x = 0; x < 6; x++)
                {
                    bits[i * 6 + x] = (byte)((str_data[i] >> (5 - x)) & 1);
                }
            }

            // Initial shift
            Common.mMpswd_shift(bits, Common.PASSWORD_BITS_COUNT, -15);

            // Retrieve the scramble code from the last four bits
            int code = (bits[128] << 3) | (bits[129] << 2) | (bits[130] << 1) | (bits[131] << 0);

            // Unscramble
            switch (code)
            {
                case < 5: // [0, 4] 5/16
                    Common.mMpswd_reverse(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS);
                    Common.mMpswd_shift(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS, code * -3);
                    break;
                case >= 5 and < 9: // [5, 8] 4/16 (1/4)
                    Common.mMpswd_hanten(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS);
                    Common.mMpswd_shift(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS, code * 5);
                    break;
                case >= 9 and < 13: // [9, 12] 4/16 (1/4)
                    Common.mMpswd_shift(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS, code * 5);
                    Common.mMpswd_reverse(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS);
                    break;
                default: // >= 13 [13, 15] 3/16
                    Common.mMpswd_shift(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS, code * -3);
                    Common.mMpswd_hanten(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS);
                    Common.mMpswd_reverse(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS);
                    break;
            }

            // Reconstitute bits into bytes
            byte[] data = new byte[Common.PASSWORD_DATA_SIZE];
            int pos = 0;
            for (int i = 0; i < Common.PASSWORD_DATA_SIZE - 1; i++)
            {
                byte b = 0;
                for (int x = 0; x < 8; x++)
                {
                    b |= (byte)(bits[pos++] << (7 - x));
                }
                data[i] = b;
            }

            data[Common.PASSWORD_DATA_SIZE - 1] = (byte)code; // last four bits

            return data; // Password is decoded
        }
    }
}
