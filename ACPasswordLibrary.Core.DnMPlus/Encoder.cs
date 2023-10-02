namespace ACPasswordLibrary.Core.DnMPlus
{
    public static class Encoder
    {
        private static string mMpswd_chg_common_font_code(in byte[] data)
        {
            string str = "";
            for (int i = 0; i < Common.PASSWORD_STRING_SIZE; i++)
            {
                str += Common.usable_to_fontnum[data[i]];
            }

            return str;
        }

        public static string mMpswd_encode_code(in byte[] data)
        {
            if (data.Length != Common.PASSWORD_DATA_SIZE)
            {
                throw new Exception("Bad password data length!");
            }

            // Break bits out
            byte[] bits = new byte[Common.PASSWORD_BITS_COUNT];
            int pos = 0;
            for (int i = 0; i < Common.PASSWORD_DATA_SIZE - 1; i++)
            {
                for (int x = 0; x < 8; x++)
                {
                    bits[pos++] = (byte)((data[i] >> (7 - x)) & 1);
                }
            }

            // Perform dynamic scramble
            int code = data[16];
            switch (code)
            {
                case < 5:
                    Common.mMpswd_shift(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS, code * 3);
                    Common.mMpswd_reverse(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS);
                    break;
                case >= 5 and < 9:
                    Common.mMpswd_shift(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS, code * -5);
                    Common.mMpswd_hanten(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS);
                    break;
                case >= 9 and < 13:
                    Common.mMpswd_reverse(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS);
                    Common.mMpswd_shift(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS, code * -5);
                    break;
                default: // >= 13
                    Common.mMpswd_reverse(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS);
                    Common.mMpswd_hanten(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS);
                    Common.mMpswd_shift(bits, Common.PASSWORD_DATA_SCRAMBLE_BITS, code * 3);
                    break;
            }

            // Copy code bits
            bits[128] = (byte)((code >> 3) & 1);
            bits[129] = (byte)((code >> 2) & 1);
            bits[130] = (byte)((code >> 1) & 1);
            bits[131] = (byte)((code >> 0) & 1);

            // Final shift
            Common.mMpswd_shift(bits, Common.PASSWORD_BITS_COUNT, 15);

            // Reconstitute into 6-bit values
            byte[] str_data = new byte[Common.PASSWORD_STRING_SIZE];
            for (int i = 0; i < Common.PASSWORD_STRING_SIZE; i++)
            {
                for (int x = 0; x < 6; x++)
                {
                    str_data[i] |= (byte)(bits[i * 6 + x] << (5 - x));
                }
            }

            // Convert to string and return
            return mMpswd_chg_common_font_code(str_data);
        }
    }
}
