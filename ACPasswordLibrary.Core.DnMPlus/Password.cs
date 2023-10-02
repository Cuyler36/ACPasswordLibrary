namespace ACPasswordLibrary.Core.DnMPlus
{
    public sealed class Password
    {
        public enum CodeType
        {
            Famicom,
            Popular,
            CardE,
            Magazine
        }

        public CodeType Type;
        public int HitRateIndex;
        public byte NpcCode;
        public byte SpecialNpcType;
        public ushort PresentIndex;
        public string String0 = ""; // Player name
        public string String1 = ""; // Town name
        public byte Checksum; // 4 bits

        public Password(in byte[] data)
        {
            Checksum = data[16];
            for (int i = 0; i < 6; i++)
            {
                String0 += Common.CharacterSet[data[2 + i]];
                String1 += Common.CharacterSet[data[8 + i]];
            }

            PresentIndex = (ushort)((data[14] << 8) | data[15]);

            Type = (CodeType)(data[0] >> 6);
            switch (Type)
            {
                case CodeType.Famicom:
                case CodeType.Magazine:
                    HitRateIndex = data[0] & 0x3F;
                    SpecialNpcType = 0xFF;
                    NpcCode = 0xFF;
                    break;
                case CodeType.Popular:
                    HitRateIndex = 1;
                    SpecialNpcType = (byte)(data[0] & 1);
                    NpcCode = data[1];
                    break;
                case CodeType.CardE:
                    HitRateIndex = (data[0] >> 1) & 3;
                    SpecialNpcType = (byte)(data[0] & 1);
                    NpcCode = data[1];
                    break;
            }
        }

        public byte CalculateChecksum()
        {
            int checksum = String0.Aggregate(0, (curr, c) => curr += Array.IndexOf(Common.CharacterSet, c.ToString()));
            checksum += String1.Aggregate(0, (curr, c) => curr += Array.IndexOf(Common.CharacterSet, c.ToString()));
            checksum += PresentIndex;

            if (Type == CodeType.Popular || Type == CodeType.CardE)
            {
                checksum += NpcCode + (SpecialNpcType << 8);
            }

            if (Type == CodeType.CardE)
            {
                checksum += HitRateIndex;
            }

            checksum &= 0xFFFF;
            ushort chk = (ushort)(checksum + (checksum >> 4) * -16);
            return (byte)chk;
        }

        private bool mMpswd_password_zuru_check()
        {
            int checksum = String0.Aggregate(0, (curr, c) => curr += Array.IndexOf(Common.CharacterSet, c.ToString()));
            checksum += String1.Aggregate(0, (curr, c) => curr += Array.IndexOf(Common.CharacterSet, c.ToString()));
            checksum += PresentIndex;

            if (Type == CodeType.Popular || Type == CodeType.CardE)
            {
                checksum += NpcCode + (SpecialNpcType << 8);
            }

            if (Type == CodeType.CardE)
            {
                checksum += HitRateIndex;
            }

            checksum &= 0xFFFF;
            byte chk = (byte)(checksum + (checksum >> 4) * -16);
            return chk != Checksum;
        }

        public bool IsValid()
        {
            return Type switch
            {
                CodeType.Famicom => HitRateIndex == 1 && !mMpswd_password_zuru_check() && Array.IndexOf(Common.pswd_famicom_list, PresentIndex) != -1,
                CodeType.Popular or CodeType.CardE => ((SpecialNpcType == 0 && NpcCode < 0xEC) || (SpecialNpcType == 1 && NpcCode < 0x1E)) && !mMpswd_password_zuru_check() && Common.CheckHPMail_presentlist(PresentIndex),
                CodeType.Magazine => Array.IndexOf(Common.HitRateValues, HitRateIndex) != -1 && !mMpswd_password_zuru_check() && Common.CheckHPMail_presentlist(PresentIndex),
                _ => throw new ArgumentOutOfRangeException(nameof(Type), "Invalid code type encountered")
            };
        }

        public ushort GetPresentId() => Common.GetPresentItemNo(PresentIndex);
    }
}
