using ACPasswordLibrary.CommandLine.DnMPlus;
using ACPasswordLibrary.CommandLine.DnMPlus.Properties;
using ACPasswordLibrary.Core.DnMPlus;
using System.Diagnostics;
using System.CommandLine;

namespace ACPasswordLibrary.CommandLine.DnMPlus
{
    class Program
    {
        static readonly ResourceDictionary dict = new(Resources.AF_Item_List);

        static async Task<int> Main(string[] args)
        {
            var rootCommand = new RootCommand();
            var decodeCommand = new Command("dec", "Decodes a password");
            rootCommand.AddCommand(decodeCommand);
            var passwordArgument = new Argument<string>(
                name: "password",
                description: "The password to be decoded."
            );
            decodeCommand.AddArgument(passwordArgument);
            var fileOption = new Option<FileInfo?>(
                name: "--file",
                description: "Optional output file path"
            );
            decodeCommand.AddOption(fileOption);

            decodeCommand.SetHandler((passwordArgument, fileOption) =>
            {
                byte[] data = Decoder.mMpswd_decode_code(passwordArgument);
                Password password = new(data);

                string str = @$"================ Password {passwordArgument} ================
Type: {password.Type}
Present: {(password.PresentIndex == 0xFFFF ? "Random Famicom Only" : dict[password.GetPresentId()])} [{password.PresentIndex:X4}|{password.GetPresentId():X4}]
String0: {password.String0}
String1: {password.String1}
HitRateIndex: {password.HitRateIndex}
NpcCode: {password.NpcCode}
SpecialNpcType: {password.SpecialNpcType}
EmbeddedChecksum: {password.Checksum}

================ Calculated Info ================
Calculated Checksum: {password.CalculateChecksum()}
Valid Code: {password.IsValid()}

";

                if (fileOption == null)
                {
                    Console.WriteLine(str);
                }
                else
                {
                    File.AppendAllText(fileOption.FullName, str);
                }
            }, passwordArgument, fileOption);

            //string pswd = "こうくべべむむねまやんごがむむけうあむけうは";




            //string s = Encoder.mMpswd_encode_code(data);

            /*
            for (int i = 0; i < Common.pswd_famicom_list.Length; i++)
            {
                {
                    Console.WriteLine($"{Common.GetPresentItemNo(Common.pswd_famicom_list[i]):X4}\t{dict[Common.GetPresentItemNo(Common.pswd_famicom_list[i])]}");
                }
            }
            */
            /*
            for (ushort i = 0; i < Common.PRESENT_FTR_COUNT; i++)
            {
                if (Common.CheckHPMail_presentlist(i))
                {
                    Debug.WriteLine($"{Common.GetPresentItemNo(i):X4}\t{dict[Common.GetPresentItemNo(i)]}");
                }
            }

            for (int i = 0; i < Common.PRESENT_CLO_COUNT; i++)
            {
                ushort idx = (ushort)(Common.PRESENT_CLO_START + i);
                if (Common.CheckHPMail_presentlist(idx))
                {
                    Debug.WriteLine($"{Common.GetPresentItemNo(idx):X4}\t{dict[Common.GetPresentItemNo(idx)]}");
                }
            }


            for (int i = 0; i < Common.PRESENT_CPT_COUNT; i++)
            {
                ushort idx = (ushort)(Common.PRESENT_CPT_START + i);
                if (Common.CheckHPMail_presentlist(idx))
                {
                    Debug.WriteLine($"{Common.GetPresentItemNo(idx):X4}\t{dict[Common.GetPresentItemNo(idx)]}");
                }
            }

            for (int i = 0; i < Common.PRESENT_WAL_COUNT; i++)
            {
                ushort idx = (ushort)(Common.PRESENT_WAL_START + i);
                if (Common.CheckHPMail_presentlist(idx))
                {
                    Debug.WriteLine($"{Common.GetPresentItemNo(idx):X4}\t{dict[Common.GetPresentItemNo(idx)]}");
                }
            }
            */

            return await rootCommand.InvokeAsync(args);
        }
    }
}
