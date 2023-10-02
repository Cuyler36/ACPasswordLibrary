using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using static ACPasswordLibrary.Common;

namespace ACPasswordLibrary.CmdLine
{
    class Program
    {
        static void Main(string[] args)
        {
            /*var passwordBytes = Encoder.MakePassword(CodeType.User, 1, "!", "!", 0x2200, 0, 0xFF);
            var password = BytesToString(passwordBytes);
            var decoded = Decoder.DecodeToPassword(passwordBytes);*/

            if (false)
            {
                if (args == null || args.Length < 1)
                {
                    Console.WriteLine("Enter the password to decode");
                    args = new[] { Console.ReadLine().Replace("\r", "").Replace("\n", "") };
                }

                if (args[0].Length == 28)
                {
                    var binaryData = new byte[28];
                    for (var i = 0; i < 28; i++)
                        if (CharacterSet.Contains(args[0][i].ToString()))
                            binaryData[i] = (byte)Array.IndexOf(CharacterSet, args[0][i].ToString());

                    var decodedPassword = Decoder.DecodeToPassword(binaryData);
                    Console.WriteLine($"Code Type: {decodedPassword.CodeType}");
                    Console.WriteLine($"Present Id: {decodedPassword.ItemId:X4}");
                    Console.WriteLine($"String0: {BytesToString(decodedPassword.String0)}");
                    Console.WriteLine($"String1: {BytesToString(decodedPassword.String1)}");
                    Console.WriteLine($"Npc Code: {decodedPassword.NpcCode:X2}");
                    Console.WriteLine($"Special Npc: {decodedPassword.IsSpecialNpc}");
                    Console.WriteLine($"Magazine Hit Rate Idx: {decodedPassword.HitRateIdx}");
                    Console.WriteLine($"Embedded Checksum: {decodedPassword.Checksum}");
                }
            }
            else
            {
                Console.WriteLine("Enter the hex item id of the item you'd like to generate codes for:");
                if (ushort.TryParse(Console.ReadLine(), System.Globalization.NumberStyles.HexNumber, null, out var itemId))
                {
                    Console.WriteLine("Enter the maximum number of passwords per thread to be generated (0 for infinite):");
                    if (uint.TryParse(Console.ReadLine(), out var generationCount))
                    {
                        Console.WriteLine("Enter the number of processor threads to use in generating passwords:");
                        if (uint.TryParse(Console.ReadLine(), out var threadCount))
                        {
                            if (threadCount > 0)
                            {
                                GenerateCardEMiniPassword(itemId, generationCount, threadCount + 1);
                            }
                        }
                    }
                }
            }

            Console.WriteLine($"Done!");
            Console.ReadKey();
        }

        /*static void GenerateNetPassword()
        {
            var passwords = 0;

            for (var npcType = 0; npcType < 2; npcType++)
            {
                for (var npcCode = 0; npcCode < 256; npcCode++)
                {
                    var password = Encoder.MakePassword(CodeType.User, 1, "!", "!", 0x2203, (byte)npcType, (byte)npcCode, true);
                    Console.WriteLine(BytesToString(password));
                    passwords++;
                }
            }

            Console.WriteLine($"Done! {passwords} passwords!");
        }*/


        static void GenerateCardEMiniPasswordThread(ushort itemId, int start, int end, int threadId, uint numPasswords)
        {
            var count = 0;
            var bestScore = int.MaxValue;
            var bestPassword = "";

            // String0
            for (var char0 = start; char0 < end; char0++)
            {
                for (var char1 = 0; char1 < 256; char1++)
                {
                    for (var char2 = 0; char2 < 256; char2++)
                    {
                        for (var char3 = 0; char3 < 256; char3++)
                        {
                            for (var char4 = 0; char4 < 256; char4++)
                            {
                                for (var char5 = 0; char5 < 256; char5++)
                                {
                                    for (var char6 = 0; char6 < 256; char6++)
                                    {
                                        for (var char7 = 0; char7 < 256; char7++)
                                        {
                                            var str = new byte[8]
                                            { (byte)char0, (byte)char1, (byte)char2, (byte)char3, (byte)char4, (byte)char5, (byte)char6, (byte)char7 };

                                            var password = BytesToString(Encoder.MakePassword(CodeType.Card_E_Mini, 1, str,
                                            str, itemId, 0, 0xFF));
                                            var thisScore = CodeScorer.ScoreCode(password);
                                            if (thisScore < bestScore)
                                            {
                                                bestScore = thisScore;
                                                bestPassword = password;
                                                Console.WriteLine($"Thread #{threadId} => Item Id: {itemId:X4} | Password: {password} | Score: {bestScore} | Passwords Generated: {count}");
                                            }

                                            count++;

                                            if (numPasswords > 0 && count >= numPasswords)
                                            {

                                                Console.ForegroundColor = ConsoleColor.Green;
                                                Console.WriteLine($"Thread #{threadId} BEST PASSWORD => Item Id: {itemId:X4} | Password: {bestPassword} | Score: {bestScore} | Passwords Generated: {count}");
                                                Console.ForegroundColor = ConsoleColor.White;
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

        static void GenerateCardEMiniPassword(ushort itemId, uint passCount, uint numThreads)
        {
            int numPerThread = 256 / (int)numThreads;
            var total = 0;
            for (var i = 0; i < numThreads; i++)
            {
                var x = i;
                var tempTotal = total;
                var t = new Thread(() => GenerateCardEMiniPasswordThread(itemId, tempTotal, x == numThreads - 1 ? 256 - tempTotal : (tempTotal + numPerThread), x, passCount));
                total += numPerThread;
                t.Start();
            }
        }
    }
}
