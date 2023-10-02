namespace ACPasswordLibrary.CommandLine.AnimalCrossing
{
    public static class CodeScoreData
    {
        public static readonly char[][][] QWERTYLayout =
        {
            new[]
            {
                new[] { '!', '?', '"', '-', '~', '—', '\'', ';', ':', '⚷' },
                new[] { 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p' },
                new[] { 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', '\n' },
                new[] { 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', ' ' }
            },
            new[]
            {
                new[] { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' },
                new[] { 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P' },
                new[] { 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', '\n' },
                new[] { 'Z', 'X', 'C', 'V', 'B', 'N', 'M', ',', '.', ' ' },
            }
        };

        public static readonly char[][][] AlphabeticalLayout =
        {
            new[]
            {
                new[] { '!', '?', '"', '-', '~', '—', '\'', ';', ':', '⚷' },
                new[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j' },
                new[] { 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', '\n' },
                new[] { 't', 'u', 'v', 'w', 'x', 'y', 'z', ',', '.', ' ' },
            },
            new[]
            {
                new[] { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0' },
                new[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J' },
                new[] { 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', '\n' },
                new[] { 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ',', '.', ' ' },
            }
        };

        private static readonly char[][] SymbolsLayout =
        {
            new[] { '#', '?', '"', '-', '~', '—', '•', ';', ':', 'Æ' },
            new[] { '%', '&', '@', '_', '¯', '/', '¦', '×', '÷', '=' },
            new[] { '(', ')', '<', '>', '«', '»', '∈', '∋', '+', '\n' },
            new[] { 'ß', 'Þ', 'ð', '§', '‖', 'µ', '¬', ',', '.', ' ' }
        };

        private static Dictionary<char, Dictionary<char, int>> GenerateLayoutScoreDictionary(in char[][][] list, in char[][][] otherList)
        {
            var lookupDict = new Dictionary<char, Dictionary<char, int>>();

            try
            {
                for (var upperCase = 0; upperCase < 2; upperCase++)
                {
                    for (var row = 0; row < list[upperCase].Length; row++)
                    {
                        for (var col = 0; col < list[upperCase][row].Length; col++)
                        {
                            if (lookupDict.ContainsKey(list[upperCase][row][col])) continue;

                            var charDict = new Dictionary<char, int>();
                            lookupDict.Add(list[upperCase][row][col], charDict);

                            // Iterate through each array again and calculate variance.
                            for (var otherUpper = 0; otherUpper < 2; otherUpper++)
                            {
                                for (var otherRow = 0; otherRow < otherList[otherUpper].Length; otherRow++)
                                {
                                    for (var otherCol = 0; otherCol < otherList[otherUpper][otherRow].Length; otherCol++)
                                    {
                                        if (charDict.ContainsKey(otherList[otherUpper][otherRow][otherCol])) continue;

                                        var rowDifference = Math.Abs(row - otherRow);
                                        var colDifference = Math.Abs(col - otherCol);
                                        var movementDifference = rowDifference + colDifference;

                                        if (movementDifference == 0)
                                        {
                                            movementDifference += list != otherList ? 1 : 0;
                                            if (list == otherList)
                                                movementDifference += Math.Abs(upperCase - otherUpper);
                                        }

                                        var difference = Math.Min(movementDifference, 6);
                                        charDict.Add(otherList[otherUpper][otherRow][otherCol], difference);
                                    }
                                }
                            }

                            // Score Character => Symbol
                            for (var symRow = 0; symRow < SymbolsLayout.Length; symRow++)
                            {
                                for (var symCol = 0; symCol < SymbolsLayout[symRow].Length; symCol++)
                                {
                                    if (charDict.ContainsKey(SymbolsLayout[symRow][symCol])) continue;

                                    var rowDifference = Math.Abs(row - symRow);
                                    var colDifference = Math.Abs(col - symCol);
                                    var movementDifference = rowDifference + colDifference;

                                    if (movementDifference == 0)
                                        movementDifference += 2 + upperCase; // changed from 1 to 2

                                    var difference = Math.Min(movementDifference, 6);
                                    charDict.Add(SymbolsLayout[symRow][symCol], difference);
                                }
                            }
                        }
                    }
                }

                // Generate Symbols inline for list
                for (var symRow = 0; symRow < SymbolsLayout.Length; symRow++)
                {
                    for (var symCol = 0; symCol < SymbolsLayout[symRow].Length; symCol++)
                    {
                        if (lookupDict.ContainsKey(SymbolsLayout[symRow][symCol])) continue;

                        var charDict = new Dictionary<char, int>();
                        lookupDict.Add(SymbolsLayout[symRow][symCol], charDict);

                        for (var upperCase = 0; upperCase < 2; upperCase++)
                        {
                            for (var row = 0; row < list[upperCase].Length; row++)
                            {
                                for (var col = 0; col < list[upperCase][row].Length; col++)
                                {
                                    if (charDict.ContainsKey(list[upperCase][row][col])) continue;

                                    var rowDifference = Math.Abs(row - symRow);
                                    var colDifference = Math.Abs(col - symCol);
                                    var movementDifference = rowDifference + colDifference;

                                    if (movementDifference == 0)
                                    {
                                        movementDifference += list != otherList ? 1 : 0;
                                        if (list == otherList)
                                            movementDifference += upperCase;
                                    }

                                    var difference = Math.Min(movementDifference, 6);
                                    charDict.Add(list[upperCase][row][col], difference + 1); // Add one because of the extra keyboard transition.
                                }
                            }
                        }

                        // Score Symbol => Symbol
                        for (var row = 0; row < SymbolsLayout.Length; row++)
                        {
                            for (var col = 0; col < SymbolsLayout[row].Length; col++)
                            {
                                if (charDict.ContainsKey(SymbolsLayout[row][col])) continue;

                                var rowDifference = Math.Abs(symRow - row);
                                var colDifference = Math.Abs(symCol - col);

                                var difference = Math.Min(rowDifference + colDifference, 6);
                                charDict.Add(SymbolsLayout[row][col], difference);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return lookupDict;
        }

        #region QWERTY Scores
        public static Dictionary<char, Dictionary<char, int>> QWERTYScores = GenerateLayoutScoreDictionary(QWERTYLayout, QWERTYLayout);
        #endregion

        #region QWERTY -> Alphabetical Scores
        public static Dictionary<char, Dictionary<char, int>> QWERTYTransitionalScores = GenerateLayoutScoreDictionary(QWERTYLayout, AlphabeticalLayout);
        #endregion

        #region Alphabeical Scores
        public static Dictionary<char, Dictionary<char, int>> AlphabeticalScores = GenerateLayoutScoreDictionary(AlphabeticalLayout, AlphabeticalLayout);
        #endregion

        #region Alphabetical -> QWERTY Scores
        public static Dictionary<char, Dictionary<char, int>> AlphabeticalTransitionalScores = GenerateLayoutScoreDictionary(AlphabeticalLayout, QWERTYLayout);
        #endregion
    }
}
