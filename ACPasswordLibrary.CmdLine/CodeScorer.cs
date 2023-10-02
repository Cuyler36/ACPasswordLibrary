namespace ACPasswordLibrary.CmdLine
{
    public sealed class CodeScorer
    {
        public enum Keyboard
        {
            QWERTY = 0, Alphabetical = 1
        }

        public static int ScoreCode(string code)
        {
            var layout = Keyboard.QWERTY;

            var score = 0;
            var currentChar = '1';
            foreach (var nextChar in code)
            {
                if (currentChar == nextChar) continue; // No score change at all.

                if (layout == Keyboard.QWERTY)
                {
                    var qwertyScore = CodeScoreData.QWERTYScores[currentChar][nextChar];
                    var transitionScore = CodeScoreData.QWERTYTransitionalScores[currentChar][nextChar];
                    if (qwertyScore <= transitionScore)
                        score += qwertyScore;
                    else
                    {
                        score += transitionScore;
                        layout = Keyboard.Alphabetical;
                    }
                }
                else
                {
                    var alphaScore = CodeScoreData.AlphabeticalScores[currentChar][nextChar];
                    var transitionScore = CodeScoreData.AlphabeticalTransitionalScores[currentChar][nextChar];
                    if (alphaScore <= transitionScore)
                        score += alphaScore;
                    else
                    {
                        score += transitionScore;
                        layout = Keyboard.QWERTY;
                    }
                }

                currentChar = nextChar;
            }

            return score;
        }
    }
}
