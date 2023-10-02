using System;

namespace ACPasswordLibrary.CommandLine.AnimalCrossing
{
    public sealed class CodeScorer
    {
        public enum Keyboard
        {
            QWERTY = 0, Alphabetical = 1, Both = 2
        }

        public static int ScoreCode(string code, Keyboard keyboard = Keyboard.Both)
        {
            var layout = Keyboard.QWERTY;
            var score = (code[20] != code[21]) ? 1 : 0;
            var currentChar = '!';

            if (keyboard == Keyboard.Both)
            {
                foreach (var nextChar in code)
                {
                    if (currentChar != nextChar)
                    {
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
                    }
                    currentChar = nextChar;
                }
            }
            else if (keyboard == Keyboard.QWERTY)
            {
                foreach (var nextChar in code)
                {
                    if (currentChar != nextChar)
                        score += CodeScoreData.QWERTYScores[currentChar][nextChar];

                    currentChar = nextChar;
                }
            }
            else
            {
                foreach (var nextChar in code)
                {
                    if (currentChar != nextChar)
                        score += CodeScoreData.AlphabeticalScores[currentChar][nextChar];

                    currentChar = nextChar;
                }
            }

            return score;
        }
    }
}
