/*
   Copyright CrypTool 2 Team <ct2contact@CrypTool.org>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
using CrypTool.PluginBase;
using CrypTool.PluginBase.Miscellaneous;
using System;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Zxcvbn;
using Zxcvbn.Matcher.Matches;


namespace CrypTool.Plugins.ExtrapolateBruteforce
{
    [Author("Marius-Victor Włostowski", "marius.wlostowski@gmx.de", "Bachelor thesis 'Extrapolation von Bruteforceangriffen' UniBW - 06/24", "dummy email address")]
    
    [PluginInfo("CrypTool.Plugins.ExtrapolateBruteforce.Properties.Resources", "ExtrapolateBruteforceCaption", "ExtrapolateBruteforceTooltip", "ExtrapolateBruteforce/userdoc.xml", "CrypWin/images/default.png")]
    //Incorporated Dan Wheeler's "zxcvbn core"-package for C#, and "zxcvbn extra" by thus plus AdisonCavani
    [ComponentCategory(ComponentCategory.ToolsMisc)] 
    public class ExtrapolateBruteforce : ICrypComponent
    {
        
        #region Private Variables
        private readonly ExtrapolateBruteforcePresentation _presentation = new ExtrapolateBruteforcePresentation();
        private string _password; // input _password
        private string _passwordFeedback; //Gathers a detailed report on the password analysis done.
        private readonly ExtrapolateBruteforceSettings _settings = new ExtrapolateBruteforceSettings();
        #endregion

        public event PropertyChangedEventHandler PropertyChanged;
        
        #region Data Properties
        [PropertyInfo(Direction.InputData, "PasswordCaption", "PasswordTooltip", false)]
        public string Password
        {
            get => _password;
            set => _password = value;
        }

        [PropertyInfo(Direction.OutputData, "PasswordFeedbackCaption", "PasswordFeedbackTooltip", false)]
        public string PasswordFeedback
        {
            get => _passwordFeedback;
            set
            {
                _passwordFeedback = value;
                OnPropertyChanged("PasswordFeedback");
            }
        }
        #endregion

        #region IPlugin Members

        /// <summary>
        /// Provide plugin-related parameters (per instance) or return null.
        /// </summary>
        public ISettings Settings => _settings;
        
        //public UserControl ExtrapolateBruteforcePresentation => _presentation;

        public UserControl Presentation => _presentation;
        #endregion


        /// <summary>
        /// Provide custom presentation to visualize the execution or return null.
        /// </summary>


        /// <summary>
        /// Called once when workflow execution starts.
        /// </summary>
        public void PreExecution()
        {
        }

        /// <summary>
        /// Called every time this plugin is run in the workflow execution.
        /// </summary>
        #region Execute
        public void Execute()
        {
            // HOWTO: Use this to show the progress of a plugin algorithm execution in the editor.
            ProgressChanged(0, 1);
            #region executeStartingVariables
            if (this._password == null)
            {
                return;
            }

            Result result = Core.EvaluatePassword(_password);
            string passwordFeedback = _passwordFeedback;
            StringBuilder passwordFeedbackSummarizer = new StringBuilder();
            
            //Concerning character types
            bool lowercaseLetters = false;
            int lowercaseLettersAmount = 0;
            bool uppercaseLetters = false;
            int uppercaseLettersAmount = 0;
            bool numbers = false;
            int numbersAmount = 0;
            bool specialCharacters = false;
            int specialCharactersAmount = 0;     
            
            //basic metrics of the password
            int passwordLength = _password.Length;
            double zxcvbnEntropy = Math.Round(result.Entropy, 2);
            double shannonEntropy = Math.Log(94, 2)*passwordLength;
            double guessesUser = result.GuessesLog10; //guesses taken for password from user's perspective, for display reasons
            double guessesAttackerAmount = Math.Pow(94, passwordLength)/2; //for display  reasons
            double guessesAttacker = Math.Round(Math.Log10(guessesAttackerAmount), 2);
            
            ///* Hash-Mode 3200 (bcrypt $2*$, Blowfish (Unix)) [Iterations: 32]
            ///Speed.#1.........:   184.0 kH/s (50.22ms) @ Accel:4 Loops:32 Thr:24 Vec:1
            ///snippet source: https://gist.githubusercontent.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd/raw/265c25315440e0219e9c0406a56369ccaf640ac6/RTX_4090_v6.2.6.Benchmark
            double rtx4090HashingRig = 1840000; //184.0 kilohashes/s*10 = Hashing speed of 10 nvidia GeForce RTX4090 with hashcat = 1.84 megahashes/s
           
            double bruteforceTimeSecondsUser = Math.Round(result.Guesses / rtx4090HashingRig, 2);
            double bruteforceTimeSecondsAttacker = Math.Round(guessesAttackerAmount / rtx4090HashingRig, 2);
           
            //Calling the method timeUnitPicker for returning a string.Format with the exact time amount and unit as string
            string bruteforceTimeUser = timeUnitPicker(bruteforceTimeSecondsUser);
            string bruteforceTimeAttacker = timeUnitPicker(bruteforceTimeSecondsAttacker);
            #endregion

            // Ranges: Very Weak, Weak, Moderate, Strong, Very Strong
            int passwordScore = passwordScoreCalculator(bruteforceTimeSecondsUser);

            #region Analysis concerning character types and their amount of characters relative to password length
            //checking for character type amounts
            //code snippet modified from Nils Kopals "PasswordStrength"-plugin
            foreach (char c in _password)
            {
                //lowercase letters
                if (char.IsLower(c))
                {
                    lowercaseLettersAmount++;
                }
                //uppercase letters
                else if (char.IsUpper(c))
                {
                    uppercaseLettersAmount++;
                }
                //numbers
                else if (char.IsDigit(c))
                {
                    numbersAmount++;
                }
                //special characters
                else if (!char.IsLetterOrDigit(c))
                {
                    specialCharactersAmount++;
                }
                else 
                { 
 
                }
            }
            // setting boolian values for character types based on amounts found
            if (lowercaseLettersAmount != 0)
            {
                lowercaseLetters = true;
            }
            if (uppercaseLettersAmount != 0)
            {
                uppercaseLetters = true;
            }
            if (numbersAmount != 0)
            {
                numbers = true;
            }
            if (specialCharactersAmount != 0)
            {
                specialCharacters = true;
            }

            //calculating percentage values of character usage in password, rounded to two digits
            double lowercaseQuotient = Math.Round((double)lowercaseLettersAmount/(double)passwordLength*100, 2);
            double uppercaseQuotient = Math.Round((double)uppercaseLettersAmount/(double)passwordLength * 100, 2);
            double numbersQuotient = Math.Round((double)numbersAmount/(double)passwordLength * 100, 2);
            double specialCharactersQuotient = Math.Round((double)specialCharactersAmount/(double)passwordLength * 100, 2);
            #endregion

            #region Dictionary matches found
            int matchLength = 0;
            int matchesAmount = 0;
            double passwordQuotient = 0;
            StringBuilder helper = new StringBuilder();
            if (result.MatchSequence.Any() == false)
            {
                helper.AppendLine(Properties.Resources._noMatchesFound);
            }
            else
            {
                foreach (Zxcvbn.Matcher.Matches.Match match in result.MatchSequence)
                {
                    if (match is BruteForceMatch bruteForceMatch)
                    { } // bruteforce matches don't count, because guessing attacks have to follow sophisticated rules  
                    else
                    {
                        if (match is DateMatch dateMatch)
                        {
                            helper.AppendLine("'" + dateMatch.Token + Properties.Resources._foundIn + match.Pattern + "'\n");
                            matchLength = matchLength + dateMatch.Token.Length;
                            matchesAmount++;
                        }
                        else if (match is DictionaryMatch dictionaryMatch)
                        {
                            helper.AppendLine("'" + dictionaryMatch.Token + Properties.Resources._foundIn + match.Pattern + "'\n");
                            matchLength = matchLength + dictionaryMatch.Token.Length;
                            matchesAmount++;
                        }
                        else if (match is RegexMatch regexMatch)
                        {
                            helper.AppendLine("'" + regexMatch.Token + Properties.Resources._foundIn + match.Pattern + "'\n");
                            matchLength = matchLength + regexMatch.Token.Length;
                            matchesAmount++;
                        }
                        else if (match is RepeatMatch repeatMatch)
                        {
                            helper.AppendLine("'" + repeatMatch.Token + Properties.Resources._foundIn + match.Pattern + "'\n");
                            matchLength = matchLength + repeatMatch.Token.Length;
                            matchesAmount++;
                        }
                        else if (match is SequenceMatch sequenceMatch)
                        {
                            helper.AppendLine("'" + sequenceMatch.Token + Properties.Resources._foundIn + match.Pattern + "'\n");
                            matchLength = matchLength + sequenceMatch.Token.Length;
                            matchesAmount++;
                        }
                        else if (match is SpatialMatch spatialMatch)
                        {
                            helper.AppendLine("'" + spatialMatch.Token + Properties.Resources._foundIn + match.Pattern + "'\n");
                            matchLength = matchLength + spatialMatch.Token.Length;
                            matchesAmount++;
                        }
                        else 
                        { 
                        
                        }
                    }
                }
                if (matchesAmount == 0)
                {
                    passwordQuotient = 0;
                    helper.Insert(0, Properties.Resources._noMatchesFound);
                }
                else if (passwordLength == matchLength)
                {
                    passwordQuotient = 100;
                    helper.Insert(0, Properties.Resources._matchesOneHundredPercent + "\n");
                }
                else
                {
                    passwordQuotient = Math.Round((double)matchLength / (double)passwordLength * 100, 2);
                    if(matchesAmount == 1)
                    {
                        helper.Insert(0, string.Format(Properties.Resources._matchFound + "\n", matchesAmount));
                    }
                    else 
                    {
                        helper.Insert(0, string.Format(Properties.Resources._matchesFound + "\n", matchesAmount));
                    }
                }
            }
            ProgressChanged(0.25, 1);
            #endregion
            ///Analysis of the password string and its evaluation.
            ///Checking for it's length, character types [lower-/uppercase, numbers and special characters], entropy value
            ///as well as whether any matches were found - if matches are found a comparison quotient will be calculated as [% of password substrings found in dictionaries]: 
            ///The result of the analysis is gathered in a stringbuilder for GUI display.
            #region passwordFeedback
            if (passwordLength < 8)
            {
                passwordFeedbackSummarizer.AppendLine(Properties.Resources._tooShort);
            }
            else if (passwordLength == 8)
            {
                passwordFeedbackSummarizer.AppendLine(Properties.Resources._minimumLengthReached);
            }
            else if (passwordLength > 8 && passwordLength < 12)
            {
                passwordFeedbackSummarizer.AppendLine(Properties.Resources._minimumLengthSurpassed);
            }
            else if (passwordLength == 12)
            {
                passwordFeedbackSummarizer.AppendLine(Properties.Resources._minimumSecureLengthReached);
            }
            else if (passwordLength > 12)
            {
                passwordFeedbackSummarizer.AppendLine(Properties.Resources._secureMinimumLengthSurpassed);
            }
            else
            {
                passwordFeedbackSummarizer.AppendLine(string.Format("ERROR: passwordLength = {0}", passwordLength));
            }

            if (passwordQuotient >= 50)
            {
                passwordFeedbackSummarizer.AppendLine(string.Format(Properties.Resources._fiftyPercentOfDictionaryMatches, passwordQuotient));
            }
            else if (passwordQuotient == 100)
            {
                passwordFeedbackSummarizer.AppendLine(string.Format(Properties.Resources._matchesOneHundredPercent, passwordQuotient));
            }
            if (result.Entropy < 40)
            {
                passwordFeedbackSummarizer.AppendLine(string.Format(Properties.Resources._entropyLow, zxcvbnEntropy));
            }
            else if (result.Entropy >= 60 && result.Entropy < 90)
            {
                passwordFeedbackSummarizer.AppendLine(Properties.Resources._entropyGood);
            }
            else if (result.Entropy >= 90 && result.Entropy < 120)
            {
                passwordFeedbackSummarizer.AppendLine(Properties.Resources._entropyStrong);
            }
            else if (result.Entropy >= 120)
            {
                passwordFeedbackSummarizer.AppendLine(Properties.Resources._entropyVeryStrong);
            }
            else
            {

            }
            #endregion

            //Feedback appends all necessary helper strings
            passwordFeedbackSummarizer.Append(helper.ToString().Trim());
            passwordFeedback = passwordFeedbackSummarizer.ToString().Trim();
            PasswordFeedback = passwordFeedback;
            ProgressChanged(0.5, 1);
            #region presentation
            _presentation.Dispatcher.Invoke(DispatcherPriority.Normal, (SendOrPostCallback)delegate
            {
                try
                {
                    //Labeling Password Strength by evaluating the calculated password score
                    //Modified code is a snippet of Nils Kopals plugin "PasswordStrength"
                    #region passwordStrength
                    _presentation.PasswordStrengthProgressBar.Maximum = 5;
                    _presentation.PasswordStrengthProgressBar.Value = passwordScore + 1;
                    if (passwordScore == 0) 
                    {
                        _presentation.PasswordStrengthProgressBar.Foreground = Brushes.DarkRed;
                        _presentation.PasswordStrength.Text = string.Format(Properties.Resources._veryWeak);
                        _presentation.PasswordStrength.Foreground = Brushes.Black;
                    }
                    else if (passwordScore == 1) 
                    {
                        _presentation.PasswordStrengthProgressBar.Foreground = Brushes.Orange;
                        _presentation.PasswordStrength.Text = string.Format(Properties.Resources._weak);
                        _presentation.PasswordStrength.Foreground = Brushes.Black;
                    }
                    else if (passwordScore == 2) 
                    {
                        _presentation.PasswordStrengthProgressBar.Foreground = Brushes.Gold;
                        _presentation.PasswordStrength.Text = string.Format(Properties.Resources._moderate);
                        _presentation.PasswordStrength.Foreground = Brushes.Black;
                    }
                    else if (passwordScore == 3) 
                    {
                        _presentation.PasswordStrengthProgressBar.Foreground = Brushes.GreenYellow;
                        _presentation.PasswordStrength.Text = string.Format(Properties.Resources._strong);
                        _presentation.PasswordStrength.Foreground = Brushes.Black;
                    }
                    else if (passwordScore == 4) 
                    {
                        _presentation.PasswordStrengthProgressBar.Foreground = Brushes.DarkGreen;
                        _presentation.PasswordStrength.Text = string.Format(Properties.Resources._veryStrong);                        
                        _presentation.PasswordStrength.Foreground = Brushes.LightGray;
                    }
                    else 
                    {
                        _presentation.PasswordStrength.Text = "ERROR: This case should never be reached: passwordStrength calculation went wrong.";
                        _presentation.PasswordStrengthProgressBar.Foreground = Brushes.Lavender;
                    }
                    #endregion
                    
                    //BruteforceTimeUserGUI
                    _presentation.BruteforceTimeUser.Text = bruteforceTimeUser;

                    //guesses needed from user's perspective
                    _presentation.GuessesUser.Text = string.Format(Properties.Resources._guessesUserCaption, Math.Round(guessesUser, 2));

                    //NIST-EntropyGUI
                    _presentation.zxcvbnEntropy.Text = string.Format(Properties.Resources._zxcvbnEntropyCaption, zxcvbnEntropy);

                    //passwordLengthGUI
                    if (passwordLength == 1)
                    {
                        _presentation.PasswordLength.Text = string.Format(Properties.Resources._stringLengthOneCharacter);
                    }
                    else
                    {
                        _presentation.PasswordLength.Text = string.Format(Properties.Resources._stringLengthOtherThanOne, passwordLength);
                    }

                    //configuring word usage "character(s)" for the PasswordQuotient presentation
                    if (matchLength != 1)
                    {
                        _presentation.PasswordQuotient.Text = string.Format(Properties.Resources._passwordQuotientCaption, passwordQuotient, matchLength, Properties.Resources._characters);
                    }
                    else
                    {
                        _presentation.PasswordQuotient.Text = string.Format(Properties.Resources._passwordQuotientCaption, passwordQuotient, matchLength, Properties.Resources._character);
                    }

                    ProgressChanged(0.75, 1);

                    ///Checking for character types, their amount and setting boolian values for later -> GUI 
                    #region Letters, decimal digits and special characters
                    //lowercaseLettersGUI
                    if (lowercaseLetters == true)
                    {
                        if (lowercaseLettersAmount == 1)
                        {
                            _presentation.LowercaseLetters.Text = string.Format(Properties.Resources._lowercaseLetter, lowercaseQuotient);
                        }
                        else if (lowercaseLettersAmount > 1)
                        {
                            _presentation.LowercaseLetters.Text = string.Format(Properties.Resources._lowercaseLetters, lowercaseLettersAmount, lowercaseQuotient);
                        }
                        else
                        {
                            _presentation.LowercaseLetters.Text = string.Format("ERROR. This should not have happened. lowercaseLettersGUI amount = {0}", lowercaseLettersAmount);
                        }
                    }
                    else
                    {
                        _presentation.LowercaseLetters.Text = string.Format(Properties.Resources._noLowercaseLetters);
                    }
                    //uppercaseLettersGUI
                    if (uppercaseLetters == true)
                    {
                        if (uppercaseLettersAmount == 1)
                        {
                            _presentation.UppercaseLetters.Text = string.Format(Properties.Resources._uppercaseLetter, uppercaseQuotient);
                        }
                        else if (uppercaseLettersAmount > 1)
                        {
                            _presentation.UppercaseLetters.Text = string.Format(Properties.Resources._uppercaseLetters, uppercaseLettersAmount, uppercaseQuotient);
                        }
                        else
                        {
                            _presentation.UppercaseLetters.Text = string.Format("ERROR. This should not have happened. uppercaseLettersGUI amount = {0}", uppercaseLettersAmount);
                        }
                    }
                    else
                    {
                        _presentation.UppercaseLetters.Text = string.Format(Properties.Resources._noUppercaseLetters);
                    }
                    //numbersGUI
                    if (numbers == true)
                    {
                        if (numbersAmount == 1)
                        {
                            _presentation.Numbers.Text = string.Format(Properties.Resources._number, numbersQuotient);
                        }
                        else if (numbersAmount > 1)
                        {
                            _presentation.Numbers.Text = string.Format(Properties.Resources._numbers, numbersAmount, numbersQuotient);
                        }
                        else
                        {
                            _presentation.Numbers.Text = string.Format("ERROR. This should not have happened. numbersGUI amount = {0}", numbersAmount);
                        }
                    }
                    else
                    {
                        _presentation.Numbers.Text = string.Format(Properties.Resources._noNumbers);
                    }
                    //specialCharactersGUI
                    if (specialCharacters == true)
                    {
                        if (specialCharactersAmount == 1)
                        {
                            _presentation.SpecialCharacters.Text = string.Format(Properties.Resources._specialCharacter, specialCharactersQuotient);
                        }
                        else if (specialCharactersAmount > 1)
                        {
                            _presentation.SpecialCharacters.Text = string.Format(Properties.Resources._specialCharacters, specialCharactersAmount, specialCharactersQuotient);
                        }
                        else
                        {
                            _presentation.SpecialCharacters.Text = string.Format("ERROR. This should not have happened. lowercaseLettersGUI amount = {0}", specialCharactersAmount);
                        }
                    }
                    else
                    {
                        _presentation.SpecialCharacters.Text = string.Format(Properties.Resources._noSpecialCharacters);
                    }
                    #endregion

                    //BruteforceTimeAttackerGUI
                    _presentation.BruteforceTimeAttacker.Text = string.Format(Properties.Resources._bruteforceTimeAttackerCaption, bruteforceTimeAttacker);

                    //GuessesAttackerGUI
                    _presentation.GuessesAttacker.Text = string.Format(Properties.Resources._guessesAttackerCaption, guessesAttacker);

                    //ShannonEntropyGUI
                    _presentation.ShannonEntropy.Text = string.Format(Properties.Resources._shannonEntropyCaption, Math.Round(shannonEntropy, 2));                                      
                    
                    ProgressChanged(1, 1);
                }
                catch (Exception ex)
                {
                    GuiLogMessage(string.Format("Exception during update of ExtrapolateBruteforcePresentation: {0}", ex.Message), NotificationLevel.Error);
                }
            }, null);
            #endregion
        }
        #endregion
 
        public void PostExecution()
        {
            Execute();
        }


        public void Stop()
        {
        }

        public void Initialize()
        {
        }

        public void Dispose()
        {
        }

        

        #region Event Handling

        public event StatusChangedEventHandler OnPluginStatusChanged;

        public event GuiLogNotificationEventHandler OnGuiLogNotificationOccured;

        public event PluginProgressChangedEventHandler OnPluginProgressChanged;

        private void GuiLogMessage(string message, NotificationLevel logLevel)
        {
            if (OnGuiLogNotificationOccured != null)
            {
                OnGuiLogNotificationOccured(this, new GuiLogEventArgs(message, this, logLevel));
            }
        }

        private void OnPropertyChanged(string name)
        {
            EventsHelper.PropertyChanged(PropertyChanged, this, new PropertyChangedEventArgs(name));
        }

        private void ProgressChanged(double value, double max)
        {
            EventsHelper.ProgressChanged(OnPluginProgressChanged, this, new PluginProgressEventArgs(value, max));
        }
        #endregion        

        #region timeUnitPicker
        public string timeUnitPicker(double seconds)
        {
            int secondsPerYear = 31557600; //(365*3+366)days per year/4 years = 365.25 days per year
            int secondsPerDay = 86400;
            int secondsPerHour = 3600;
            int secondsPerMinute = 60;

            double years = Math.Round(seconds / secondsPerYear, 2);
            double days = Math.Round(seconds / secondsPerDay, 2); ;
            double hours = Math.Round(seconds / secondsPerHour, 2);
            double minutes = Math.Round(seconds / secondsPerMinute, 2);
            if (years < 1)
            {
                if (days < 1)
                {
                    if (hours < 1)
                    {
                        if (minutes < 1)
                        {
                            if (seconds > 1)
                            {
                                return string.Format("{0} {1}" , seconds, Properties.Resources._seconds);
                            }
                            else if (seconds == 1)
                            {
                                return string.Format("{0} {1}", seconds, Properties.Resources._second);
                            }
                            else
                            {
                                return string.Format("< 1 {0}", Properties.Resources._second);
                            }
                        }
                        else if (minutes > 1 | minutes == 1)
                        {                            
                            if (minutes > 1)
                            {
                                return string.Format("{0} {1}", minutes, Properties.Resources._minutes);
                            }
                            else
                            {
                                return string.Format("{0} {1}", minutes, Properties.Resources._minute);
                            }
                        }
                    }
                    else if (hours > 1 | hours == 1)
                    {
                        if (hours > 1)
                        {
                            return string.Format("{0} {1}", hours, Properties.Resources._hours);
                        }
                        else
                        {
                            return string.Format("{0} {1}", hours, Properties.Resources._hour);
                        }
                    }

                }
                else if (days > 1 | days == 1)
                {
                    if (days > 1)
                    {
                        return string.Format("{0} {1}", days, Properties.Resources._days);
                    }
                    else
                    {
                        return string.Format("{0} {1}", seconds, Properties.Resources._day);
                    }
                }
            }
            else
            {               
                if (years > 1)
                {
                    return string.Format("{0} {1}", years, Properties.Resources._years);
                }
                else
                {
                    return string.Format("{0} {1}", years, Properties.Resources._year);
                }
            }
            return "ERROR in timeUnitPicker!";
        }
        #endregion

        #region passwordScoreCalculator
        public int passwordScoreCalculator(double seconds)
        {
            int secondsPerYear = 31557600;
            int secondsPerDay = 86400;
            int secondsPerMinute = 60;

            if (seconds / secondsPerMinute < 1)
            {
                return 0;
            }
            else if (seconds / secondsPerDay < 1)
            {
                return 1;
            }
            else if (seconds / secondsPerYear < 1)
            {
                return 2;
            }
            else if (seconds / secondsPerYear < 1000)
            {
                return 3;
            }
            else
            {
                return 4;
            }
        }
        #endregion
    }
}
