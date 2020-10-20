using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace CTR.NET
{
    public class SMDHInfo
    {
        private static readonly string[] Languages = {
            "Japanese (JP)",
            "English (EN)",
            "French (FR)",
            "German",
            "Italian",
            "Spanish",
            "Simplified Chinese",
            "Korean",
            "Dutch",
            "Portuguese",
            "Russian",
            "Traditional Chinese"
        };

        public string Magic { get; private set; }
        public string Version { get; private set; }
        public int VersionNumber { get; private set; }
        public List<SMDHTitleNameStructure> TitleNames { get; private set; }
        public SMDHApplicationSettings ApplicationSettings { get; private set; }

        public SMDHInfo(byte[] smdhData)
        {
            this.Magic = smdhData.TakeBytes(0x0, 0x4).Decode(Encoding.UTF8);
            this.Version = Tools.GetVersion(smdhData.TakeBytes(0x4, 0x6), out int versionInt);
            this.VersionNumber = versionInt;

            byte[] nameStructuresRaw = smdhData.TakeBytes(0x8, 0x2000);
            int index = 0;

            this.TitleNames = new List<SMDHTitleNameStructure>();

            for (int i = 0; i < nameStructuresRaw.Length - 0xA00; i += 0x200)
            {
                this.TitleNames.Add(new SMDHTitleNameStructure(nameStructuresRaw.TakeBytes(i, i + 0x200), Languages[index]));
                index++;
            }

            this.ApplicationSettings = new SMDHApplicationSettings(smdhData.TakeBytes(0x2008, 0x2038));
        }

        public SMDHInfo()
        {
            this.Magic = "N/A";
            this.Version = "N/A";
            this.VersionNumber = -1;
            this.TitleNames = new List<SMDHTitleNameStructure>() { new SMDHTitleNameStructure() };
            this.ApplicationSettings = new SMDHApplicationSettings();
        }

        public override string ToString()
        {
            string output = $"SMDH Info:\n\nMagic: \"{this.Magic}\"\n" +
                   $"Version: {this.Version}\n" +
                   $"Title Structure: \n\n";

            foreach (SMDHTitleNameStructure stns in this.TitleNames)
            {
                output += $"{stns}\n\n";
            }

            output += $"\n{this.ApplicationSettings}";

            return output;
        }
    }

    public class SMDHTitleNameStructure
    {
        public string LongTitle { get; set; }
        public string ShortTitle { get; set; }
        public string Publisher { get; set; }
        public string Language { get; set; }

        public SMDHTitleNameStructure(byte[] titleNameStructureRaw, string language)
        {
            this.LongTitle = titleNameStructureRaw.TakeBytes(0x0, 0x80).Decode(Encoding.Unicode);
            this.ShortTitle = titleNameStructureRaw.TakeBytes(0x80, 0x180).Decode(Encoding.Unicode);
            this.Publisher = titleNameStructureRaw.TakeBytes(0x180, 0x200).Decode(Encoding.Unicode);
            this.Language = language;
        }

        public SMDHTitleNameStructure()
        {
            this.Language = "N/A";
            this.LongTitle = "N/A";
            this.Publisher = "N/A";
            this.ShortTitle = "N/A";
        }

        public override string ToString() => $"-------------------------------\n\nSMDH Title Name Structure:\n\nLanguage: {this.Language}\n\nLong Title: {this.LongTitle}\n\nShort Title: {this.ShortTitle}\n\nPublisher: {this.Publisher}";
    }

    public class SMDHApplicationSettings
    {
        public List<GameRating> GameRatings { get; private set; } = new List<GameRating>();
        public string RegionLockout { get; private set; }
        public string MatchmakerID { get; private set; }
        public string MatchmakerBitID { get; private set; }
        public SMDHFlags Flags { get; private set; }
        public string EulaVersion { get; private set; }
        public int EulaVersionNumber { get; private set; }
        public string OptionalAnimationDefaultFrame { get; private set; }
        public string CEC_StreePassID { get; private set; }

        public SMDHApplicationSettings(byte[] applicationSettings)
        {
            this.GameRatings.Add(new GameRating(applicationSettings[0], "CERO (Japan)"));
            this.GameRatings.Add(new GameRating(applicationSettings[1], "ESRB (USA)"));
            this.GameRatings.Add(new GameRating(applicationSettings[3], "USK (Germany)"));
            this.GameRatings.Add(new GameRating(applicationSettings[4], "PEGI GEN (Europe)"));
            this.GameRatings.Add(new GameRating(applicationSettings[6], "PEGI PRT (Portugal)"));
            this.GameRatings.Add(new GameRating(applicationSettings[7], "PEGI BBFC (England)"));
            this.GameRatings.Add(new GameRating(applicationSettings[8], "COB (Australia)"));
            this.GameRatings.Add(new GameRating(applicationSettings[9], "GRB (South Korea)"));
            this.GameRatings.Add(new GameRating(applicationSettings[10], "CGSRR (Taiwan)"));
            //15
            int regionLockoutRaw = applicationSettings.TakeBytes(16, 20).IntLE();

            if ((regionLockoutRaw & 0x01) == 1)
            {
                this.RegionLockout = "Japan (JP)";
            }
            else if ((regionLockoutRaw & 0x02) == 2)
            {
                this.RegionLockout = "North America (US)";
            }
            else if ((regionLockoutRaw & 0x04) == 4)
            {
                this.RegionLockout = "Europe (EU)";
            }
            else if ((regionLockoutRaw & 0x08) == 8)
            {
                this.RegionLockout = "Australia (AU)";
            }
            else if ((regionLockoutRaw & 0x10) == 16)
            {
                this.RegionLockout = "China (CN)";
            }
            else if ((regionLockoutRaw & 0x20) == 32)
            {
                this.RegionLockout = "Korea (KO)";
            }
            else if ((regionLockoutRaw & 0x40) == 64)
            {
                this.RegionLockout = "Taiwan (TW)";
            }
            else
            {
                this.RegionLockout = "Region Free (RF)";
            }

            this.MatchmakerID = applicationSettings.TakeBytes(20, 24).Hex();
            this.MatchmakerBitID = applicationSettings.TakeBytes(24, 32).Hex();
            this.Flags = new SMDHFlags(applicationSettings.TakeBytes(32, 36).IntLE());
            this.EulaVersion = Tools.GetVersion(applicationSettings.TakeBytes(36, 38), out int versionNumber);
            this.EulaVersionNumber = versionNumber;
            this.OptionalAnimationDefaultFrame = applicationSettings.TakeBytes(40, 44).Hex();
            this.CEC_StreePassID = applicationSettings.TakeBytes(44, 48).IntLE().ToString();
        }

        public SMDHApplicationSettings ()
        {
            this.GameRatings = new List<GameRating>() { new GameRating() };
            this.RegionLockout = "N/A";
            this.MatchmakerID = "N/A";
            this.MatchmakerBitID = "N/A";
            this.Flags = new SMDHFlags();
            this.EulaVersion = "N/A";
            this.EulaVersionNumber = -1;
            this.OptionalAnimationDefaultFrame = "N/A";
            this.CEC_StreePassID = "N/A";
        }

        public override string ToString()
        {
            string output = "Age Ratings:\n\n";

            foreach (GameRating gr in this.GameRatings)
            {
                output += $"{gr}\n\n";
            }

            output += $"Region Lockout Region: {this.RegionLockout}\n";
            output += $"Online Play Matchmaker ID: {this.MatchmakerID}\n";
            output += $"Online Play Matchmaker Bit ID: {this.MatchmakerBitID}\n";
            output += $"EULA (End User License Agreement) Version: {this.EulaVersion}\n";
            output += $"Optional Animation Default Frame: {this.OptionalAnimationDefaultFrame}\n";
            output += $"CEC (StreetPass) ID: {this.CEC_StreePassID}\n\n";
            output += $"{this.Flags}\n\n";

            return output;
        }
    }

    public class GameRating
    {
        public int RawData { get; private set; }
        public string Description { get; private set; }
        public int AgeRating { get; private set; }
        public bool isEnabled { get; private set; }

        public GameRating(int rawData, string description)
        {
            this.Description = description;

            if ((rawData & 0x80) != 0)
            {
                this.isEnabled = true;
                this.AgeRating = rawData - 0x80;
            }
        }

        public GameRating()
        {
            this.RawData = -1;
            this.Description = "N/A";
            this.AgeRating = -1;
            this.isEnabled = false;
        }

        public override string ToString()
        {
            if (this.isEnabled)
            {
                return $"{this.Description}: {this.AgeRating} years and up";
            }

            return $"{this.Description}: Not enabled";
        }
    }

    public class SMDHFlags
    {
        public bool IsVisible { get; set; } = false;
        public bool AutoBoot { get; set; } = false;
        public bool Uses3D { get; set; } = false;
        public bool RequiresAcceptanceOfEULA { get; set; } = false;
        public bool AutoSaveOnExit { get; set; } = false;
        public bool UsesExtendedBanner { get; set; } = false;
        public bool RegionGameRatingRequired { get; set; } = false;
        public bool UsesSaveData { get; set; } = false;
        public bool ApplicatonDataIsRecorded { get; set; } = false;
        public bool SDSaveDataBackupsDisabled { get; set; } = false;
        public bool IsNew3DSExclusive { get; set; } = false;

        public SMDHFlags ()
        {
            this.IsVisible = false;
            this.AutoBoot = false;
            this.Uses3D = false;
            this.RequiresAcceptanceOfEULA = false;
            this.AutoSaveOnExit = false;
            this.UsesExtendedBanner = false;
            this.RegionGameRatingRequired = false;
            this.UsesSaveData = false;
            this.ApplicatonDataIsRecorded = false;
            this.SDSaveDataBackupsDisabled = false;
            this.IsNew3DSExclusive = false;
        }

        public SMDHFlags(int flags)
        {
            if ((flags & 0x0001) > 0)
            {
                this.IsVisible = true;
            }

            if ((flags & 0x0002) > 0)
            {
                this.AutoBoot = true;
            }

            if ((flags & 0x0004) > 0)
            {
                this.Uses3D = true;
            }

            if ((flags & 0x0008) > 0)
            {
                this.RequiresAcceptanceOfEULA = true;
            }

            if ((flags & 0x0010) > 0)
            {
                this.AutoSaveOnExit = true;
            }

            if ((flags & 0x0020) > 0)
            {
                this.UsesExtendedBanner = true;
            }

            if ((flags & 0x0040) > 0)
            {
                this.RegionGameRatingRequired = true;
            }

            if ((flags & 0x0080) > 0)
            {
                this.UsesSaveData = true;
            }

            if ((flags & 0x0100) > 0)
            {
                this.ApplicatonDataIsRecorded = true;
            }

            if ((flags & 0x0400) > 0)
            {
                this.SDSaveDataBackupsDisabled = true;
            }

            if ((flags & 0x1000) > 0)
            {
                this.IsNew3DSExclusive = true;
            }
        }

        public override string ToString()
        {
            return $"SMDH Application Settings Flags:\n\n" +
                   $"Will this title be visible on the HOME Menu? {this.IsVisible.YesNo()}\n" +
                   $"Will this title (if gamecart title) be automatically launched on system boot? {this.AutoBoot.YesNo()}\n" +
                   $"Does this title utilize 3D? {this.Uses3D.YesNo()}\n" +
                   $"Do you have to accept the Nintendo 3DS EULA (End User License Agreement) to launch this title? {this.RequiresAcceptanceOfEULA.YesNo()}\n" +
                   $"Does this title automatically save it's data when exiting from HOME menu? {this.AutoSaveOnExit.YesNo()}\n" +
                   $"Does this title use an extended banner? {this.UsesExtendedBanner.YesNo()}\n" +
                   $"Is game rating required for this title? {this.RegionGameRatingRequired.YesNo()}\n" +
                   $"Does this title use Save Data? {this.UsesSaveData.YesNo()}\n" +
                   $"Will data be recorded in the Activity Log (and other places) for this title? {this.ApplicatonDataIsRecorded.YesNo()}\n" +
                   $"Are SD Card Save Data backups disabled for this title? {this.SDSaveDataBackupsDisabled.YesNo()}\n" +
                   $"Is this title New Nintendo 3DS exclusive? {this.IsNew3DSExclusive.YesNo()}";
        }
    }
}