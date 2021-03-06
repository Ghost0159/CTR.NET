using System;
using System.Collections.Generic;
using System.Text;

namespace CTR.NET
{
    public enum SMDHLanguage
    {
        Japanese = 0,
        English = 1,
        French = 2,
        German = 3,
        Italian = 4,
        Spanish = 5,
        Simplified_Chinese = 6,
        Korean = 7,
        Dutch = 8,
        Portuguese = 9,
        Russian = 10,
        Traditional_Chinese = 11
    }
    public class SMDHInfo
    {

        public string Magic { get; private set; }
        public string Version { get; private set; }
        public short VersionNumber { get; private set; }
        public List<SMDHTitleNameStructure> TitleNames { get; private set; }
        public SMDHApplicationSettings ApplicationSettings { get; private set; }

        public SMDHInfo(byte[] smdhData)
        {
            this.Magic = smdhData.TakeItems(0x0, 0x4).Decode(Encoding.UTF8);
            this.Version = Tools.GetVersion(smdhData.TakeItems(0x4, 0x6), out short versionInt);
            this.VersionNumber = versionInt;

            byte[] nameStructuresRaw = smdhData.TakeItems(0x8, 0x2000);

            byte index = 0;

            this.TitleNames = new List<SMDHTitleNameStructure>();

            for (int i = 0; i < nameStructuresRaw.Length - 0xA00; i += 0x200)
            {
                this.TitleNames.Add(new SMDHTitleNameStructure(nameStructuresRaw.TakeItems(i, i + 0x200), (SMDHLanguage)Enum.ToObject(typeof(SMDHLanguage), index)));
                index++;
            }

            this.ApplicationSettings = new SMDHApplicationSettings(smdhData.TakeItems(0x2008, 0x2038));
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
        public SMDHLanguage Language { get; set; }

        public SMDHTitleNameStructure(byte[] titleNameStructureRaw, SMDHLanguage language)
        {
            this.LongTitle = titleNameStructureRaw.TakeItems(0x0, 0x80).Decode(Encoding.Unicode);
            this.ShortTitle = titleNameStructureRaw.TakeItems(0x80, 0x180).Decode(Encoding.Unicode);
            this.Publisher = titleNameStructureRaw.TakeItems(0x180, 0x200).Decode(Encoding.Unicode);
            this.Language = language;
        }

        public override string ToString() => $"-------------------------------\n\nSMDH Title Name Structure:\n\nLanguage: {this.Language}\n\nLong Title: {this.LongTitle}\n\nShort Title: {this.ShortTitle}\n\nPublisher: {this.Publisher}";
    }

    public class SMDHApplicationSettings
    {
        public List<GameRating> GameRatings { get; private set; } = new List<GameRating>() { };
        public string RegionLockout { get; private set; }
        public int MatchmakerID { get; private set; }
        public int MatchmakerBitID { get; private set; }
        public SMDHFlags Flags { get; private set; }
        public string EulaVersion { get; private set; }
        public short EulaVersionNumber { get; private set; }
        public float OptionalAnimationDefaultFrame { get; private set; }
        public int CEC_StreetPassID { get; private set; }

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

            int regionLockoutRaw = applicationSettings.TakeItems(16, 20).ToInt32();

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

            this.MatchmakerID = applicationSettings.TakeItems(20, 24).ToInt32();
            this.MatchmakerBitID = applicationSettings.TakeItems(24, 32).ToInt32();
            this.Flags = new SMDHFlags(applicationSettings.TakeItems(32, 36).ToInt32());
            this.EulaVersion = Tools.GetVersion(applicationSettings.TakeItems(36, 38), out short versionNumber);
            this.EulaVersionNumber = versionNumber;
            this.OptionalAnimationDefaultFrame = applicationSettings.TakeItems(40, 44).ToFloat();
            this.CEC_StreetPassID = applicationSettings.TakeItems(44, 48).ToInt32();
        }

        public override string ToString()
        {
            string output = "Age Ratings:\n\nRegion Lockout Region: {this.RegionLockout}\nOnline Play Matchmaker ID: {this.MatchmakerID:X8}\nOnline Play Matchmaker Bit ID: {this.MatchmakerBitID:X8}\nEULA (End User License Agreement) Version: {this.EulaVersion}\nOptional Animation Default Frame: {this.OptionalAnimationDefaultFrame}\nCEC (StreetPass) ID: {this.CEC_StreetPassID:X8}\n\n{this.Flags}\n\n";

            foreach (GameRating gr in this.GameRatings)
            {
                output += $"{gr}\n\n";
            }

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