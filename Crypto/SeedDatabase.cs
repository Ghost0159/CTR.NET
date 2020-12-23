using System;
using System.Collections.Generic;
using System.IO;

namespace CTR.NET.Crypto
{
    public class SeedDatabase
    {
        public List<SeedEntry> Seeds { get; private set; }

        public SeedDatabase(string pathToSeedDatabase)
        {
            if (!File.Exists(pathToSeedDatabase))
            {
                throw new FileNotFoundException($"File at {pathToSeedDatabase} was not found.");
            }

            this.Seeds = new List<SeedEntry>();

            ReadSeeds(File.OpenRead(pathToSeedDatabase));
        }

        public SeedDatabase(Stream seedDatabaseStream)
        {
            ReadSeeds(seedDatabaseStream);
        }

        private void ReadSeeds(Stream seedDatabaseStream)
        {
            using (seedDatabaseStream)
            {
                short titleAmount = seedDatabaseStream.ReadBytes(2).ToInt16();

                this.Seeds = new List<SeedEntry>(titleAmount);

                if (seedDatabaseStream.Length != 0x10 + titleAmount * 0x20)
                {
                    throw new ArgumentException($"Expected length {0x10 + titleAmount * 0x20}, got {seedDatabaseStream.Length} instead.");
                }

                //seeking to start of seed area
                seedDatabaseStream.Seek(0x10, SeekOrigin.Begin);

                for (long i = seedDatabaseStream.Position; i < seedDatabaseStream.Position + titleAmount * 0x20; i += 0x20)
                {
                    this.Seeds.Add(new SeedEntry(seedDatabaseStream.ReadBytes(0x8), seedDatabaseStream.ReadBytes(0x10)));

                    seedDatabaseStream.ReadBytes(0x8);
                }
            }
        }
    }

    public class SeedEntry
    {
        public byte[] TitleID { get; private set; }
        public byte[] Seed { get; private set; }

        public SeedEntry(byte[] titleId, byte[] seed)
        {
            this.TitleID = titleId;
            this.Seed = seed;
        }
    }
}