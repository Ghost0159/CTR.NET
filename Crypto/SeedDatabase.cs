using System;
using System.Collections.Generic;
using System.IO;

namespace CTR.NET.Crypto
{
    public class SeedDatabase
    {
        public Dictionary<long, byte[]> Seeds { get; private set; }

        public SeedDatabase(string pathToSeedDatabase)
        {
            if (!File.Exists(pathToSeedDatabase))
            {
                throw new FileNotFoundException($"File at {pathToSeedDatabase} was not found.");
            }
            
            this.Seeds = new Dictionary<long, byte[]>();

            ReadSeeds(File.OpenRead(pathToSeedDatabase));
        }

        public SeedDatabase(Stream seedDatabaseStream)
        {
            this.Seeds = new Dictionary<long, byte[]>();

            ReadSeeds(seedDatabaseStream);
        }

        private void ReadSeeds(Stream seedDatabaseStream)
        {
            using (seedDatabaseStream)
            {
                short titleAmount = seedDatabaseStream.ReadBytes(2).ToInt16();

                if (seedDatabaseStream.Length != 0x10 + titleAmount * 0x20)
                {
                    throw new ArgumentException($"Expected file size {0x10 + titleAmount * 0x20}, got {seedDatabaseStream.Length}");
                }

                //seeking to start of seed area
                seedDatabaseStream.Seek(0x10, SeekOrigin.Begin);

                for (long i = seedDatabaseStream.Position; i < seedDatabaseStream.Position + titleAmount * 0x20; i += 0x20)
                {
                    long tid = seedDatabaseStream.ReadBytes(0x8).ToInt64();
                    byte[] seed = seedDatabaseStream.ReadBytes(0x10);

                    this.Seeds[tid] = seed;

                    seedDatabaseStream.ReadBytes(0x8);
                }
            }
        }
    }
}