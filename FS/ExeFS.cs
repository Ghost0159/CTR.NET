using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Linq;

namespace CTR.NET.FS
{
    public class ExeFSEntry
    {
        public string Name { get; private set; }
        public long Offset { get; private set; }
        public long Size { get; private set; }
        public byte[] Hash { get; private set; }

        public ExeFSEntry(string name, long offset, long size, byte[] hash)
        {
            this.Name = name;
            this.Offset = offset;
            this.Size = size;
            this.Hash = hash;
        }
    }

    public class ExeFS : IDisposable
    {
        public static readonly int ExeFSEntrySize = 0x10;
        public static readonly int ExeFSEntryCount = 10;
        public static readonly byte[] EmptyEntry = new byte[16] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
        public static readonly int ExeFSHeaderSize = 0x200;


        public Dictionary<string, ExeFSEntry> Entries { get; private set; }

        public void Dispose()
        {
            this.ExeFSStream.Dispose();
        }
        private Stream ExeFSStream { get; set; }

        public ExeFS(string pathToExefs)
        {
            this.ExeFSStream = File.OpenRead(pathToExefs);
            Read();
        }

        public ExeFS(Stream exefsStream)
        {
            this.ExeFSStream = exefsStream;
            Read();
        }

        private void Read()
        {
            this.Entries = new Dictionary<string, ExeFSEntry>();

            byte[] header = this.ExeFSStream.ReadBytes(ExeFSHeaderSize);

            Tuple<List<int>, List<int>> entriesAndHashes = Tuple.Create(new List<int>() { 0, 16, 32, 48, 64, 80, 96, 112, 128, 144 }, new List<int>() { 480, 448, 416, 384, 352, 320, 288, 256, 224, 192 });

            for (int i = 0; i < 10; i++)
            {
                byte[] rawEntry = header.TakeItems(entriesAndHashes.Item1[i], entriesAndHashes.Item1[i] + 0x10);
                byte[] rawHash = header.TakeItems(entriesAndHashes.Item2[i], entriesAndHashes.Item2[i] + 0x20);

                if (Enumerable.SequenceEqual(rawEntry, EmptyEntry))
                {
                    continue;
                }

                string name = rawEntry.TakeItems(0x0, 0x8).Decode(Encoding.ASCII).Replace("\0", "");

                this.Entries[name] = new ExeFSEntry(name, rawEntry.TakeItems(0x8, 0xC).IntLE() + 0x200, rawEntry.TakeItems(0xC, 0x10).IntLE(), rawHash);

                if ((this.Entries[name].Offset % 0x200) > 0)
                {
                    this.ExeFSStream.Close();
                    throw new ArgumentException("ExeFS Entry Offset not a multiple of 0x200");
                }
            }
        }

        public void ExtractExeFS(DirectoryInfo outputDirectory)
        {
            foreach (KeyValuePair<string, ExeFSEntry> entry in this.Entries)
            {
                ExtractEntry(entry.Value, File.Create($"{outputDirectory.FullName}/{entry.Value.Name}"));
            }
        }

        public void ExtractSingleEntry(string name, FileStream outputFile)
        {
            ExtractEntry(this.Entries.ToList().Find(ent => ent.Key == name).Value, outputFile);
        }

        public void ExtractSingleEntry(string name, string pathToOutputFile)
        {
            ExtractEntry(this.Entries.ToList().Find(ent => ent.Key == name).Value, File.Create(pathToOutputFile));
        }

        private void ExtractEntry(ExeFSEntry entry, Stream output)
        {
            using (output)
            {
                this.ExeFSStream.Seek(entry.Offset, SeekOrigin.Begin);
                output.Write(ExeFSStream.ReadBytes(entry.Size));
            }
        }
    }
}