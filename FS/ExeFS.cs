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
        public int Offset { get; private set; }
        public int Size { get; private set; }
        public byte[] Hash { get; private set; } //SHA-256

        public ExeFSEntry(string name, int offset, int size, byte[] hash)
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

        public List<ExeFSEntry> Entries { get; private set; }

        private bool canRead;
        public bool CanRead
        {
            get
            {
                try
                {
                    if (this.ExeFSStream == null || !this.ExeFSStream.CanRead)
                    {
                        return false;
                    }
                }
                catch (ObjectDisposedException)
                {
                    return false;
                }

                return true;
            }

            set { canRead = value; }
        }

        private bool EntriesLoaded { get; set; }

        public void Dispose()
        {
            this.ExeFSStream.Dispose();
        }
        private Stream ExeFSStream { get; set; }

        public ExeFS(string pathToExefs)
        {
            if (!File.Exists(pathToExefs))
            {
                throw new FileNotFoundException(null, pathToExefs);
            }

            this.ExeFSStream = File.OpenRead(pathToExefs);

            LoadEntries(this.ExeFSStream.SeekReadBytes(0, SeekOrigin.Begin, 0x200));
        }

        public ExeFS(Stream exefsStream)
        {
            this.ExeFSStream = exefsStream;

            LoadEntries(this.ExeFSStream.SeekReadBytes(0, SeekOrigin.Begin, 0x200));
        }

        //used only for NCCH decryption, or to list the entries of the exefs i guess
        public ExeFS(byte[] exefsHeader)
        {
            LoadEntries(exefsHeader);
        }

        private void LoadEntries(byte[] header)
        {
            this.Entries = new List<ExeFSEntry>();

            List<byte[]> hashes = new List<byte[]>();

            for (int i = 0x200; i > 0xC0; i -= 0x20)
            {
                byte[] hash = header.TakeItems(i - 0x20, i);

                if (hash.All(hashByte => hashByte == 0x0))
                {
                    continue;
                }

                hashes.Add(hash);
            }

            byte added = 0;

            for (int i = 0; i < 0xA0; i += 0x10)
            {
                byte[] entry = header.TakeItems(i, i + 0x10);

                if (Enumerable.SequenceEqual(entry, EmptyEntry))
                {
                    continue;
                }

                string name = entry.TakeItems(0x0, 0x8).Decode(Encoding.ASCII).Replace("\x00", "");
                int offset = entry.TakeItems(0x8, 0xC).ToInt32() + 0x200;
                int size = entry.TakeItems(0xC, 0x10).ToInt32();

                if ((offset % 0x200) != 0)
                {
                    throw new InvalidDataException($"ERROR: The given offset for {name} is 0x{offset:X}, which is not a multiple of 0x200");
                }

                byte[] hash = hashes[added];

                this.Entries.Add(new ExeFSEntry(name, offset, size, hash));

                added++;
            }

            this.EntriesLoaded = true;
        }

        public void ExtractExeFS(DirectoryInfo outputDirectory)
        {
            if (!this.CanRead)
            {
                throw new ArgumentException("ERROR: Cannot read from steam - object is disposed or no stream is present");
            }

            foreach (ExeFSEntry entry in this.Entries)
            {
                ExtractEntry(entry, File.Create($"{outputDirectory.FullName}/{entry.Name}"));
            }
        }

        public void ExtractSingleEntry(string name, FileStream outputFile)
        {
            if (!this.CanRead)
            {
                throw new ArgumentException("ERROR: Cannot read from steam - object is disposed or no stream is present");
            }

            ExtractEntry(this.Entries.ToList().Find(ent => ent.Name == name), outputFile);
        }

        public void ExtractSingleEntry(string name, string pathToOutputFile)
        {
            if (!this.CanRead)
            {
                throw new ArgumentException("ERROR: Cannot read from steam - object is disposed or no stream is present");
            }

            ExtractEntry(this.Entries.ToList().Find(ent => ent.Name == name), File.Create(pathToOutputFile));
        }

        private void ExtractEntry(ExeFSEntry entry, Stream output)
        {
            using (output)
            {
                Tools.ExtractStreamPartBuffered(this.ExeFSStream, output, entry.Offset, entry.Size);
            }
        }

        public bool Verify()
        {
            if (this.CanRead && this.EntriesLoaded)
            {
                foreach (ExeFSEntry entry in this.Entries)
                {
                    //since exefs files are usually small, i will just load them into memory to hash them, as doing it buffered is just NO.

                    using (MemoryStream ms = new MemoryStream(entry.Size))
                    {
                        Tools.ExtractStreamPartBuffered(this.ExeFSStream, ms, entry.Offset, entry.Size);

                        byte[] calculatedHash = Tools.HashStreamSHA256(ms);

                        if (!Enumerable.SequenceEqual(entry.Hash, calculatedHash))
                        {
                            return false;
                        }
                    }
                }

                return true;
            }
            else
            {
                throw new ArgumentException("ERROR: Cannot read from steam - object is disposed or no stream is present");
            }
        }

        public static void Create(DirectoryInfo exefsDir, Stream outputStream)
        {
            FileInfo[] files = exefsDir.GetFiles();

            //checks if the input is valid

            if (files.Length == 0 || files.Length > 10)
                throw new ArgumentException("The specified ExeFS directory is empty or there are more than 10 files in it.");

            if (files.Any(file => file.Name.Length > 8))
                throw new ArgumentException("One or more files in the ExeFS directory have names that are longer than 8 characters.");

            if (files.Any(file => file.Length > uint.MaxValue))
                throw new ArgumentException("One or more files in the ExeFS directory are too big to fit inside of an ExeFS.");

            if (outputStream == null || !outputStream.CanWrite || !outputStream.CanSeek)
                throw new ArgumentException("The specified Stream has been disposed or is otherwise not seekable and writable");

            //sort the files
            Array.Sort(files, (f1, f2) => f1.Name.CompareTo(f2.Name));

            //using a memory stream, as that's much easier to work with than raw byte arrays, and it can just be coverted into a byte array at the end
            using (MemoryStream ms = new MemoryStream(0x200))
            {
                byte[][] hashes = new byte[files.Length][];
                int currentOffset = 0;

                for (int i = 0; i < files.Length; i++)
                {
                    ms.Write(Encoding.ASCII.GetBytes(files[i].Name).PadRight(0x00, 8), 0, 8);
                    ms.Write(BitConverter.GetBytes(currentOffset), 0, 4);
                    ms.Write(BitConverter.GetBytes((int)files[i].Length), 0, 4);

                    outputStream.Seek(currentOffset + 0x200, SeekOrigin.Begin);

                    //open current file in readonly mode and copy it to the aligned offset in the exefs
                    files[i].OpenRead().CopyTo(outputStream);

                    currentOffset = Tools.RoundUp(currentOffset + files[i].Length, 0x200);

                    hashes[i] = Tools.HashStreamSHA256(files[i].OpenRead(), true);
                }

                //seek to the begin of the hash region, depending on how many hashes there are

                ms.Seek(0x200 - (0x20 * hashes.Length), SeekOrigin.Begin);

                Array.Reverse(hashes);

                //write each hash until end of header in reverse order, the first file's hash will be the last hash
                for (int i = 0; i < hashes.Length; i++)
                {
                    ms.Write(hashes[i], 0, hashes[i].Length);
                }

                //write header
                byte[] header = ms.ToArray();

                outputStream.Seek(0, SeekOrigin.Begin);
                outputStream.Write(header, 0, header.Length);
                outputStream.SetLength(Tools.RoundUp(outputStream.Length, 0x200));
            }
        }
    }
}