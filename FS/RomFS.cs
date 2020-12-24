using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;
using System.Threading.Tasks;
using System.IO.MemoryMappedFiles;

namespace CTR.NET.FS
{
    public class RomFSRegion
    {
        public long Offset { get; private set; }
        public long Size { get; private set; }

        public RomFSRegion(long offset, long size)
        {
            this.Offset = offset;
            this.Size = size;
        }
    }

    public class RomFSEntry
    {
        public List<RomFSEntry> Contents { get; set; }
        public long Size { get; set; }
        public long Offset { get; set; }
        public string Name { get; set; }
        public string NameMeta { get; set; }
        public RomFSEntryType Type { get; set; }

    }

    public enum RomFSEntryType
    {
        File = 0,
        Directory = 1
    }

    public class RomFS : IDisposable
    {
        private MemoryMappedFile RomFSMemoryMappedFile { get; set; }
        private bool IsCaseInsensitive { get; set; }

        private long LV3Offset { get; set; } = 0;
        private long DataOffset { get; set; } = 0;

        private RomFSRegion LV3DirHash { get; set; }
        private RomFSRegion LV3DirMeta { get; set; }
        private RomFSRegion LV3FileHash { get; set; }
        private RomFSRegion LV3FileMeta { get; set; }
        public long TotalSize { get; private set; }
        public RomFSEntry FileSystem { get; set; }

        public RomFS(string pathToRomfs, bool caseInsensitive)
        {
            if (!File.Exists(pathToRomfs))
                throw new FileNotFoundException(null, pathToRomfs);

            Load(File.Open(pathToRomfs, FileMode.Open, FileAccess.ReadWrite), caseInsensitive);
        }

        public RomFS(FileStream romfsStream, bool caseInsensitive)
        {
            if ((!romfsStream.CanRead) || (!romfsStream.CanSeek))
                throw new ArgumentException("Cannot read or seek specified Stream.");

            Load(romfsStream, caseInsensitive);
        }

        private void Load(FileStream romfsStream, bool caseInsensitive)
        {
            this.RomFSMemoryMappedFile = MemoryMappedFile.CreateFromFile(romfsStream, null, romfsStream.Length, MemoryMappedFileAccess.ReadWrite, HandleInheritability.Inheritable, false );
            this.IsCaseInsensitive = caseInsensitive;
            this.LV3Offset = 0;
            this.TotalSize = 0;

            LV3Offset = 0;

            using (MemoryMappedViewStream romfsViewStream = this.RomFSMemoryMappedFile.CreateViewStream())
            {
                byte[] magic = romfsViewStream.ReadBytes(4);

                if (Enumerable.SequenceEqual(magic, new byte[] { 0x49, 0x56, 0x46, 0x43 })) //"IFVC"
                {
                    byte[] ifvc = magic.MergeWith(romfsViewStream.ReadBytes(0x54));
                    int ifvcMagicNumber = ifvc.TakeItems(0x4, 0x8).ToInt32();

                    if (!(ifvcMagicNumber == 0x10000))
                    {
                        throw new InvalidOperationException($"IFVC Magic Number invalid - expected 0x10000, got 0x{ifvcMagicNumber:X}");
                    }

                    int masterHashSize = ifvc.TakeItems(0x8, 0xC).ToInt32();
                    int lv3BlockSize = ifvc.TakeItems(0x4C, 0x50).ToInt32();
                    int lv3HashBlockSize = 1 << lv3BlockSize;

                    LV3Offset += Tools.RoundUp(masterHashSize + 0x60, lv3HashBlockSize);

                    romfsViewStream.Seek(LV3Offset, SeekOrigin.Begin);
                    magic = romfsViewStream.ReadBytes(4);
                }

                byte[] lv3Header = magic.MergeWith(romfsViewStream.ReadBytes(0x24));

                int lv3HeaderSize = magic.ToInt32();
                int lv3FileDataOffset = lv3Header.TakeItems(0x24, 0x28).ToInt32();

                this.LV3DirHash = new RomFSRegion(lv3Header.TakeItems(0x4, 0x8).ToInt32(), lv3Header.TakeItems(0x8, 0xC).ToInt32());
                this.LV3DirMeta = new RomFSRegion(lv3Header.TakeItems(0xC, 0x10).ToInt32(), lv3Header.TakeItems(0x10, 0x14).ToInt32());
                this.LV3FileHash = new RomFSRegion(lv3Header.TakeItems(0x14, 0x18).ToInt32(), lv3Header.TakeItems(0x18, 0x1C).ToInt32());
                this.LV3FileMeta = new RomFSRegion(lv3Header.TakeItems(0x1C, 0x20).ToInt32(), lv3Header.TakeItems(0x20, 0x24).ToInt32());
                this.DataOffset = LV3Offset + lv3FileDataOffset;

                if (lv3HeaderSize != 0x28)
                {
                    throw new ArgumentException("Length defined in LV3 Header is not 0x20");
                }

                if (this.LV3DirHash.Offset < lv3HeaderSize)
                {
                    throw new ArgumentException("Directory Hash Offset is before the end of the LV3 Header");
                }

                if (this.LV3DirMeta.Offset < this.LV3DirHash.Offset + this.LV3DirHash.Size)
                {
                    throw new ArgumentException("Directory Metadata Offset is before the end of the Directory Hash Region");
                }

                if (this.LV3FileHash.Offset < this.LV3DirMeta.Offset + this.LV3DirMeta.Size)
                {
                    throw new ArgumentException("File Hash Offset is before the end of the Directory Metadata Region");
                }

                if (this.LV3FileMeta.Offset < this.LV3FileHash.Offset + this.LV3FileHash.Size)
                {
                    throw new ArgumentException("File Metadata Offset is before the end of the File Hash Region");
                }

                if (lv3FileDataOffset < this.LV3FileMeta.Offset + this.LV3FileMeta.Size)
                {
                    throw new ArgumentException("File Data Offset is before the end of the File Metadata Region");
                }

                this.FileSystem = new RomFSEntry { Name = "romfs", Type = RomFSEntryType.Directory };
                romfsViewStream.Seek(this.LV3Offset + LV3DirMeta.Offset, SeekOrigin.Begin);

                GetEntries(this.FileSystem, romfsViewStream.ReadBytes(0x18), "/", romfsViewStream);
            }
        }

        public void Dispose()
        {
            this.RomFSMemoryMappedFile.Dispose();
        }

        //shamelessly copied from pyctr
        private void GetEntries(RomFSEntry entry, byte[] raw, string currentPath, MemoryMappedViewStream romfsViewStream)
        {
            UInt32 firstChildDir = raw.TakeItems(0x8, 0xC).ToUInt32();
            UInt32 firstFile = raw.TakeItems(0xC, 0x10).ToUInt32();

            entry.Type = RomFSEntryType.Directory;
            entry.Contents = new List<RomFSEntry>();

            if (firstChildDir != 0xFFFFFFFF)
            {
                romfsViewStream.Seek(this.LV3Offset + LV3DirMeta.Offset + firstChildDir, SeekOrigin.Begin);

                while (true)
                {
                    byte[] childDirMeta = romfsViewStream.ReadBytes(0x18);
                    UInt32 nextSiblingDir = childDirMeta.TakeItems(0x4, 0x8).ToUInt32();

                    string childDirName = romfsViewStream.ReadBytes(childDirMeta.TakeItems(0x14, 0x18).ToUInt32()).Decode(Encoding.Unicode);
                    string childDirNameMeta = (this.IsCaseInsensitive) ? childDirName.ToLower() : childDirName;

                    if (entry.Contents.Any(content => content.NameMeta == childDirNameMeta && content.Type == RomFSEntryType.Directory))
                    {
                        Console.WriteLine($"Directory Name Collision: {currentPath}{childDirName}");
                    }

                    entry.Contents.Add(new RomFSEntry { Name = childDirName, NameMeta = childDirNameMeta });
                    GetEntries(entry.Contents.Find(content => content.Name == childDirName), childDirMeta, $"{currentPath}{childDirName}/", romfsViewStream);

                    if (nextSiblingDir == 0xFFFFFFFF)
                    {
                        break;
                    }

                    romfsViewStream.Seek(this.LV3Offset + LV3DirMeta.Offset + nextSiblingDir, SeekOrigin.Begin);
                }
            }

            if (firstFile != 0xFFFFFFFF)
            {
                romfsViewStream.Seek(LV3Offset + LV3FileMeta.Offset + firstFile, SeekOrigin.Begin);

                while (true)
                {
                    byte[] childFileMeta = romfsViewStream.ReadBytes(0x20);

                    UInt32 nextSiblingFile = childFileMeta.TakeItems(0x4, 0x8).ToUInt32();
                    UInt32 childFileOffset = childFileMeta.TakeItems(0x8, 0x10).ToUInt32();
                    long childFileSize = childFileMeta.TakeItems(0x10, 0x18).ToInt64();

                    string childFileName = romfsViewStream.ReadBytes(childFileMeta.TakeItems(0x1C, 0x20).ToUInt32()).Decode(Encoding.Unicode);
                    string childFileNameMeta = (this.IsCaseInsensitive) ? childFileName.ToLower() : childFileName;

                    if (entry.Contents.Any(content => content.NameMeta == childFileNameMeta && content.Type == RomFSEntryType.File))
                    {
                        Console.WriteLine($"File Name Collision: {currentPath}{childFileName}");
                    }

                    entry.Contents.Add(new RomFSEntry { NameMeta = childFileNameMeta, Name = childFileName, Offset = childFileOffset, Size = childFileSize, Type = RomFSEntryType.File }); ;
                    this.TotalSize += childFileSize;

                    if (nextSiblingFile == 0xFFFFFFFF)
                    {
                        break;
                    }

                    romfsViewStream.Seek(this.LV3Offset + LV3FileMeta.Offset + nextSiblingFile, SeekOrigin.Begin);
                }
            }
        }

        public void ExtractFile(Stream outputStream, string path)
        {
            RomFSEntry entry = GetEntryFromPath(path);

            if (entry.Type == RomFSEntryType.Directory)
            {
                throw new ArgumentException($"Path \"{path}\" points to a directory, not a file. You can use ExtractEntry() for this.");
            }

            using (outputStream)
            {
                Tools.ExtractFileStreamPart(this.RomFSMemoryMappedFile, outputStream, this.DataOffset + entry.Offset, entry.Size);
            }
        }

        public void ExtractEntry(RomFSEntry entry, string outputDirectoryPath)
        {
            Directory.CreateDirectory(outputDirectoryPath);

            Parallel.ForEach(entry.Contents, (ent) => {
                if (ent.Type == RomFSEntryType.Directory)
                {
                    if (ent.Contents == null)
                    {
                        Directory.CreateDirectory($"{outputDirectoryPath}/{ent.Name}");
                        return;
                    }

                    ExtractEntry(ent, $"{outputDirectoryPath}/{ent.Name}");
                }
                else if (ent.Type == RomFSEntryType.File)
                {
                    using (FileStream fs = File.Create($"{outputDirectoryPath}/{ent.Name}"))
                    {
                        Tools.ExtractFileStreamPart(this.RomFSMemoryMappedFile, fs, this.DataOffset + ent.Offset, ent.Size);
                    }
                }
            });
        }

        public RomFSEntry GetEntryFromPath(string path)
        {
            if (path[0] == '/')
            {
                path = path.Remove(0, 1);
            }

            RomFSEntry entry = this.FileSystem;

            foreach (string part in path.Split("/"))
            {
                if (part == "")
                {
                    break;
                }

                try
                {
                    entry = entry.Contents.Find(content => content.Name == part);
                }
                catch (KeyNotFoundException)
                {
                    throw new ArgumentException($"The a part of the path {path} was not found inside this RomFS.");
                }
            }

            return entry;
        }
    }
}