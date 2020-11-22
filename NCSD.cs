using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CTR.NET
{
    public class NCSD : IDisposable
    {
        public NCSDInfo Info { get; private set; }
        private Stream NCSDStream { get; set; }

        public NCSD(Stream ncsdStream)
        {
            this.NCSDStream = ncsdStream;
            this.Info = new NCSDInfo(ncsdStream);
        }

        public void ExtractPartition(FileStream outputFile, NCSDPartitions partition)
        {
            if (!this.Info.Partitions.Any(part => part.ID == partition))
            {
                throw new ArgumentException($"Specified partition ID {Enum.GetName(typeof(NCSDPartitions), partition)} {(int)partition} was not found inside this NCSD.");
            }

            Extract(this.Info.Partitions.Find(part => part.ID == partition), outputFile);
        }

        public void ExtractPartition(string outputFilePath, NCSDPartitions partition)
        {
            if (!this.Info.Partitions.Any(part => part.ID == partition))
            {
                throw new ArgumentException($"Specified partition ID {Enum.GetName(typeof(NCSDPartitions), partition)} {(int)partition} was not found inside this NCSD.");
            }

            Extract(this.Info.Partitions.Find(part => part.ID == partition), File.Create(outputFilePath));
        }

        public void ExtractAllPartitions(DirectoryInfo outputDirectory)
        {
            foreach (NCSDPartition partition in this.Info.Partitions)
            {
                Extract(partition, File.Create($"{outputDirectory.FullName}/content_{Enum.GetName(typeof(NCSDPartitions), partition)}.ncch"));
            }
        }

        private void Extract(NCSDPartition section, Stream outputStream)
        {
            Tools.ExtractFromStreamBuffered(this.NCSDStream, outputStream, section.Offset, section.Offset + section.Size);
        }

        public void Dispose()
        {
            this.NCSDStream.Dispose();
        }
    }
    public class NCSDInfo
    {
        public static int NCSDMediaUnit = 0x200;
        public long ImageSize { get; private set; }
        public List<NCSDPartition> Partitions { get; private set; }
        public byte[] MediaId { get; private set; }

        public NCSDInfo(Stream ncsdStream)
        {
            ncsdStream.Seek(0x100, SeekOrigin.Begin);
            byte[] header = ncsdStream.ReadBytes(0x100);

            if (header.TakeItems(0x0, 0x4).Hex() != "4E435344") //if header at 0x0-0x4 isn't 'NCSD'
            {
                throw new ArgumentException("NCSD magic not found in header of specified file.");
            }

            this.MediaId = header.TakeItems(0x8, 0x10).FReverse();

            if (this.MediaId == new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 })
            {
                throw new ArgumentException("Specified file is a NAND, and not an NCSD Image.");
            }

            this.ImageSize = header.TakeItems(0x4, 0x8).FReverse().ToInt64() * NCSDMediaUnit;

            this.Partitions = new List<NCSDPartition>();

            byte[] partRaw = header.TakeItems(0x20, 0x60);

            int[] range = new int[] { 0, 8, 16, 24, 32, 40, 48, 56 };

            for (int i = 0; i < range.Length; i++)
            {
                byte[] partInfo = partRaw.TakeItems(range[i], range[i] + 8);
                long partOffset = (long)partInfo.TakeItems(0x0, 0x4).ToInt32() * (long)NCSDMediaUnit;
                long partSize = (long)partInfo.TakeItems(0x4, 0x8).ToInt32() * (long)NCSDMediaUnit;

                if (partOffset > 0)
                {
                    int partitionId = i;
                    this.Partitions.Add(new NCSDPartition(partOffset, partSize, i));
                }
            }
        }

        public override string ToString()
        {
            string output =
                $"NCSD IMAGE\n" +
                $"Media ID: {this.MediaId}\n" +
                $"Image Size: {this.ImageSize} (0x{this.ImageSize:X}) bytes\n\n";

            foreach (NCSDPartition s in this.Partitions)
            {
                output += ($"{s}\n\n");
            }

            return output;
        }
    }

    public class NCSDPartition
    {
        public long Offset { get; private set; }
        public long Size { get; private set; }
        public NCSDPartitions ID { get; set; }

        public NCSDPartition(long offset, long size, int id)
        {
            this.Offset = offset;
            this.Size = size;
            this.ID = (NCSDPartitions)id;
        }

        public override string ToString()
        {
            return
                $"NCSD SECTION \n" +
                $"ID: {(int)this.ID} ({Enum.GetName(typeof(NCSDPartitions), this.ID)})\n" +
                $"Offset: 0x{this.Offset:X}\n" +
                $"Size: {this.Size} (0x{this.Size:X}) bytes";
        }
    }

    public enum NCSDPartitions
    {
        Application = 0,
        Manual = 1,
        DownloadPlayChild = 2,
        Unknown3 = 3,
        Unknown4 = 4,
        Unknown5 = 5,
        UpdateNew3DS = 6,
        UpdateOld3DS = 7
    }
}