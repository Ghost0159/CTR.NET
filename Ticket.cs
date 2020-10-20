using System.IO;
using System.Text;

namespace CTR.NET
{
    public class TicketInfo
    {
        public Signature SignatureInfo { get; private set; }
        public byte[] SignatureData { get; private set; }
        public string Issuer { get; private set; }
        public byte[] ECCPublicKey { get; private set; }
        public byte Version { get; private set; }
        public byte CaCrlVersion { get; private set; }
        public byte SignerCrlVersion { get; private set; }
        public byte[] Titlekey { get; private set; }
        public byte[] TicketID { get; private set; }
        public byte[] ConsoleID { get; private set; }
        public byte[] TitleID { get; private set; }
        public string TicketTitleVersion { get; private set; }
        public int TicketTitleVersionNumber { get; private set; }
        public byte LicenseType { get; private set; }
        public byte CommonKeyYIndex { get; private set; }
        public byte[] EShopAccountID { get; private set; }
        public byte Audit { get; private set; }
        public byte[] Limits { get; private set; }
        public byte[] ContentIndex { get; private set; }
        public int TicketSize { get; private set; }

        public TicketInfo(byte[] ticket)
        {
            using (MemoryStream ms = new MemoryStream(ticket))
            {
                this.SignatureInfo = Signature.Parse(ms.ReadBytes(0x4));
                this.SignatureData = ms.ReadBytes(this.SignatureInfo.Size);
                ms.ReadBytes(this.SignatureInfo.PaddingSize);
                this.Issuer = ms.ReadBytes(0x40).Decode(Encoding.UTF8);
                this.ECCPublicKey = ms.ReadBytes(0x3C);
                this.Version = (byte)ms.ReadByte();
                this.CaCrlVersion = (byte)ms.ReadByte();
                this.SignerCrlVersion = (byte)ms.ReadByte();
                this.Titlekey = ms.ReadBytes(0x10);
                ms.ReadByte(); //reserved
                this.TicketID = ms.ReadBytes(0x8);
                this.ConsoleID = ms.ReadBytes(0x4);
                this.TitleID = ms.ReadBytes(0x8);
                ms.ReadBytes(0x2); //reserved 2
                this.TicketTitleVersion = Tools.GetVersion(ms.ReadBytes(0x2), out int versionInt);
                this.TicketTitleVersionNumber = versionInt;
                ms.ReadBytes(0x8); //reserved 3
                this.LicenseType = (byte)ms.ReadByte();
                this.CommonKeyYIndex = (byte)ms.ReadByte();
                ms.ReadBytes(0x2A); //reserved 4
                this.EShopAccountID = ms.ReadBytes(0x4);
                ms.ReadByte(); //reserved 5
                this.Audit = (byte)ms.ReadByte();
                ms.ReadBytes(0x42); //reserved 6
                this.Limits = ms.ReadBytes(0x40);
                this.ContentIndex = ms.ReadBytes(ms.Length - ms.Position);
                this.TicketSize = (int)ms.Length;
            }
        }

        public override string ToString()
        {
            return $"Ticket Info:\n\n" +
                $"Ticket Size: {this.TicketSize} (0x{this.TicketSize:X}) bytes\n" +
                $"Signature Name: {this.SignatureInfo.Name}\n" +
                $"Signature Size: {this.SignatureInfo.Size} (0x{this.SignatureInfo.Size:X}) bytes\n" +
                $"Signature Padding Size: {this.SignatureInfo.PaddingSize} (0x{this.SignatureInfo.PaddingSize:X}) bytes\n\n" +
                $"Signature data:\n{this.SignatureData.Hex().PrettifyHex(32)}\n\n" +
                $"Issuer: {this.Issuer.Trim()}\n\n" +
                $"ECC Public Key:\n\n{this.ECCPublicKey.Hex().PrettifyHex(32)}\n" +
                $"Version: {this.Version} (0x{this.Version:X})\n" +
                $"CA CRL Version: {this.CaCrlVersion} (0x{this.CaCrlVersion:X})\n" +
                $"Signer CRL Version: {this.SignerCrlVersion} (0x{this.SignerCrlVersion:X})\n" +
                $"Title Key: {this.Titlekey.Hex()}\n" +
                $"Ticket ID: {this.TicketID.Hex()}\n" +
                $"Console ID: {this.ConsoleID.Hex()}\n" +
                $"Title ID: {this.TitleID.Hex()}\n" +
                $"Title Version: {this.TicketTitleVersion} ({this.TicketTitleVersionNumber})\n" +
                $"License Type: {this.LicenseType} (0x{this.LicenseType:X})\n" +
                $"Common KeyY Decryption Keyslot Index: 0x{this.CommonKeyYIndex:X}\n" +
                $"eShop Account ID: {this.EShopAccountID.Hex()}\n" +
                $"Audit: {this.Audit} (0x{this.Audit:X})\n\n" +
                $"Limits:\n\n{this.Limits.Hex().PrettifyHex(32)}\n" +
                $"Content Index:\n\n{this.ContentIndex.Hex().PrettifyHex(32)}";
        }
    }
}