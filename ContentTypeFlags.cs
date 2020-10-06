using System;
namespace CTR_LIB
{
  class ContentTypeFlags
  {
    public bool Encrypted { get; private set; }
    public bool IsDisc { get; private set; }
    public bool Cfm { get; private set; }
    public bool Optional { get; private set; }
    public bool Shared { get; private set; }
    
    public ContentTypeFlags(bool enc, bool disc, bool cfm, bool opt, bool shared)
    {
      this.Encrypted = enc;
      this.IsDisc = disc;
      this.Cfm = cfm;
      this.Optional = opt;
      this.Shared = shared;
    }
    
    private static bool BoolFromInt(int input) => (input == 0) ? false : true;
    
    public override string ToString() => $"================================\nCONTENT TYPE FLAGS:\n\nENCRYPTED: {this.Encrypted}\nIS DISC: {this.IsDisc}\nCFM: {this.Cfm}\nOPTIONAL: {this.Optional}\nSHARED: {this.Shared}\n================================";
    
    public static ContentTypeFlags GetFlags(int flags)
    {
      
      return new ContentTypeFlags(
        BoolFromInt(flags & 1),
        BoolFromInt(flags & 2),
        BoolFromInt(flags & 4),
        BoolFromInt(flags & 0x4000),
        BoolFromInt(flags & 0x8000)
      );
    }
    public int AsInt() => (((this.Encrypted == true) ? 1 : 0) | (((this.IsDisc == true) ? 1 : 0) << 1) | (((this.Cfm == true) ? 1 : 0) << 2) | (((this.Optional == true) ? 1 : 0) << 14) | (((this.Shared == true) ? 1 : 0) << 15));
  }
}