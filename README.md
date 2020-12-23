# CTR.NET

CTR (Nintendo 3DS) Library in C#, "ported" from pyctr

My coding isn't the best, but "if it works, it works".

This came to be because I very much dislike python (no hate towards ihaveamac, he's the one who inspired me to do all of this).

I will try to expand this library to support the most 3DS types.

Currently Suppported Types:

- CIA (.cia) General Information, Extacting Contents, Header Information, etc.
- NCSD (.3ds/.cci) General Information, Extracting Contents
- TMD (Title Metadata) (.tmd) General Information, Extensive Header Information, etc.
- Ticket (.tik, ticket.bin) General Information
- SMDH (icon.bin, icon.smdh) General Information, HOME Menu Options, etc.
- NCCH (.cxi/.cfa) General Header Information
- ExeFS (.exefs) Extraction (maybe .code decompression soon)
- RomFS (.romfs) Extraction

Has a Crypto Engine that is able to decrypt CIA contents (NCCH decryption coming soon tm.)
