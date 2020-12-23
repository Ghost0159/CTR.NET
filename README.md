# CTR.NET

CTR (Nintendo 3DS) Library in C#, "ported" from pyctr

My coding isn't the best, but "if it works, it works".

This came to be because I very much dislike python (no hate towards ihaveamac, him and his tools are the ones who inspired me to do all of this).

I will try to expand this library to support the most 3DS types.

Features:

- CIA (.cia) Extacting Contents, Header Information
- NCSD (.3ds/.cci) Extracting Contents, Header Information
- TMD (Title Metadata) (.tmd) General Information, Extensive Header Information
- Ticket (.tik, ticket.bin) General Information
- SMDH (icon.bin, icon.smdh) General Information, HOME Menu Options, etc.
- NCCH (.cxi/.cfa) Decryption and Extraction of contents, Header Information
- ExeFS (.exefs) Extraction and Creation (maybe .code decompression soon)
- RomFS (.romfs) Extraction
- Crypto Engine that is able to decrypt CIA and NCCH containers
