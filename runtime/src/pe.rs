//! Minimal PE parser. Just the fields the heuristic engine needs:
//! section list (name + Characteristics) and the imported function
//! names per imported DLL.
//!
//! Hand-written instead of pulling in `goblin` so a security-tool
//! reader can audit every byte we read from the server-supplied
//! buffer without crawling a 50k-line dependency.

#[derive(Debug)]
pub struct ParsedPe<'a> {
    pub raw_bytes: &'a [u8],
    pub size_of_image: u32,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
}

#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub characteristics: u32,
}

#[derive(Debug)]
pub struct Import {
    pub dll: String,
    pub functions: Vec<String>,
}

pub fn parse(buf: &[u8]) -> Result<ParsedPe<'_>, &'static str> {
    if buf.len() < 0x40 {
        return Err("buffer too small for DOS header");
    }
    if &buf[..2] != b"MZ" {
        return Err("missing MZ signature");
    }
    let pe_offset = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap()) as usize;
    if pe_offset + 0x18 > buf.len() {
        return Err("PE header out of range");
    }
    if &buf[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err("missing PE signature");
    }
    let coff = pe_offset + 4;
    let machine = u16::from_le_bytes(buf[coff..coff + 2].try_into().unwrap());
    if machine != 0x014C {
        return Err("not an i386 PE");
    }
    let num_sections = u16::from_le_bytes(buf[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let opt_header_size =
        u16::from_le_bytes(buf[coff + 16..coff + 18].try_into().unwrap()) as usize;

    let opt = coff + 20;
    if opt + opt_header_size > buf.len() {
        return Err("optional header out of range");
    }
    if u16::from_le_bytes(buf[opt..opt + 2].try_into().unwrap()) != 0x010B {
        return Err("not a PE32 (need 0x010B in opt magic)");
    }
    let size_of_image = u32::from_le_bytes(buf[opt + 56..opt + 60].try_into().unwrap());
    // Data Directories start at offset 96 in PE32 optional header.
    // Index 1 is the import-table directory.
    let dir_base = opt + 96;
    let import_dir_rva =
        u32::from_le_bytes(buf[dir_base + 8..dir_base + 12].try_into().unwrap());
    let _import_dir_size =
        u32::from_le_bytes(buf[dir_base + 12..dir_base + 16].try_into().unwrap());

    let sections_start = opt + opt_header_size;
    if sections_start + num_sections * 40 > buf.len() {
        return Err("section table out of range");
    }
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = sections_start + i * 40;
        let name_bytes = &buf[off..off + 8];
        let name = std::str::from_utf8(name_bytes)
            .unwrap_or("?")
            .trim_end_matches('\0')
            .to_string();
        sections.push(Section {
            name,
            virtual_size: u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap()),
            virtual_address: u32::from_le_bytes(buf[off + 12..off + 16].try_into().unwrap()),
            raw_size: u32::from_le_bytes(buf[off + 16..off + 20].try_into().unwrap()),
            raw_pointer: u32::from_le_bytes(buf[off + 20..off + 24].try_into().unwrap()),
            characteristics: u32::from_le_bytes(buf[off + 36..off + 40].try_into().unwrap()),
        });
    }

    let imports = if import_dir_rva != 0 {
        parse_imports(buf, import_dir_rva, &sections)?
    } else {
        Vec::new()
    };

    Ok(ParsedPe {
        raw_bytes: buf,
        size_of_image,
        sections,
        imports,
    })
}

/// `IMAGE_IMPORT_DESCRIPTOR` walk. Each descriptor is 20 bytes:
/// OriginalFirstThunk (RVA), TimeDateStamp, ForwarderChain, Name,
/// FirstThunk. Terminator is an all-zero descriptor.
fn parse_imports(
    buf: &[u8],
    dir_rva: u32,
    sections: &[Section],
) -> Result<Vec<Import>, &'static str> {
    let mut out = Vec::new();
    let mut cursor_rva = dir_rva;
    loop {
        let desc_off = match rva_to_offset(cursor_rva, sections) {
            Some(o) => o,
            None => return Ok(out), // descriptor outside any section -> stop
        };
        if desc_off + 20 > buf.len() {
            return Ok(out);
        }
        let oft = u32::from_le_bytes(buf[desc_off..desc_off + 4].try_into().unwrap());
        let name_rva = u32::from_le_bytes(buf[desc_off + 12..desc_off + 16].try_into().unwrap());
        let ft = u32::from_le_bytes(buf[desc_off + 16..desc_off + 20].try_into().unwrap());
        if oft == 0 && name_rva == 0 && ft == 0 {
            return Ok(out);
        }
        let dll = read_cstring_at_rva(buf, name_rva, sections)
            .unwrap_or_else(|| "<bad>".into());
        let thunk_rva = if oft != 0 { oft } else { ft };
        let mut funcs = Vec::new();
        if let Some(thunk_off) = rva_to_offset(thunk_rva, sections) {
            let mut t = thunk_off;
            while t + 4 <= buf.len() {
                let entry = u32::from_le_bytes(buf[t..t + 4].try_into().unwrap());
                if entry == 0 {
                    break;
                }
                if entry & 0x8000_0000 != 0 {
                    funcs.push(format!("ord:{}", entry & 0xFFFF));
                } else if let Some(name_off) = rva_to_offset(entry + 2, sections) {
                    if name_off < buf.len() {
                        funcs.push(read_cstring(buf, name_off));
                    }
                }
                t += 4;
                if funcs.len() > 1000 {
                    break; // sanity cap
                }
            }
        }
        out.push(Import { dll, functions: funcs });
        cursor_rva += 20;
        if out.len() > 64 {
            break; // sanity cap on DLL count
        }
    }
    Ok(out)
}

fn rva_to_offset(rva: u32, sections: &[Section]) -> Option<usize> {
    for s in sections {
        if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size.max(s.raw_size) {
            return Some((s.raw_pointer + (rva - s.virtual_address)) as usize);
        }
    }
    None
}

fn read_cstring(buf: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < buf.len() && buf[end] != 0 && end - offset < 256 {
        end += 1;
    }
    std::str::from_utf8(&buf[offset..end])
        .unwrap_or("<utf8>")
        .to_string()
}

fn read_cstring_at_rva(buf: &[u8], rva: u32, sections: &[Section]) -> Option<String> {
    rva_to_offset(rva, sections).map(|off| read_cstring(buf, off))
}

/// Best-effort SizeOfImage read for the dump-to-disk path. Doesn't
/// validate the full PE -- just chases enough headers to find the
/// optional-header field. Returns None for clearly-malformed input
/// so the caller can fall back to a fixed cap.
pub fn guess_size(buf: &[u8]) -> Option<usize> {
    if buf.len() < 0x40 || &buf[..2] != b"MZ" {
        return None;
    }
    let pe_offset = u32::from_le_bytes(buf[0x3C..0x40].try_into().ok()?) as usize;
    if pe_offset + 0x60 > buf.len() {
        return None;
    }
    if &buf[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }
    let opt = pe_offset + 4 + 20;
    if opt + 60 > buf.len() {
        return None;
    }
    if u16::from_le_bytes(buf[opt..opt + 2].try_into().ok()?) != 0x010B {
        return None;
    }
    Some(u32::from_le_bytes(buf[opt + 56..opt + 60].try_into().ok()?) as usize)
}
