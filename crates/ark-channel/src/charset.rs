//! Legacy charset decoding per the WHATWG Encoding Standard (decoders only; ark always
//! sends UTF-8). Every encoding and label of the standard: UTF-8, the single-byte family
//! (windows-125x, ISO-8859-x, KOI8-R/U, IBM866, macintosh, x-mac-cyrillic, windows-874),
//! GBK / gb18030 (index-gb18030 + ranges), Big5 (incl. HKSCS, per index-big5), EUC-JP,
//! ISO-2022-JP, Shift_JIS (Windows-31J), EUC-KR (windows-949), UTF-16LE/BE, replacement
//! and x-user-defined. Malformed input yields U+FFFD exactly where the standard's
//! decoders emit an error (bytes it restores are reprocessed). Labels are matched as the
//! standard says (ASCII-case-insensitive, trimmed), then with separators ignored, then
//! against a few Windows code-page aliases that mail uses (cp936, ms950, cp949…).
//! Tables are generated from the WHATWG index files by `tools/gen_charset_tables.py`
//! into `data/` (BSD-3-Clause, see THIRD_PARTY_NOTICES.md), about 180 KB in all.

const R: char = '\u{fffd}';

static BIG5: &[u8] = include_bytes!("../data/big5.bin");
static GB18030: &[u8] = include_bytes!("../data/gb18030.bin");
static GB18030_RANGES: &[u8] = include_bytes!("../data/gb18030-ranges.bin");
static JIS0208: &[u8] = include_bytes!("../data/jis0208.bin");
static JIS0212: &[u8] = include_bytes!("../data/jis0212.bin");
static EUC_KR: &[u8] = include_bytes!("../data/euc-kr.bin");
static SINGLE_BYTE: &[u8] = include_bytes!("../data/single-byte.bin");
static LABELS: &str = include_str!("../data/labels.txt");

/// Single-byte encodings in `single-byte.bin` order; ISO-8859-8-I (last) shares ISO-8859-8's table.
const SINGLE: [&str; 28] = [
    "IBM866", "ISO-8859-2", "ISO-8859-3", "ISO-8859-4", "ISO-8859-5", "ISO-8859-6", "ISO-8859-7", "ISO-8859-8", "ISO-8859-10", "ISO-8859-13", "ISO-8859-14", "ISO-8859-15", "ISO-8859-16", "KOI8-R", "KOI8-U", "macintosh", "windows-874", "windows-1250", "windows-1251",
    "windows-1252", "windows-1253", "windows-1254", "windows-1255", "windows-1256", "windows-1257", "windows-1258", "x-mac-cyrillic", "ISO-8859-8-I",
];

/// Beyond WHATWG: code-page names some mailers put in `charset=`.
const EXTRA: [(&str, &str); 15] = [
    ("cp936", "GBK"), ("ms936", "GBK"), ("windows-936", "GBK"), ("euc-cn", "GBK"), ("cp950", "Big5"), ("ms950", "Big5"), ("windows-950", "Big5"), ("cp949", "EUC-KR"), ("ms949", "EUC-KR"), ("uhc", "EUC-KR"), ("cp932", "Shift_JIS"), ("windows-932", "Shift_JIS"), ("ujis", "EUC-JP"), ("cp874", "windows-874"), ("latin9", "ISO-8859-15"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    /// Index into the single-byte list.
    Single(u8),
    Gbk,
    Gb18030,
    Big5,
    EucJp,
    Iso2022Jp,
    ShiftJis,
    EucKr,
    Replacement,
    Utf16Be,
    Utf16Le,
    XUserDefined,
}

impl Encoding {
    /// The WHATWG label lookup: `" Big5-HKSCS "` → Big5, `"x-gbk"` → GBK, `"latin1"` → windows-1252.
    pub fn for_label(label: &str) -> Option<Encoding> {
        let l = label.trim_matches(|c: char| c.is_ascii_whitespace()).to_ascii_lowercase();
        let squash = |s: &str| s.chars().filter(char::is_ascii_alphanumeric).collect::<String>();
        let rows = || LABELS.lines().filter(|r| !r.starts_with('#')).filter_map(|r| r.split_once(' '));
        let s = squash(&l);
        let name = rows()
            .find(|(_, labels)| labels.split(' ').any(|x| x == l))
            .or_else(|| rows().find(|(_, labels)| !s.is_empty() && labels.split(' ').any(|x| squash(x) == s)))
            .map(|r| r.0)
            .or_else(|| EXTRA.iter().find(|e| squash(e.0) == s).map(|e| e.1))?;
        Encoding::by_name(name)
    }

    fn by_name(name: &str) -> Option<Encoding> {
        use Encoding::*;
        Some(match name {
            "UTF-8" => Utf8,
            "GBK" => Gbk,
            "gb18030" => Gb18030,
            "Big5" => Big5,
            "EUC-JP" => EucJp,
            "ISO-2022-JP" => Iso2022Jp,
            "Shift_JIS" => ShiftJis,
            "EUC-KR" => EucKr,
            "replacement" => Replacement,
            "UTF-16BE" => Utf16Be,
            "UTF-16LE" => Utf16Le,
            "x-user-defined" => XUserDefined,
            n => Single(SINGLE.iter().position(|s| *s == n)? as u8),
        })
    }

    /// The standard's canonical name (`Shift_JIS`, `windows-1252`, `gb18030`…).
    pub fn name(self) -> &'static str {
        use Encoding::*;
        match self {
            Utf8 => "UTF-8",
            Single(i) => SINGLE[i as usize],
            Gbk => "GBK",
            Gb18030 => "gb18030",
            Big5 => "Big5",
            EucJp => "EUC-JP",
            Iso2022Jp => "ISO-2022-JP",
            ShiftJis => "Shift_JIS",
            EucKr => "EUC-KR",
            Replacement => "replacement",
            Utf16Be => "UTF-16BE",
            Utf16Le => "UTF-16LE",
            XUserDefined => "x-user-defined",
        }
    }

    /// Decode `b` as this encoding, ignoring any BOM ("decode without BOM").
    pub fn decode_without_bom(self, b: &[u8]) -> String {
        let mut o = String::with_capacity(b.len() + b.len() / 2);
        match self {
            Encoding::Utf8 => return String::from_utf8_lossy(b).into_owned(),
            Encoding::Single(i) => {
                let t = &SINGLE_BYTE[if i == 27 { 7 } else { i as usize } * 256..][..256];
                o.extend(b.iter().map(|&c| if c < 0x80 { c as char } else { ch(Some(u16_at(t, c as usize - 0x80)).filter(|&v| v != 0)) }));
            }
            Encoding::Gbk | Encoding::Gb18030 => gb18030(b, &mut o),
            Encoding::Big5 => dbcs(b, &mut o, lead_81_fe, big5),
            Encoding::EucJp => euc_jp(b, &mut o),
            Encoding::Iso2022Jp => iso_2022_jp(b, &mut o),
            Encoding::ShiftJis => dbcs(b, &mut o, sjis_single, sjis),
            Encoding::EucKr => dbcs(b, &mut o, lead_81_fe, euc_kr),
            Encoding::Replacement if !b.is_empty() => o.push(R),
            Encoding::Replacement => {}
            Encoding::Utf16Be | Encoding::Utf16Le => utf16(b, self == Encoding::Utf16Be, &mut o),
            Encoding::XUserDefined => o.extend(b.iter().map(|&c| if c < 0x80 { c as char } else { ch(Some(0xf780 + c as u32 - 0x80)) })),
        }
        o
    }

    /// WHATWG "decode": a UTF-8 / UTF-16 BOM overrides the encoding and is dropped.
    pub fn decode(self, b: &[u8]) -> String {
        match b {
            [0xef, 0xbb, 0xbf, r @ ..] => Encoding::Utf8.decode_without_bom(r),
            [0xfe, 0xff, r @ ..] => Encoding::Utf16Be.decode_without_bom(r),
            [0xff, 0xfe, r @ ..] => Encoding::Utf16Le.decode_without_bom(r),
            _ => self.decode_without_bom(b),
        }
    }
}

/// Decode with a charset label; None when the label is unknown.
pub fn decode_label(b: &[u8], label: &str) -> Option<String> {
    Some(Encoding::for_label(label)?.decode(b))
}

fn ch(cp: Option<u32>) -> char {
    cp.and_then(char::from_u32).unwrap_or(R)
}

fn u16_at(t: &[u8], i: usize) -> u32 {
    u16::from_le_bytes([t[2 * i], t[2 * i + 1]]) as u32
}

/// `(first pointer, count, values…)` tables; 0 = no mapping. Returns (code point low 16 bits, slot).
fn index(t: &[u8], p: usize) -> Option<(u32, usize)> {
    let i = p.checked_sub(u16_at(t, 0) as usize).filter(|&i| i < u16_at(t, 1) as usize)?;
    Some((u16_at(t, 2 + i), i)).filter(|v| v.0 != 0)
}

fn bmp(t: &[u8], p: usize) -> Option<u32> {
    index(t, p).map(|v| v.0)
}

fn in_range(c: u8, lo: u8, hi: u8) -> bool {
    (lo..=hi).contains(&c)
}

/// The two-byte shape shared by Big5, Shift_JIS and EUC-KR: ASCII passes; `single` maps
/// other bytes (Some(None) = a leading byte); `pair` pushes a leading + trailing pair or
/// refuses it, in which case an ASCII trailing byte is reprocessed.
fn dbcs(b: &[u8], o: &mut String, single: fn(u8) -> Option<Option<u32>>, pair: fn(u8, u8, &mut String) -> bool) {
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        i += 1;
        match if c < 0x80 { Some(Some(c as u32)) } else { single(c) } {
            Some(Some(cp)) => o.push(ch(Some(cp))),
            None => o.push(R),
            Some(None) => {
                let Some(&t) = b.get(i) else {
                    o.push(R);
                    break;
                };
                i += 1;
                if !pair(c, t, o) {
                    o.push(R);
                    if t < 0x80 {
                        i -= 1;
                    }
                }
            }
        }
    }
}

fn lead_81_fe(c: u8) -> Option<Option<u32>> {
    in_range(c, 0x81, 0xfe).then_some(None)
}

fn big5(l: u8, t: u8, o: &mut String) -> bool {
    if !in_range(t, 0x40, 0x7e) && !in_range(t, 0xa1, 0xfe) {
        return false;
    }
    let p = (l as usize - 0x81) * 157 + t as usize - if t < 0x7f { 0x40 } else { 0x62 };
    let s = match p {
        1133 => "\u{ca}\u{304}",
        1135 => "\u{ca}\u{30c}",
        1164 => "\u{ea}\u{304}",
        1166 => "\u{ea}\u{30c}",
        _ => {
            let Some((v, i)) = index(BIG5, p) else { return false };
            // The bitmap after the values marks the HKSCS code points in plane 2.
            let n = u16_at(BIG5, 1) as usize;
            o.push(ch(Some(v | if BIG5[4 + 2 * n + i / 8] >> (i % 8) & 1 == 1 { 0x20000 } else { 0 })));
            return true;
        }
    };
    o.push_str(s);
    true
}

fn sjis_single(c: u8) -> Option<Option<u32>> {
    match c {
        0x80 => Some(Some(0x80)),
        0xa1..=0xdf => Some(Some(0xff61 - 0xa1 + c as u32)),
        0x81..=0x9f | 0xe0..=0xfc => Some(None),
        _ => None,
    }
}

fn sjis(l: u8, t: u8, o: &mut String) -> bool {
    if !in_range(t, 0x40, 0x7e) && !in_range(t, 0x80, 0xfc) {
        return false;
    }
    let p = (l as usize - if l < 0xa0 { 0x81 } else { 0xc1 }) * 188 + t as usize - if t < 0x7f { 0x40 } else { 0x41 };
    // Windows EUDC → private use.
    let cp = if (8836..=10715).contains(&p) { Some(0xe000 - 8836 + p as u32) } else { bmp(JIS0208, p) };
    cp.map(|c| o.push(ch(Some(c)))).is_some()
}

fn euc_kr(l: u8, t: u8, o: &mut String) -> bool {
    in_range(t, 0x41, 0xfe) && bmp(EUC_KR, (l as usize - 0x81) * 190 + t as usize - 0x41).map(|c| o.push(ch(Some(c)))).is_some()
}

fn euc_jp(b: &[u8], o: &mut String) {
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        i += 1;
        if c < 0x80 {
            o.push(c as char);
            continue;
        }
        if !(c == 0x8e || c == 0x8f || in_range(c, 0xa1, 0xfe)) {
            o.push(R);
            continue;
        }
        let Some(&t) = b.get(i) else {
            o.push(R);
            break;
        };
        i += 1;
        if c == 0x8e && in_range(t, 0xa1, 0xdf) {
            o.push(ch(Some(0xff61 - 0xa1 + t as u32)));
            continue;
        }
        let (table, l, t) = if c == 0x8f && in_range(t, 0xa1, 0xfe) {
            let Some(&t3) = b.get(i) else {
                o.push(R);
                break;
            };
            i += 1;
            (JIS0212, t, t3)
        } else {
            (JIS0208, c, t)
        };
        match (in_range(l, 0xa1, 0xfe) && in_range(t, 0xa1, 0xfe)).then(|| bmp(table, (l as usize - 0xa1) * 94 + t as usize - 0xa1)).flatten() {
            Some(cp) => o.push(ch(Some(cp))),
            None => {
                o.push(R);
                if t < 0x80 {
                    i -= 1;
                }
            }
        }
    }
}

fn gb18030_range(p: u32) -> Option<u32> {
    if (p > 39419 && p < 189000) || p > 1237575 {
        return None;
    }
    if p == 7457 {
        return Some(0xe7c7);
    }
    let at = |i: usize| (u32::from_le_bytes(GB18030_RANGES[i * 8..i * 8 + 4].try_into().unwrap()), u32::from_le_bytes(GB18030_RANGES[i * 8 + 4..i * 8 + 8].try_into().unwrap()));
    // Last range whose pointer ≤ p (the first starts at 0).
    let (mut lo, mut hi) = (0, GB18030_RANGES.len() / 8);
    while hi - lo > 1 {
        let m = (lo + hi) / 2;
        if at(m).0 <= p {
            lo = m;
        } else {
            hi = m;
        }
    }
    let (rp, cp) = at(lo);
    Some(cp + p - rp)
}

fn gb18030(b: &[u8], o: &mut String) {
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        i += 1;
        match c {
            0..=0x7f => o.push(c as char),
            0x80 => o.push('€'),
            0xff => o.push(R),
            _ => {
                // Multi-byte: a truncated sequence is one error at the end.
                let Some(&c2) = b.get(i) else {
                    o.push(R);
                    break;
                };
                i += 1;
                if in_range(c2, 0x30, 0x39) {
                    let Some(&c3) = b.get(i) else {
                        o.push(R);
                        break;
                    };
                    i += 1;
                    if !in_range(c3, 0x81, 0xfe) {
                        o.push(R);
                        i -= 2;
                        continue;
                    }
                    let Some(&c4) = b.get(i) else {
                        o.push(R);
                        break;
                    };
                    i += 1;
                    if !in_range(c4, 0x30, 0x39) {
                        o.push(R);
                        i -= 3;
                        continue;
                    }
                    let p = (c as u32 - 0x81) * 12600 + (c2 as u32 - 0x30) * 1260 + (c3 as u32 - 0x81) * 10 + c4 as u32 - 0x30;
                    o.push(ch(gb18030_range(p)));
                    continue;
                }
                let ok = in_range(c2, 0x40, 0x7e) || in_range(c2, 0x80, 0xfe);
                match ok.then(|| bmp(GB18030, (c as usize - 0x81) * 190 + c2 as usize - if c2 < 0x7f { 0x40 } else { 0x41 })).flatten() {
                    Some(cp) => o.push(ch(Some(cp))),
                    None => {
                        o.push(R);
                        if c2 < 0x80 {
                            i -= 1;
                        }
                    }
                }
            }
        }
    }
}

fn iso_2022_jp(b: &[u8], o: &mut String) {
    #[derive(Clone, Copy, PartialEq)]
    enum S {
        Ascii,
        Roman,
        Kana,
        Lead,
        Trail,
        EscStart,
        Esc,
    }
    let (mut st, mut out_st, mut lead, mut output) = (S::Ascii, S::Ascii, 0u8, false);
    let mut i = 0;
    loop {
        // End of input stays "next" (it is never consumed), like the standard's queue.
        let c = b.get(i).copied();
        if c.is_some() {
            i += 1;
        }
        match (st, c) {
            (S::Ascii | S::Roman | S::Kana | S::Lead, Some(0x1b)) => st = S::EscStart,
            (S::Ascii | S::Roman | S::Kana | S::Lead, None) => return,
            (S::Ascii | S::Roman | S::Kana | S::Lead, Some(c)) => {
                output = false;
                match (st, c) {
                    (S::Roman, 0x5c) => o.push('¥'),
                    (S::Roman, 0x7e) => o.push('‾'),
                    (S::Ascii | S::Roman, ..0x80) if c != 0x0e && c != 0x0f => o.push(c as char),
                    (S::Kana, 0x21..=0x5f) => o.push(ch(Some(0xff61 - 0x21 + c as u32))),
                    (S::Lead, 0x21..=0x7e) => (lead, st) = (c, S::Trail),
                    _ => o.push(R),
                }
            }
            (S::Trail, c) => {
                st = if c == Some(0x1b) { S::EscStart } else { S::Lead };
                let pair = c.filter(|c| in_range(*c, 0x21, 0x7e)).and_then(|c| bmp(JIS0208, (lead as usize - 0x21) * 94 + c as usize - 0x21));
                o.push(ch(pair));
            }
            (S::EscStart, Some(c @ (0x24 | 0x28))) => (lead, st) = (c, S::Esc),
            (S::EscStart, c) => {
                if c.is_some() {
                    i -= 1;
                }
                (output, st) = (false, out_st);
                o.push(R);
            }
            (S::Esc, c) => {
                let l = std::mem::take(&mut lead);
                let next = match (l, c) {
                    (0x28, Some(0x42)) => Some(S::Ascii),
                    (0x28, Some(0x4a)) => Some(S::Roman),
                    (0x28, Some(0x49)) => Some(S::Kana),
                    (0x24, Some(0x40 | 0x42)) => Some(S::Lead),
                    _ => None,
                };
                match next {
                    Some(s) => {
                        (st, out_st) = (s, s);
                        // Two escapes in a row with nothing between them are an error.
                        if std::mem::replace(&mut output, true) {
                            o.push(R);
                        }
                    }
                    None => {
                        i -= if c.is_some() { 2 } else { 1 };
                        (output, st) = (false, out_st);
                        o.push(R);
                    }
                }
            }
        }
    }
}

fn utf16(b: &[u8], be: bool, o: &mut String) {
    let mut u: Vec<u16> = (0..b.len() / 2).map(|i| [b[2 * i], b[2 * i + 1]]).map(|p| if be { u16::from_be_bytes(p) } else { u16::from_le_bytes(p) }).collect();
    let odd = b.len() % 2 == 1;
    // A dangling lead surrogate plus an odd byte are one error at the end.
    if odd && u.last().is_some_and(|c| (0xd800..0xdc00).contains(c)) {
        u.pop();
    }
    o.extend(char::decode_utf16(u).map(|r| r.unwrap_or(R)));
    if odd {
        o.push(R);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(label: &str, b: &[u8]) -> String {
        decode_label(b, label).unwrap_or_else(|| panic!("label {label}"))
    }

    #[test]
    fn labels_follow_whatwg_plus_codepage_aliases() {
        let name = |l: &str| Encoding::for_label(l).map(Encoding::name);
        for (l, n) in [
            ("big5-hkscs", "Big5"), ("CSBIG5", "Big5"), ("x-x-big5", "Big5"), ("ms950", "Big5"), ("cp950", "Big5"), ("x-gbk", "GBK"), ("gb2312", "GBK"), ("GB_2312-80", "GBK"), ("cp936", "GBK"), ("gb18030", "gb18030"), ("x-sjis", "Shift_JIS"), ("windows-31j", "Shift_JIS"), ("ms_kanji", "Shift_JIS"),
            ("cp932", "Shift_JIS"), ("x-euc-jp", "EUC-JP"), ("csiso2022jp", "ISO-2022-JP"), ("ks_c_5601-1987", "EUC-KR"), ("windows-949", "EUC-KR"), ("cp949", "EUC-KR"), ("latin1", "windows-1252"), ("US-ASCII", "windows-1252"), ("iso_8859-1:1987", "windows-1252"), ("latin-1", "windows-1252"),
            ("iso-8859-15", "ISO-8859-15"), ("latin-9", "ISO-8859-15"), ("iso-8859-11", "windows-874"), ("koi8_r", "KOI8-R"), ("koi8-ru", "KOI8-U"), ("iso-8859-8-i", "ISO-8859-8-I"), ("utf-16", "UTF-16LE"), ("unicodefffe", "UTF-16BE"), ("\t utf8 ", "UTF-8"), ("hz-gb-2312", "replacement"), ("iso-2022-kr", "replacement"),
            ("x-user-defined", "x-user-defined"), ("x-mac-ukrainian", "x-mac-cyrillic"),
        ] {
            assert_eq!(name(l), Some(n), "{l}");
        }
        assert_eq!((name("x-unknown"), name(""), name("-")), (None, None, None));
        // Every row of the generated label table maps to an Encoding with that name.
        for row in LABELS.lines().filter(|r| !r.starts_with('#')) {
            let mut w = row.split(' ');
            let n = w.next().unwrap();
            assert!(w.all(|l| name(l) == Some(n)), "{row}");
        }
    }

    #[test]
    fn tables_are_complete() {
        let count = |t: &[u8]| (0..u16_at(t, 1) as usize).filter(|&i| u16_at(t, 2 + i) != 0).count();
        assert_eq!([count(BIG5), count(GB18030), count(JIS0208), count(JIS0212), count(EUC_KR)], [18590, 23940, 7724, 6067, 17048], "entries per WHATWG index");
        assert_eq!((GB18030_RANGES.len() / 8, SINGLE_BYTE.len()), (207, 27 * 256));
    }

    #[test]
    fn chinese() {
        assert_eq!(d("big5", &[0xa4, 0xa4, 0xa4, 0xe5]), "中文");
        // HKSCS: BMP (87 40), plane 2 (FA 40, C8 7A), the four two-code-point pointers, last cell.
        assert_eq!(d("big5-hkscs", &[0x87, 0x40, 0xfa, 0x40, 0xc8, 0x7a, 0xfe, 0xfe]), "䏰𠕇𠃌秔");
        assert_eq!(d("big5", &[0x88, 0x62, 0x88, 0x64, 0x88, 0xa3, 0x88, 0xa5]), "Ê̄Ê̌ê̄ê̌");
        // Bad trail: ASCII is reprocessed, others swallowed; truncated lead → one U+FFFD.
        assert_eq!(d("big5", &[0xa4, b'0', 0xa4, 0x80, b'x', 0xa4]), "\u{fffd}0\u{fffd}x\u{fffd}");
        assert_eq!(d("big5", &[0x80, 0xff]), "\u{fffd}\u{fffd}");
        assert_eq!(d("gbk", &[0xd6, 0xd0, 0xce, 0xc4, 0x80]), "中文€");
        assert_eq!(d("gb2312", &[0xc4, 0xe3, 0xba, 0xc3]), "你好");
        // GB18030: four-byte ranges (BMP and supplementary), the 7457 special, 2022 index change.
        assert_eq!(d("gb18030", &[0x81, 0x30, 0x81, 0x30, 0x84, 0x31, 0xa4, 0x39, 0x90, 0x30, 0x81, 0x30, 0xe3, 0x32, 0x9a, 0x35]), "\u{80}\u{ffff}\u{10000}\u{10ffff}");
        assert_eq!(d("gb18030", &[0x81, 0x35, 0xf4, 0x37, 0xa6, 0xd9, 0x95, 0x32, 0x82, 0x36]), "\u{e7c7}\u{fe10}\u{20000}");
        assert_eq!(d("gb18030", &[0x84, 0x31, 0xa5, 0x30, 0xe3, 0x32, 0x9a, 0x36]), "\u{fffd}\u{fffd}", "pointers outside the ranges");
        // Bad 3rd / 4th byte: the digit (and the 3rd byte) are reprocessed.
        assert_eq!(d("gb18030", &[0x81, 0x30, b'A']), "\u{fffd}0A");
        assert_eq!(d("gb18030", &[0x81, 0x30, 0x81, 0xff]), "\u{fffd}0\u{fffd}");
        assert_eq!(d("gb18030", &[0x81, 0x30, 0x81]), "\u{fffd}");
        assert_eq!(d("gbk", &[0xd6, b'\n']), "\u{fffd}\n");
    }

    #[test]
    fn japanese_and_korean() {
        assert_eq!(d("shift_jis", &[0x93, 0xfa, 0x96, 0x7b, 0xb1, 0x80, 0x5c]), "日本ｱ\u{80}\\");
        assert_eq!(d("windows-31j", &[0x87, 0x40, 0xf0, 0x40, 0xfa, 0x40, 0xa0]), "①\u{e000}ⅰ\u{fffd}");
        assert_eq!(d("euc-jp", &[0xc6, 0xfc, 0xcb, 0xdc, 0x8e, 0xb1, 0x8f, 0xa2, 0xaf]), "日本ｱ˘");
        assert_eq!(d("euc-jp", &[0x8f, 0xa2, b'a', 0xc6]), "\u{fffd}a\u{fffd}");
        let esc = |s: &str| s.replace('E', "\x1b").into_bytes();
        assert_eq!(d("iso-2022-jp", &esc("aE$BF|K\\E(B!E(J\\~E(I1E(Bz")), "a日本!¥‾ｱz");
        assert_eq!(d("iso-2022-jp", &esc("E$BE(Bx")), "\u{fffd}x", "empty escape run");
        assert_eq!(d("iso-2022-jp", &esc("E$BF")), "\u{fffd}", "truncated pair");
        assert_eq!(d("iso-2022-jp", &esc("E(Zq")), "\u{fffd}(Zq", "unknown escape reprocessed");
        assert_eq!(d("iso-2022-jp", b"\x0e\x80"), "\u{fffd}\u{fffd}");
        assert_eq!(d("euc-kr", &[0xc7, 0xd1, 0xb1, 0xb9, 0x81, 0x41, 0xc7, b'!']), "한국갂\u{fffd}!");
    }

    #[test]
    fn single_byte_utf16_and_bom() {
        assert_eq!(d("koi8-r", &[0xd0, 0xd2, 0xc9, 0xd7, 0xc5, 0xd4]), "привет");
        assert_eq!(d("windows-1251", &[0xcf, 0xf0, 0xe8]), "При");
        assert_eq!(d("iso-8859-7", &[0xe1, 0xe2]), "αβ");
        assert_eq!(d("windows-1252", &[0x80, 0x81, 0x93, 0xe9]), "€\u{81}“é");
        assert_eq!(d("iso-8859-15", &[0xa4]), "€");
        assert_eq!(d("iso-8859-3", &[0xa5]), "\u{fffd}", "unmapped");
        assert_eq!(d("utf-16le", &[0x2d, 0x4e, 0x3d, 0xd8, 0x00, 0xde]), "中😀");
        assert_eq!(d("utf-16be", &[0x4e, 0x2d, 0xd8]), "中\u{fffd}");
        assert_eq!(d("utf-16be", &[0xd8, 0x3d, 0x00]), "\u{fffd}");
        assert_eq!(d("utf-16le", &[0x00, 0xdc, 0x41, 0x00]), "\u{fffd}A");
        assert_eq!(d("big5", &[0xef, 0xbb, 0xbf, 0xe4, 0xb8, 0xad]), "中", "BOM wins");
        assert_eq!(d("utf-8", &[0xff, 0xfe, 0x41, 0x00]), "A");
        assert_eq!(d("utf-8", &[0xe4, 0xb8, b'x']), "\u{fffd}x");
        assert_eq!((d("iso-2022-kr", b"abc"), d("replacement", b"")), ("\u{fffd}".into(), String::new()));
        assert_eq!(d("x-user-defined", &[0x41, 0x80, 0xff]), "A\u{f780}\u{f7ff}");
    }
}
