use bytes::{BufMut, Bytes};
use faster_hex::hex_decode_unchecked;
use nom::bytes::complete::{tag, take_while_m_n};
use nom::character::complete::{digit1, line_ending};
use nom::multi::separated_list0;
use nom::sequence::separated_pair;
use nom::{AsChar, IResult, Parser};
use std::str::from_utf8_unchecked;

fn parse_hash(s: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while_m_n(35, 35, AsChar::is_hex_digit)(s)
}

fn parse_line(s: &[u8]) -> IResult<&[u8], &[u8]> {
    // discards count
    let (rem, (hash, _)) = separated_pair(parse_hash, tag(":"), digit1).parse(s)?;
    Ok((rem, hash))
}

pub fn parse_file(prefix: u32, s: &[u8]) -> IResult<&[u8], Vec<Bytes>> {
    let mut base_hash = Vec::with_capacity(3);
    base_hash.put_u16((prefix >> 4) as u16);
    base_hash.put_u8((prefix as u8) << 4);

    let (rem, hex_hashes) = separated_list0(line_ending, parse_line).parse(s)?;
    let mut hashes: Vec<Bytes> = Vec::with_capacity(hex_hashes.len());

    for hex in hex_hashes {
        let mut hash = vec![0; 20];
        hash[..3].copy_from_slice(&base_hash);

        // guaranteed to be [:xdigit:] because of is_hex_digit call in parse_hash
        let byte3 = unsafe { from_utf8_unchecked(&hex[0..1]) };
        hash[2] |= u8::from_str_radix(byte3, 16).unwrap();

        hex_decode_unchecked(&hex[1..], &mut hash[3..]);
        hashes.push(Bytes::from(hash));
    }
    Ok((rem, hashes))
}
