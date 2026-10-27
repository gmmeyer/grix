//! The guest's virtual nameserver: answer the A and AAAA questions in a
//! DNS query (as the guest's resolver sends it over UDP) with addresses the
//! host's resolver found. The query comes from the guest, so it's parsed
//! defensively; anything that isn't a plain one-question query gets no
//! answer, and the guest's resolver times out as it would on a real network.

use std::net::IpAddr;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const SERVFAIL: u16 = 2;
const NXDOMAIN: u16 = 3;
const TTL: u32 = 60;

/// The question in a query: (id, name, type, the question's bytes, the RD bit).
fn parse(query: &[u8]) -> Option<(u16, String, u16, &[u8], u16)> {
    if query.len() < 12 || query.len() > 4096 {
        return None;
    }
    let id = u16::from_be_bytes([query[0], query[1]]);
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    // A standard query (QR = 0, opcode 0) with one question.
    if flags & 0xf800 != 0 || qdcount != 1 {
        return None;
    }
    let mut at = 12;
    let mut name = String::new();
    loop {
        let len = *query.get(at)? as usize;
        at += 1;
        if len == 0 {
            break;
        }
        // No compression in questions; labels are at most 63 bytes.
        if len > 63 || name.len() + len > 253 {
            return None;
        }
        let label = query.get(at..at + len)?;
        if !label.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_') {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(label).ok()?);
        at += len;
    }
    let qtype = u16::from_be_bytes(query.get(at..at + 2)?.try_into().ok()?);
    let qclass = u16::from_be_bytes(query.get(at + 2..at + 4)?.try_into().ok()?);
    if qclass != CLASS_IN || name.is_empty() {
        return None;
    }
    Some((id, name.to_ascii_lowercase(), qtype, &query[12..at + 4], flags & 0x0100))
}

/// The name a query asks about, if it's one this answers.
pub(crate) fn question(query: &[u8]) -> Option<String> {
    parse(query).map(|(_, name, ..)| name)
}

/// Answer `query` with `addrs` (`None`: the name doesn't exist). Only the
/// addresses of the asked type go in; other question types get an empty
/// answer.
pub(crate) fn answer(query: &[u8], addrs: Option<&[IpAddr]>) -> Option<Vec<u8>> {
    reply(query, addrs, if addrs.is_none() { NXDOMAIN } else { 0 })
}

/// SERVFAIL: the server can't answer now (the resolver tries again, or
/// another server).
pub(crate) fn failure(query: &[u8]) -> Option<Vec<u8>> {
    reply(query, Some(&[]), SERVFAIL)
}

fn reply(query: &[u8], addrs: Option<&[IpAddr]>, rcode: u16) -> Option<Vec<u8>> {
    let (id, _, qtype, question, rd) = parse(query)?;
    let records: Vec<Vec<u8>> = addrs
        .unwrap_or(&[])
        .iter()
        .filter_map(|a| match (a, qtype) {
            (IpAddr::V4(v4), TYPE_A) => Some(v4.octets().to_vec()),
            (IpAddr::V6(v6), TYPE_AAAA) => Some(v6.octets().to_vec()),
            _ => None,
        })
        .take(16)
        .collect();
    let mut out = Vec::with_capacity(12 + question.len() + records.len() * 28);
    out.extend_from_slice(&id.to_be_bytes());
    // QR, the client's RD, RA.
    out.extend_from_slice(&(0x8080 | rd | rcode).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(question);
    for rdata in records {
        out.extend_from_slice(&[0xc0, 12]); // the name: a pointer to the question's
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&TTL.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    #[test]
    fn answers_a_and_aaaa() {
        let addrs: Vec<IpAddr> = vec!["10.0.2.2".parse().unwrap(), "::1".parse().unwrap()];
        let q = query("Example.COM", TYPE_A);
        assert_eq!(question(&q).as_deref(), Some("example.com"));
        let a = answer(&q, Some(&addrs)).unwrap();
        assert_eq!(&a[..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([a[2], a[3]]) & 0xf, 0);
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1, "one A record");
        assert_eq!(&a[a.len() - 4..], &[10, 0, 2, 2]);
        let a = answer(&query("example.com", TYPE_AAAA), Some(&addrs)).unwrap();
        assert_eq!(&a[a.len() - 16..], &"::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        let a = answer(&query("nope.invalid", TYPE_A), None).unwrap();
        assert_eq!(u16::from_be_bytes([a[2], a[3]]) & 0xf, NXDOMAIN);
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 0);
        let a = failure(&query("example.com", TYPE_A)).unwrap();
        assert_eq!((u16::from_be_bytes([a[2], a[3]]) & 0xf, a[7]), (SERVFAIL, 0));
    }

    #[test]
    fn ignores_garbage() {
        let mut q = query("example.com", TYPE_A);
        q[5] = 2; // two questions
        assert!(answer(&q, Some(&[])).is_none());
        assert!(answer(&[0; 11], None).is_none());
        let mut bad = query("example.com", TYPE_A);
        bad[12] = 200; // label longer than the packet
        assert!(answer(&bad, None).is_none());
        let mut x: u32 = 7;
        for len in 0..200 {
            let junk: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1103515245).wrapping_add(12345);
                    (x >> 16) as u8
                })
                .collect();
            let _ = answer(&junk, None);
        }
    }
}
