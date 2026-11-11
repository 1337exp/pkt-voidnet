//! Canonical text description of a datagram. This is the format of the vector file
//! (`vectors/wire-v1.txt`); other-language implementations must print the same text.
//! Каноничное текстовое описание датаграммы: формат файла векторов. Реализации на
//! других языках обязаны печатать тот же текст.

use core::fmt::{self, Write};

use crate::wire::{parse, ChannelMode, Datagram, Frame};

fn hex<W: Write>(w: &mut W, bytes: &[u8]) -> fmt::Result {
    if bytes.is_empty() {
        return w.write_char('-');
    }
    for b in bytes {
        write!(w, "{b:02x}")?;
    }
    Ok(())
}

fn hello<W: Write>(w: &mut W, h: &crate::wire::HelloFields) -> fmt::Result {
    write!(
        w,
        "ver={} proto={:016x} app={} cfg={:08x} rnd={:016x} caps={:08x}",
        h.wire_version, h.protocol_id, h.app_version, h.config_hash, h.client_random, h.caps
    )
}

/// Write the canonical description of `buf`, or `drop` if it does not parse.
/// Записать каноничное описание `buf` или `drop`, если он не разбирается.
pub fn describe<W: Write>(w: &mut W, buf: &[u8], channels: &[ChannelMode]) -> fmt::Result {
    let Ok(d) = parse(buf, channels) else {
        return w.write_str("drop");
    };
    match d {
        Datagram::Data(dd) => {
            write!(w, "DATA token={:016x} pn={}", dd.token, dd.pn)?;
            for f in dd.frames() {
                w.write_str("; ")?;
                match f {
                    Frame::Ack(a) => {
                        write!(
                            w,
                            "ACK largest={} delay={} first={} ranges=",
                            a.largest, a.delay, a.first
                        )?;
                        if a.n == 0 {
                            w.write_char('-')?;
                        }
                        for (i, (gap, len)) in a.blocks.iter().take(usize::from(a.n)).enumerate() {
                            if i > 0 {
                                w.write_char(',')?;
                            }
                            write!(w, "{gap}/{len}")?;
                        }
                    }
                    Frame::Msg { ch, mseq, payload } => {
                        write!(w, "MSG ch={ch} ")?;
                        if let Some(m) = mseq {
                            write!(w, "mseq={m} ")?;
                        }
                        write!(w, "len={} data=", payload.len())?;
                        hex(w, payload)?;
                    }
                    Frame::Ping => w.write_str("PING")?,
                    Frame::Disconnect { reason } => write!(w, "DISC reason={reason}")?,
                }
            }
            Ok(())
        }
        Datagram::Hello(h) => {
            w.write_str("HELLO ")?;
            hello(w, &h)
        }
        Datagram::Challenge { coarse, cookie } => {
            write!(w, "CHALLENGE coarse={coarse} cookie={cookie:016x}")
        }
        Datagram::Response {
            coarse,
            cookie,
            hello: h,
        } => {
            write!(w, "RESPONSE coarse={coarse} cookie={cookie:016x} ")?;
            hello(w, &h)
        }
        Datagram::Accept {
            token,
            echo,
            caps,
            blob,
        } => {
            write!(
                w,
                "ACCEPT token={token:016x} echo={echo:016x} caps={caps:08x} blob="
            )?;
            hex(w, blob)
        }
        Datagram::Reject { code, echo } => write!(w, "REJECT code={code} echo={echo:016x}"),
    }
}
