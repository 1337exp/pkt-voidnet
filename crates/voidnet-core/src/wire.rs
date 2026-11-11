//! Datagram parsing and building. The normative description is `docs/wire.md`.
//! Разбор и построение датаграмм. Нормативное описание: `docs/wire.md`.

use crate::ack::AckFrame;
use crate::io::{Reader, Writer};

/// Wire format generation carried in HELLO. / Поколение формата в HELLO.
pub const WIRE_VERSION: u8 = 1;
/// Largest datagram. / Наибольшая датаграмма.
pub const MAX_DATAGRAM: usize = 1400;
/// Most channels. / Наибольшее число каналов.
pub const MAX_CHANNELS: usize = 16;
/// Length of HELLO and RESPONSE. / Длина HELLO и RESPONSE.
pub const HANDSHAKE_LEN: usize = 64;
/// Longest ACCEPT blob. / Наибольший blob в ACCEPT.
pub const MAX_BLOB: usize = 32;
/// Length of the DATA header (kind, token, pn). / Длина заголовка DATA.
pub const DATA_HEADER_LEN: usize = 11;
/// Length of CHALLENGE. / Длина CHALLENGE.
pub const CHALLENGE_LEN: usize = 13;
/// Length of REJECT. / Длина REJECT.
pub const REJECT_LEN: usize = 10;
/// Fixed part of ACCEPT before the blob. / Постоянная часть ACCEPT до blob.
pub const ACCEPT_FIXED_LEN: usize = 22;
/// Length of HELLO FIELDS. / Длина HELLO FIELDS.
pub const HELLO_FIELDS_LEN: usize = 29;

/// Datagram kind bytes. / Байты вида датаграммы.
pub mod kind {
    pub const DATA: u8 = 0x00;
    pub const HELLO: u8 = 0x80;
    pub const CHALLENGE: u8 = 0x81;
    pub const RESPONSE: u8 = 0x82;
    pub const ACCEPT: u8 = 0x83;
    pub const REJECT: u8 = 0x84;
}

/// Frame tags above the channel range. / Теги кадров выше диапазона каналов.
pub mod tag {
    pub const MAX_CHANNEL: u8 = 0x0F;
    pub const ACK: u8 = 0x10;
    pub const PING: u8 = 0x11;
    pub const DISCONNECT: u8 = 0x12;
}

/// Delivery mode of a channel. / Режим доставки канала.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChannelMode {
    Unreliable = 0,
    UnreliableSequenced = 1,
    ReliableOrdered = 2,
}

impl ChannelMode {
    /// Whether messages carry `mseq`. / Несут ли сообщения `mseq`.
    pub const fn numbered(self) -> bool {
        !matches!(self, ChannelMode::Unreliable)
    }
}

/// Why a datagram was dropped. / Почему датаграмма отброшена.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    Empty,
    TooLong,
    UnknownKind,
    BadLength,
    Truncated,
    NonZeroPadding,
    Noncanonical,
    UnknownFrame,
    BadChannel,
    FrameOrder,
    NoFrames,
    BadAck,
    BadBlob,
}

/// Why a write failed. / Почему запись не удалась.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WriteError {
    NoSpace,
    /// Value or call order not allowed by the wire format.
    Invalid,
}

/// HELLO FIELDS (29 bytes). / HELLO FIELDS (29 байт).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HelloFields {
    pub wire_version: u8,
    pub protocol_id: u64,
    pub app_version: u32,
    pub config_hash: u32,
    pub client_random: u64,
    pub caps: u32,
}

impl HelloFields {
    fn read(r: &mut Reader<'_>) -> Result<Self, ParseError> {
        Ok(Self {
            wire_version: r.u8()?,
            protocol_id: r.u64()?,
            app_version: r.u32()?,
            config_hash: r.u32()?,
            client_random: r.u64()?,
            caps: r.u32()?,
        })
    }

    fn write(&self, w: &mut Writer<'_>) -> Result<(), WriteError> {
        w.put_u8(self.wire_version)?;
        w.put_u64(self.protocol_id)?;
        w.put_u32(self.app_version)?;
        w.put_u32(self.config_hash)?;
        w.put_u64(self.client_random)?;
        w.put_u32(self.caps)
    }
}

/// A frame inside DATA. / Кадр внутри DATA.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Frame<'a> {
    Msg {
        ch: u8,
        mseq: Option<u16>,
        payload: &'a [u8],
    },
    Ack(AckFrame),
    Ping,
    Disconnect {
        reason: u8,
    },
}

impl Frame<'_> {
    /// Whether this frame obliges the receiver to acknowledge. / Требует ли подтверждения.
    pub fn ack_eliciting(&self) -> bool {
        !matches!(self, Frame::Ack(_))
    }
}

fn read_frame<'a>(r: &mut Reader<'a>, channels: &[ChannelMode]) -> Result<Frame<'a>, ParseError> {
    let t = r.u8()?;
    match t {
        0..=tag::MAX_CHANNEL => {
            let mode = channels.get(usize::from(t)).ok_or(ParseError::BadChannel)?;
            let mseq = if mode.numbered() {
                Some(r.u16()?)
            } else {
                None
            };
            let len = r.varint()? as usize;
            let payload = r.bytes(len)?;
            Ok(Frame::Msg {
                ch: t,
                mseq,
                payload,
            })
        }
        tag::ACK => Ok(Frame::Ack(AckFrame::read(r)?)),
        tag::PING => Ok(Frame::Ping),
        tag::DISCONNECT => Ok(Frame::Disconnect { reason: r.u8()? }),
        _ => Err(ParseError::UnknownFrame),
    }
}

/// A parsed DATA datagram: header plus a validated frame area.
/// Разобранная DATA: заголовок и проверенная область кадров.
#[derive(Clone, Copy, Debug)]
pub struct DataDatagram<'a> {
    pub token: u64,
    pub pn: u16,
    body: &'a [u8],
    channels: &'a [ChannelMode],
}

impl<'a> DataDatagram<'a> {
    /// Iterate over the frames. Validation already happened in [`parse`].
    /// Обход кадров. Проверка уже выполнена в [`parse`].
    pub fn frames(&self) -> Frames<'a> {
        Frames {
            r: Reader::new(self.body),
            channels: self.channels,
        }
    }

    /// Whether any frame is ack-eliciting. / Есть ли кадр, требующий подтверждения.
    pub fn ack_eliciting(&self) -> bool {
        self.frames().any(|f| f.ack_eliciting())
    }
}

/// Iterator over the frames of a validated DATA datagram. / Обход кадров.
#[derive(Clone, Copy)]
pub struct Frames<'a> {
    r: Reader<'a>,
    channels: &'a [ChannelMode],
}

impl<'a> Iterator for Frames<'a> {
    type Item = Frame<'a>;

    fn next(&mut self) -> Option<Frame<'a>> {
        if self.r.is_empty() {
            return None;
        }
        read_frame(&mut self.r, self.channels).ok()
    }
}

/// A parsed datagram. / Разобранная датаграмма.
#[derive(Clone, Copy, Debug)]
pub enum Datagram<'a> {
    Data(DataDatagram<'a>),
    Hello(HelloFields),
    Challenge {
        coarse: u32,
        cookie: u64,
    },
    Response {
        coarse: u32,
        cookie: u64,
        hello: HelloFields,
    },
    Accept {
        token: u64,
        echo: u64,
        caps: u32,
        blob: &'a [u8],
    },
    Reject {
        code: u8,
        echo: u64,
    },
}

/// Parse one datagram. Strict: any deviation from `docs/wire.md` is an error and the
/// caller drops the datagram without a reply. `channels` is the channel table.
/// Разбор датаграммы. Строгий: любое отклонение от `docs/wire.md` это ошибка, и
/// вызывающий молча отбрасывает датаграмму. `channels` — таблица каналов.
pub fn parse<'a>(buf: &'a [u8], channels: &'a [ChannelMode]) -> Result<Datagram<'a>, ParseError> {
    if buf.len() > MAX_DATAGRAM {
        return Err(ParseError::TooLong);
    }
    if channels.len() > MAX_CHANNELS {
        return Err(ParseError::BadChannel);
    }
    let mut r = Reader::new(buf);
    let k = r.u8().map_err(|_| ParseError::Empty)?;
    match k {
        kind::DATA => parse_data(r, buf, channels),
        kind::HELLO => {
            if buf.len() != HANDSHAKE_LEN {
                return Err(ParseError::BadLength);
            }
            let hello = HelloFields::read(&mut r)?;
            r.zero_padding()?;
            Ok(Datagram::Hello(hello))
        }
        kind::CHALLENGE => {
            if buf.len() != CHALLENGE_LEN {
                return Err(ParseError::BadLength);
            }
            Ok(Datagram::Challenge {
                coarse: r.u32()?,
                cookie: r.u64()?,
            })
        }
        kind::RESPONSE => {
            if buf.len() != HANDSHAKE_LEN {
                return Err(ParseError::BadLength);
            }
            let coarse = r.u32()?;
            let cookie = r.u64()?;
            let hello = HelloFields::read(&mut r)?;
            r.zero_padding()?;
            Ok(Datagram::Response {
                coarse,
                cookie,
                hello,
            })
        }
        kind::ACCEPT => {
            let token = r.u64()?;
            let echo = r.u64()?;
            let caps = r.u32()?;
            let blob_len = usize::from(r.u8()?);
            if blob_len > MAX_BLOB {
                return Err(ParseError::BadBlob);
            }
            if r.remaining() != blob_len {
                return Err(ParseError::BadLength);
            }
            let blob = r.bytes(blob_len)?;
            Ok(Datagram::Accept {
                token,
                echo,
                caps,
                blob,
            })
        }
        kind::REJECT => {
            if buf.len() != REJECT_LEN {
                return Err(ParseError::BadLength);
            }
            Ok(Datagram::Reject {
                code: r.u8()?,
                echo: r.u64()?,
            })
        }
        _ => Err(ParseError::UnknownKind),
    }
}

fn parse_data<'a>(
    mut r: Reader<'a>,
    buf: &'a [u8],
    channels: &'a [ChannelMode],
) -> Result<Datagram<'a>, ParseError> {
    if buf.len() <= DATA_HEADER_LEN {
        return Err(ParseError::NoFrames);
    }
    let token = r.u64()?;
    let pn = r.u16()?;
    let body = r.rest();

    let mut fr = Reader::new(body);
    let (mut count, mut seen_ping, mut seen_disc) = (0usize, false, false);
    while !fr.is_empty() {
        if seen_disc {
            return Err(ParseError::FrameOrder);
        }
        match read_frame(&mut fr, channels)? {
            Frame::Ack(_) if count != 0 => return Err(ParseError::FrameOrder),
            Frame::Ping if seen_ping => return Err(ParseError::FrameOrder),
            Frame::Ping => seen_ping = true,
            Frame::Disconnect { .. } => seen_disc = true,
            _ => {}
        }
        count += 1;
    }
    Ok(Datagram::Data(DataDatagram {
        token,
        pn,
        body,
        channels,
    }))
}

/// Builder for one DATA datagram. Failed calls leave the buffer as it was, so a sender
/// can try the next smaller message. Enforces the frame order rules.
/// Построитель одной DATA. Неудачный вызов ничего не меняет, поэтому отправитель может
/// попробовать следующее, меньшее сообщение. Следит за порядком кадров.
pub struct DataWriter<'b> {
    w: Writer<'b>,
    channels: &'b [ChannelMode],
    frames: usize,
    ended: bool,
    pinged: bool,
}

impl<'b> DataWriter<'b> {
    pub fn new(
        out: &'b mut [u8],
        channels: &'b [ChannelMode],
        token: u64,
        pn: u16,
    ) -> Result<Self, WriteError> {
        let mut w = Writer::new(out, MAX_DATAGRAM);
        w.put_u8(kind::DATA)?;
        w.put_u64(token)?;
        w.put_u16(pn)?;
        Ok(Self {
            w,
            channels,
            frames: 0,
            ended: false,
            pinged: false,
        })
    }

    /// Bytes written so far. / Записано байт.
    pub fn len(&self) -> usize {
        self.w.pos()
    }

    /// Whether no frame was added yet. / Пока нет ни одного кадра.
    pub fn is_empty(&self) -> bool {
        self.frames == 0
    }

    fn frame(
        &mut self,
        f: impl FnOnce(&mut Writer<'b>) -> Result<(), WriteError>,
    ) -> Result<(), WriteError> {
        if self.ended {
            return Err(WriteError::Invalid);
        }
        self.w.atomic(f)?;
        self.frames += 1;
        Ok(())
    }

    /// Add the ACK frame; only valid as the first frame. / Только первым кадром.
    pub fn ack(&mut self, a: &AckFrame) -> Result<(), WriteError> {
        if self.frames != 0 {
            return Err(WriteError::Invalid);
        }
        self.frame(|w| {
            w.put_u8(tag::ACK)?;
            a.write(w)
        })
    }

    /// Add a message. `mseq` must be `Some` exactly for numbered channels.
    /// Добавить сообщение. `mseq` нужен ровно для нумерованных каналов.
    pub fn msg(&mut self, ch: u8, mseq: Option<u16>, payload: &[u8]) -> Result<(), WriteError> {
        let mode = self
            .channels
            .get(usize::from(ch))
            .filter(|_| ch <= tag::MAX_CHANNEL)
            .ok_or(WriteError::Invalid)?;
        if mode.numbered() != mseq.is_some() {
            return Err(WriteError::Invalid);
        }
        let len = u32::try_from(payload.len()).map_err(|_| WriteError::NoSpace)?;
        self.frame(|w| {
            w.put_u8(ch)?;
            if let Some(m) = mseq {
                w.put_u16(m)?;
            }
            w.put_varint(len)?;
            w.put(payload)
        })
    }

    pub fn ping(&mut self) -> Result<(), WriteError> {
        if self.pinged {
            return Err(WriteError::Invalid);
        }
        self.frame(|w| w.put_u8(tag::PING))?;
        self.pinged = true;
        Ok(())
    }

    /// Add DISCONNECT; no frame may follow. / После него кадры не допускаются.
    pub fn disconnect(&mut self, reason: u8) -> Result<(), WriteError> {
        self.frame(|w| {
            w.put_u8(tag::DISCONNECT)?;
            w.put_u8(reason)
        })?;
        self.ended = true;
        Ok(())
    }

    /// Finish; fails if there is no frame. Returns the datagram length.
    /// Завершить; ошибка, если кадров нет. Возвращает длину датаграммы.
    pub fn finish(self) -> Result<usize, WriteError> {
        if self.frames == 0 {
            return Err(WriteError::Invalid);
        }
        Ok(self.w.pos())
    }
}

fn write_handshake(
    out: &mut [u8],
    k: u8,
    pre: impl FnOnce(&mut Writer<'_>) -> Result<(), WriteError>,
    pad_to: usize,
) -> Result<usize, WriteError> {
    let mut w = Writer::new(out, MAX_DATAGRAM);
    w.put_u8(k)?;
    pre(&mut w)?;
    let pad = pad_to.checked_sub(w.pos()).ok_or(WriteError::Invalid)?;
    w.put_zeros(pad)?;
    Ok(w.pos())
}

/// Encode HELLO (64 bytes). / Закодировать HELLO (64 байта).
pub fn write_hello(out: &mut [u8], h: &HelloFields) -> Result<usize, WriteError> {
    write_handshake(out, kind::HELLO, |w| h.write(w), HANDSHAKE_LEN)
}

/// Encode CHALLENGE (13 bytes). / Закодировать CHALLENGE (13 байт).
pub fn write_challenge(out: &mut [u8], coarse: u32, cookie: u64) -> Result<usize, WriteError> {
    write_handshake(
        out,
        kind::CHALLENGE,
        |w| {
            w.put_u32(coarse)?;
            w.put_u64(cookie)
        },
        CHALLENGE_LEN,
    )
}

/// Encode RESPONSE (64 bytes). / Закодировать RESPONSE (64 байта).
pub fn write_response(
    out: &mut [u8],
    coarse: u32,
    cookie: u64,
    h: &HelloFields,
) -> Result<usize, WriteError> {
    write_handshake(
        out,
        kind::RESPONSE,
        |w| {
            w.put_u32(coarse)?;
            w.put_u64(cookie)?;
            h.write(w)
        },
        HANDSHAKE_LEN,
    )
}

/// Encode ACCEPT. `blob` is at most [`MAX_BLOB`] bytes. / Закодировать ACCEPT.
pub fn write_accept(
    out: &mut [u8],
    token: u64,
    echo: u64,
    caps: u32,
    blob: &[u8],
) -> Result<usize, WriteError> {
    if blob.len() > MAX_BLOB {
        return Err(WriteError::Invalid);
    }
    let blob_len = u8::try_from(blob.len()).map_err(|_| WriteError::Invalid)?;
    let total = ACCEPT_FIXED_LEN + blob.len();
    write_handshake(
        out,
        kind::ACCEPT,
        |w| {
            w.put_u64(token)?;
            w.put_u64(echo)?;
            w.put_u32(caps)?;
            w.put_u8(blob_len)?;
            w.put(blob)
        },
        total,
    )
}

/// Encode REJECT (10 bytes). / Закодировать REJECT (10 байт).
pub fn write_reject(out: &mut [u8], code: u8, echo: u64) -> Result<usize, WriteError> {
    write_handshake(
        out,
        kind::REJECT,
        |w| {
            w.put_u8(code)?;
            w.put_u64(echo)
        },
        REJECT_LEN,
    )
}

/// Encode any parsed datagram back to bytes. Parsing a valid datagram and encoding it
/// gives the original bytes (the property the fuzz target checks).
/// Закодировать разобранную датаграмму обратно. Разбор и кодирование возвращают исходные байты.
pub fn encode(d: &Datagram<'_>, out: &mut [u8]) -> Result<usize, WriteError> {
    match d {
        Datagram::Data(dd) => {
            let mut w = DataWriter::new(out, dd.channels, dd.token, dd.pn)?;
            for f in dd.frames() {
                match f {
                    Frame::Msg { ch, mseq, payload } => w.msg(ch, mseq, payload)?,
                    Frame::Ack(a) => w.ack(&a)?,
                    Frame::Ping => w.ping()?,
                    Frame::Disconnect { reason } => w.disconnect(reason)?,
                }
            }
            w.finish()
        }
        Datagram::Hello(h) => write_hello(out, h),
        Datagram::Challenge { coarse, cookie } => write_challenge(out, *coarse, *cookie),
        Datagram::Response {
            coarse,
            cookie,
            hello,
        } => write_response(out, *coarse, *cookie, hello),
        Datagram::Accept {
            token,
            echo,
            caps,
            blob,
        } => write_accept(out, *token, *echo, *caps, blob),
        Datagram::Reject { code, echo } => write_reject(out, *code, *echo),
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::window::RecvWindow;

    const CH: [ChannelMode; 3] = [
        ChannelMode::ReliableOrdered,
        ChannelMode::Unreliable,
        ChannelMode::UnreliableSequenced,
    ];

    fn hello() -> HelloFields {
        HelloFields {
            wire_version: 1,
            protocol_id: 0x5445_4501,
            app_version: 7,
            config_hash: 0xDEAD_BEEF,
            client_random: 0x0102_0304_0506_0708,
            caps: 0,
        }
    }

    fn data(build: impl FnOnce(&mut DataWriter<'_>)) -> std::vec::Vec<u8> {
        let mut buf = [0u8; MAX_DATAGRAM];
        let mut w = DataWriter::new(&mut buf, &CH, 0x1122_3344_5566_7788, 0xBEEF).unwrap();
        build(&mut w);
        let n = w.finish().unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn data_roundtrip_all_frame_kinds() {
        let win = {
            let mut w = RecvWindow::new();
            for p in [1u64, 2, 5] {
                w.mark(p);
            }
            w
        };
        let ack = AckFrame::from_window(&win, 300).unwrap();
        let bytes = data(|w| {
            w.ack(&ack).unwrap();
            w.msg(0, Some(9), b"hello").unwrap();
            w.msg(1, None, b"").unwrap();
            w.msg(2, Some(65_535), &[7u8; 200]).unwrap();
            w.ping().unwrap();
            w.disconnect(3).unwrap();
        });
        let d = parse(&bytes, &CH).unwrap();
        let Datagram::Data(dd) = d else {
            panic!("not data")
        };
        assert_eq!((dd.token, dd.pn), (0x1122_3344_5566_7788, 0xBEEF));
        let frames: std::vec::Vec<_> = dd.frames().collect();
        assert_eq!(frames.len(), 6);
        assert!(matches!(frames[0], Frame::Ack(a) if a.largest == 5 && a.delay == 300));
        assert_eq!(
            frames[1],
            Frame::Msg {
                ch: 0,
                mseq: Some(9),
                payload: b"hello"
            }
        );
        assert_eq!(
            frames[2],
            Frame::Msg {
                ch: 1,
                mseq: None,
                payload: b""
            }
        );
        assert!(
            matches!(frames[3], Frame::Msg { ch: 2, mseq: Some(65_535), payload } if payload.len() == 200)
        );
        assert_eq!(frames[4], Frame::Ping);
        assert_eq!(frames[5], Frame::Disconnect { reason: 3 });
        let mut again = [0u8; MAX_DATAGRAM];
        let n = encode(&d, &mut again).unwrap();
        assert_eq!(&again[..n], &bytes[..]);
    }

    #[test]
    fn handshake_roundtrip() {
        let mut buf = [0u8; MAX_DATAGRAM];
        let n = write_hello(&mut buf, &hello()).unwrap();
        assert_eq!(n, 64);
        assert!(matches!(parse(&buf[..n], &CH), Ok(Datagram::Hello(h)) if h == hello()));

        let n = write_challenge(&mut buf, 123, 0xAABB_CCDD_EEFF_0011).unwrap();
        assert_eq!(n, 13);
        assert!(matches!(
            parse(&buf[..n], &CH),
            Ok(Datagram::Challenge {
                coarse: 123,
                cookie: 0xAABB_CCDD_EEFF_0011
            })
        ));

        let n = write_response(&mut buf, 123, 99, &hello()).unwrap();
        assert_eq!(n, 64);
        assert!(matches!(
            parse(&buf[..n], &CH),
            Ok(Datagram::Response { coarse: 123, cookie: 99, hello: h }) if h == hello()
        ));

        let n = write_accept(&mut buf, 5, 6, 0, b"tick=50").unwrap();
        assert_eq!(n, 22 + 7);
        assert!(matches!(
            parse(&buf[..n], &CH),
            Ok(Datagram::Accept { token: 5, echo: 6, caps: 0, blob }) if blob == b"tick=50"
        ));

        let n = write_reject(&mut buf, 3, 6).unwrap();
        assert_eq!(n, 10);
        assert!(matches!(
            parse(&buf[..n], &CH),
            Ok(Datagram::Reject { code: 3, echo: 6 })
        ));
    }

    #[test]
    fn replies_are_never_longer_than_what_triggers_them() {
        let mut buf = [0u8; MAX_DATAGRAM];
        let hello_len = write_hello(&mut buf, &hello()).unwrap();
        let response_len = write_response(&mut buf, 0, 0, &hello()).unwrap();
        let challenge_len = write_challenge(&mut buf, 0, 0).unwrap();
        let reject_len = write_reject(&mut buf, 0, 0).unwrap();
        let accept_max = write_accept(&mut buf, 0, 0, 0, &[0u8; MAX_BLOB]).unwrap();
        assert!(challenge_len <= hello_len && reject_len <= hello_len);
        assert!(accept_max <= response_len && reject_len <= response_len);
    }

    #[test]
    fn rejects_bad_kinds_lengths_and_padding() {
        assert_eq!(parse(&[], &CH).unwrap_err(), ParseError::Empty);
        assert_eq!(
            parse(&[0x01, 0, 0], &CH).unwrap_err(),
            ParseError::UnknownKind
        );
        assert_eq!(parse(&[0xFF], &CH).unwrap_err(), ParseError::UnknownKind);
        assert_eq!(parse(&[0u8; 1401], &CH).unwrap_err(), ParseError::TooLong);

        let mut buf = [0u8; 64];
        write_hello(&mut buf, &hello()).unwrap();
        assert_eq!(parse(&buf[..63], &CH).unwrap_err(), ParseError::BadLength);
        buf[40] = 1; // padding byte
        assert_eq!(parse(&buf, &CH).unwrap_err(), ParseError::NonZeroPadding);

        let mut b = [0u8; 64];
        let n = write_accept(&mut b, 1, 2, 0, b"ab").unwrap();
        assert_eq!(parse(&b[..n - 1], &CH).unwrap_err(), ParseError::BadLength);
        b[21] = 33; // blob_len over the maximum
        assert_eq!(parse(&b[..n], &CH).unwrap_err(), ParseError::BadBlob);
    }

    #[test]
    fn data_frame_rules() {
        // no frames
        assert_eq!(
            parse(&data_header(), &CH).unwrap_err(),
            ParseError::NoFrames
        );
        // unknown tags, reserved tags
        for t in [0x13u8, 0x1F, 0x20, 0xFF] {
            let mut b = data_header();
            b.push(t);
            assert_eq!(
                parse(&b, &CH).unwrap_err(),
                ParseError::UnknownFrame,
                "tag {t:#x}"
            );
        }
        // channel outside the table
        let mut b = data_header();
        b.extend_from_slice(&[5, 0]);
        assert_eq!(parse(&b, &CH).unwrap_err(), ParseError::BadChannel);
        // frame after DISCONNECT, two pings, ack not first
        let mut b = data_header();
        b.extend_from_slice(&[tag::DISCONNECT, 0, tag::PING]);
        assert_eq!(parse(&b, &CH).unwrap_err(), ParseError::FrameOrder);
        let mut b = data_header();
        b.extend_from_slice(&[tag::PING, tag::PING]);
        assert_eq!(parse(&b, &CH).unwrap_err(), ParseError::FrameOrder);
        let mut b = data_header();
        b.extend_from_slice(&[tag::PING, tag::ACK, 0, 0, 0, 0, 1]);
        assert_eq!(parse(&b, &CH).unwrap_err(), ParseError::FrameOrder);
        // message longer than the datagram
        let mut b = data_header();
        b.extend_from_slice(&[1, 10, 1, 2]);
        assert_eq!(parse(&b, &CH).unwrap_err(), ParseError::Truncated);
        // non-canonical length
        let mut b = data_header();
        b.extend_from_slice(&[1, 0x80, 0x00]);
        assert_eq!(parse(&b, &CH).unwrap_err(), ParseError::Noncanonical);
    }

    fn data_header() -> std::vec::Vec<u8> {
        let mut v = std::vec![kind::DATA];
        v.extend_from_slice(&1u64.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v
    }

    #[test]
    fn writer_enforces_rules_and_rolls_back() {
        let mut buf = [0u8; 32];
        let mut w = DataWriter::new(&mut buf, &CH, 1, 1).unwrap();
        assert_eq!(w.msg(0, None, b"x"), Err(WriteError::Invalid)); // needs mseq
        assert_eq!(w.msg(1, Some(1), b"x"), Err(WriteError::Invalid)); // must not have mseq
        assert_eq!(w.msg(9, None, b"x"), Err(WriteError::Invalid)); // no such channel
        assert!(w.is_empty());
        w.msg(1, None, b"abc").unwrap();
        let before = w.len();
        assert_eq!(w.msg(1, None, &[0u8; 40]), Err(WriteError::NoSpace));
        assert_eq!(w.len(), before, "failed write must not move the cursor");
        assert_eq!(w.ack(&ack_frame()), Err(WriteError::Invalid)); // not first
        w.ping().unwrap();
        assert_eq!(w.ping(), Err(WriteError::Invalid));
        w.disconnect(1).unwrap();
        assert_eq!(w.msg(1, None, b"x"), Err(WriteError::Invalid)); // after disconnect
        assert!(w.finish().is_ok());
    }

    fn ack_frame() -> AckFrame {
        let mut win = RecvWindow::new();
        win.mark(3);
        AckFrame::from_window(&win, 0).unwrap()
    }

    #[test]
    fn empty_writer_does_not_finish() {
        let mut buf = [0u8; 32];
        let w = DataWriter::new(&mut buf, &CH, 1, 1).unwrap();
        assert_eq!(w.finish(), Err(WriteError::Invalid));
    }

    #[test]
    fn largest_possible_data_datagram_parses() {
        let mut buf = [0u8; MAX_DATAGRAM];
        let mut w = DataWriter::new(&mut buf, &CH, 1, 1).unwrap();
        let room = MAX_DATAGRAM - w.len() - 1 - 2; // tag + 2-byte varint
        w.msg(1, None, &std::vec![9u8; room]).unwrap();
        let n = w.finish().unwrap();
        assert_eq!(n, MAX_DATAGRAM);
        assert!(parse(&buf[..n], &CH).is_ok());
    }
}
