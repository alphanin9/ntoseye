//! KD packet framing
//!
//! ```text
//! data:    [ leader=0x30303030 | type | bytecount | id | checksum ] [ payload ] [ 0xAA ]
//! control: [ leader=0x69696969 | type | 0         | id | 0        ]
//! ```

use std::collections::VecDeque;
use std::io::{Read, Write};

use crate::error::{Error, Result};

const DATA_PACKET_LEADER: u32 = 0x30303030;
const CONTROL_PACKET_LEADER: u32 = 0x69696969;
const DATA_LEADER_BYTE: u8 = 0x30;
const CONTROL_LEADER_BYTE: u8 = 0x69;
const PACKET_TRAILING_BYTE: u8 = 0xAA;
const BREAKIN_BYTE: u8 = 0x62;

const INITIAL_PACKET_ID: u32 = 0x80800000;
const SYNC_PACKET_ID: u32 = 0x00000800;

const PACKET_MAX_SIZE: usize = 4000;
const HEADER_SIZE: usize = 16;

pub const PACKET_TYPE_KD_STATE_CHANGE64: u16 = 7;
pub const PACKET_TYPE_KD_STATE_MANIPULATE: u16 = 2;
pub const PACKET_TYPE_KD_DEBUG_IO: u16 = 3;
pub const PACKET_TYPE_KD_ACKNOWLEDGE: u16 = 4;
pub const PACKET_TYPE_KD_RESEND: u16 = 5;
pub const PACKET_TYPE_KD_RESET: u16 = 6;

#[derive(Debug, Clone, Copy)]
struct Header {
    leader: u32,
    packet_type: u16,
    byte_count: u16,
    packet_id: u32,
    checksum: u32,
}

impl Header {
    fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.leader.to_le_bytes());
        buf[4..6].copy_from_slice(&self.packet_type.to_le_bytes());
        buf[6..8].copy_from_slice(&self.byte_count.to_le_bytes());
        buf[8..12].copy_from_slice(&self.packet_id.to_le_bytes());
        buf[12..16].copy_from_slice(&self.checksum.to_le_bytes());
        buf
    }

    fn decode(buf: &[u8; HEADER_SIZE]) -> Self {
        Self {
            leader: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            packet_type: u16::from_le_bytes(buf[4..6].try_into().unwrap()),
            byte_count: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
            packet_id: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            checksum: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
        }
    }
}

fn checksum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
}

#[derive(Debug, Clone)]
pub struct DataPacket {
    pub packet_type: u16,
    pub payload: Vec<u8>,
}

/// Send retry budget for RESEND or missing ACK
const MAX_SEND_RETRIES: usize = 5;

pub struct KdFraming<T> {
    transport: T,
    current_packet_id: u32,
    remote_packet_id: u32,
    queued_data: VecDeque<DataPacket>,
}

impl<T> KdFraming<T> {
    /// Mutable access to the wrapped transport
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Test-only transport accessor
    #[cfg(test)]
    pub fn transport_ref(&self) -> &T {
        &self.transport
    }
}

impl<T: Read + Write> KdFraming<T> {
    pub fn new(transport: T) -> Self {
        // First kernel packet may have SYNC set; mask it on compare/ack
        Self {
            transport,
            current_packet_id: INITIAL_PACKET_ID,
            remote_packet_id: INITIAL_PACKET_ID,
            queued_data: VecDeque::new(),
        }
    }

    /// Send an unframed break-in byte
    pub fn send_breakin(&mut self) -> Result<()> {
        self.transport.write_all(&[BREAKIN_BYTE])?;
        self.transport.flush()?;
        Ok(())
    }

    /// Send KD_RESET and reset local packet IDs
    pub fn send_reset(&mut self) -> Result<()> {
        self.current_packet_id = INITIAL_PACKET_ID;
        self.remote_packet_id = INITIAL_PACKET_ID;
        self.queued_data.clear();
        self.send_control(PACKET_TYPE_KD_RESET, 0)
    }

    pub fn send_data(&mut self, packet_type: u16, payload: &[u8]) -> Result<()> {
        if payload.len() > PACKET_MAX_SIZE {
            return Err(Error::Kd(format!(
                "outbound packet too large: {} bytes",
                payload.len()
            )));
        }

        for attempt in 0..MAX_SEND_RETRIES {
            let header = Header {
                leader: DATA_PACKET_LEADER,
                packet_type,
                byte_count: payload.len() as u16,
                packet_id: self.current_packet_id,
                checksum: checksum(payload),
            };

            kd_trace!(
                "kd: send_data: type={} id={:#x} len={} attempt={}",
                packet_type,
                self.current_packet_id,
                payload.len(),
                attempt
            );

            self.transport.write_all(&header.encode())?;
            self.transport.write_all(payload)?;
            self.transport.write_all(&[PACKET_TRAILING_BYTE])?;
            self.transport.flush()?;

            // Inner loop: drain any non-ACK packets queued in the buffer
            // (typically kernel retransmissions of a prior state-change
            // that arrived before we ACKed it). We ACK stale packets and queue
            // fresh packets for the next `recv_data`; breaking out of this
            // inner loop triggers a resend via the outer loop
            loop {
                match self.recv_any()? {
                    Received::Ack { packet_id }
                        if (packet_id & !SYNC_PACKET_ID)
                            == (self.current_packet_id & !SYNC_PACKET_ID) =>
                    {
                        kd_trace!("kd: send_data: ACKed id={:#x}", packet_id);
                        self.current_packet_id ^= 1;
                        self.current_packet_id &= !SYNC_PACKET_ID;
                        return Ok(());
                    }
                    Received::Reset => {
                        kd_trace!("kd: send_data: got RESET, resyncing ids");
                        self.current_packet_id = INITIAL_PACKET_ID;
                        self.remote_packet_id = INITIAL_PACKET_ID;
                        self.queued_data.clear();
                        break;
                    }
                    Received::Resend => {
                        kd_trace!("kd: send_data: got RESEND, retransmitting");
                        break;
                    }
                    Received::Ack { packet_id } => {
                        kd_trace!(
                            "kd: send_data: stray ACK id={:#x} (expected {:#x}), retransmitting",
                            packet_id,
                            self.current_packet_id
                        );
                        break;
                    }
                    Received::Data {
                        packet_id,
                        packet_type,
                        payload,
                    } => {
                        let ack_id = packet_id & !SYNC_PACKET_ID;
                        self.send_control(PACKET_TYPE_KD_ACKNOWLEDGE, ack_id)?;
                        if ack_id != self.remote_packet_id {
                            kd_trace!(
                                "kd: send_data: skip stale queued data type={} id={:#x} (expected {:#x}), ACKed",
                                packet_type,
                                packet_id,
                                self.remote_packet_id
                            );
                            continue;
                        }
                        kd_trace!(
                            "kd: send_data: accepted queued data type={} id={:#x} len={}",
                            packet_type,
                            packet_id,
                            payload.len()
                        );
                        self.remote_packet_id ^= 1;
                        self.remote_packet_id &= !SYNC_PACKET_ID;
                        self.queued_data.push_back(DataPacket {
                            packet_type,
                            payload,
                        });
                    }
                }
            }
        }

        Err(Error::Kd("send exceeded retry budget".into()))
    }

    /// Receive the next data packet, ACK'ing it. Discards (but ACKs) any
    /// out-of-order data packets whose id doesn't match `remote_packet_id`
    pub fn recv_data(&mut self) -> Result<DataPacket> {
        if let Some(pkt) = self.queued_data.pop_front() {
            kd_trace!(
                "kd: recv_data: returning queued type={} len={}",
                pkt.packet_type,
                pkt.payload.len()
            );
            return Ok(pkt);
        }

        loop {
            match self.recv_any()? {
                Received::Data {
                    packet_type,
                    packet_id,
                    payload,
                } => {
                    // Kernel checks our ACK id against its CurrentPacketId
                    // with SYNC masked off, so always strip SYNC here
                    let ack_id = packet_id & !SYNC_PACKET_ID;
                    self.send_control(PACKET_TYPE_KD_ACKNOWLEDGE, ack_id)?;
                    if ack_id != self.remote_packet_id {
                        kd_trace!(
                            "kd: recv_data: skip stale type={} id={:#x} (expected {:#x}), ACKed",
                            packet_type,
                            packet_id,
                            self.remote_packet_id
                        );
                        continue;
                    }
                    kd_trace!(
                        "kd: recv_data: accepted type={} id={:#x} len={}",
                        packet_type,
                        packet_id,
                        payload.len()
                    );
                    self.remote_packet_id ^= 1;
                    self.remote_packet_id &= !SYNC_PACKET_ID;
                    return Ok(DataPacket {
                        packet_type,
                        payload,
                    });
                }
                Received::Reset => {
                    kd_trace!("kd: recv_data: got RESET, resyncing ids");
                    // Kernel echoed RESET (or initiated one). Resync our ids
                    // and keep listening; don't echo (kernel's RESET handler
                    // also echoes, so we'd ping-pong)
                    self.current_packet_id = INITIAL_PACKET_ID;
                    self.remote_packet_id = INITIAL_PACKET_ID;
                    self.queued_data.clear();
                }
                Received::Ack { .. } | Received::Resend => {
                    // stray control packet; keep waiting for data
                }
            }
        }
    }

    fn send_control(&mut self, packet_type: u16, packet_id: u32) -> Result<()> {
        let header = Header {
            leader: CONTROL_PACKET_LEADER,
            packet_type,
            byte_count: 0,
            packet_id,
            checksum: 0,
        };
        self.transport.write_all(&header.encode())?;
        self.transport.flush()?;
        Ok(())
    }

    fn recv_any(&mut self) -> Result<Received> {
        loop {
            let leader = self.read_packet_leader()?;
            let mut tail = [0u8; HEADER_SIZE - 4];
            self.transport.read_exact(&mut tail)?;

            let mut header_buf = [0u8; HEADER_SIZE];
            header_buf[0..4].copy_from_slice(&leader.to_le_bytes());
            header_buf[4..].copy_from_slice(&tail);
            let header = Header::decode(&header_buf);

            if header.leader == CONTROL_PACKET_LEADER {
                return Ok(match header.packet_type {
                    PACKET_TYPE_KD_ACKNOWLEDGE => Received::Ack {
                        packet_id: header.packet_id,
                    },
                    PACKET_TYPE_KD_RESEND => Received::Resend,
                    PACKET_TYPE_KD_RESET => Received::Reset,
                    other => {
                        return Err(Error::Kd(format!(
                            "unknown control packet type {:#x}",
                            other
                        )));
                    }
                });
            }

            // data packet
            let len = header.byte_count as usize;
            if len > PACKET_MAX_SIZE {
                return Err(Error::Kd(format!(
                    "inbound packet too large: {} bytes",
                    len
                )));
            }

            let mut payload = vec![0u8; len];
            self.transport.read_exact(&mut payload)?;
            let mut trailer = [0u8; 1];
            self.transport.read_exact(&mut trailer)?;
            if trailer[0] != PACKET_TRAILING_BYTE {
                self.send_control(PACKET_TYPE_KD_RESEND, 0)?;
                continue;
            }

            let computed = checksum(&payload);
            if computed != header.checksum {
                self.send_control(PACKET_TYPE_KD_RESEND, 0)?;
                continue;
            }

            return Ok(Received::Data {
                packet_type: header.packet_type,
                packet_id: header.packet_id,
                payload,
            });
        }
    }

    /// Synchronise to a packet leader: read bytes until we see four identical
    /// leader bytes in a row. Mirrors `KdpReceivePacketLeader` in ReactOS
    fn read_packet_leader(&mut self) -> Result<u32> {
        // Per-byte trace is its own env var; the packet-level NTOSEYE_KD_TRACE
        // would drown in raw byte noise from kernel retransmissions
        loop {
            let mut byte = [0u8; 1];
            match self.transport.read_exact(&mut byte) {
                Ok(()) => {}
                Err(e) => {
                    kd_trace!("kd-trace: read error: {e}");
                    return Err(e.into());
                }
            }
            kd_trace_bytes!("kd-trace: <- {:02x}\n", byte[0]);
            if byte[0] != DATA_LEADER_BYTE && byte[0] != CONTROL_LEADER_BYTE {
                continue;
            }
            let mut want = byte[0];
            let mut matched = 1usize;
            while matched < 4 {
                self.transport.read_exact(&mut byte)?;
                kd_trace_bytes!("kd-trace: <- {:02x}\n", byte[0]);
                if byte[0] == want {
                    matched += 1;
                } else if byte[0] == DATA_LEADER_BYTE || byte[0] == CONTROL_LEADER_BYTE {
                    // start over with the new candidate
                    want = byte[0];
                    matched = 1;
                } else {
                    matched = 0;
                    break;
                }
            }
            if matched == 4 {
                return Ok(u32::from_le_bytes([want; 4]));
            }
        }
    }
}

#[derive(Debug)]
enum Received {
    Ack {
        packet_id: u32,
    },
    Resend,
    Reset,
    Data {
        packet_type: u16,
        packet_id: u32,
        payload: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

    /// In-memory transport: reads from a queued buffer, writes to a captured
    /// buffer. Lets us hand-assemble byte sequences and verify what our code
    /// emits
    struct Loopback {
        inbound: Cursor<Vec<u8>>,
        outbound: Vec<u8>,
    }

    impl Loopback {
        fn new(inbound: Vec<u8>) -> Self {
            Self {
                inbound: Cursor::new(inbound),
                outbound: Vec::new(),
            }
        }
    }

    impl Read for Loopback {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inbound.read(buf)
        }
    }

    impl Write for Loopback {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbound.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn ack_for(id: u32) -> Vec<u8> {
        let h = Header {
            leader: CONTROL_PACKET_LEADER,
            packet_type: PACKET_TYPE_KD_ACKNOWLEDGE,
            byte_count: 0,
            packet_id: id,
            checksum: 0,
        };
        h.encode().to_vec()
    }

    fn data_packet(packet_type: u16, packet_id: u32, payload: &[u8]) -> Vec<u8> {
        let h = Header {
            leader: DATA_PACKET_LEADER,
            packet_type,
            byte_count: payload.len() as u16,
            packet_id,
            checksum: checksum(payload),
        };
        let mut out = h.encode().to_vec();
        out.extend_from_slice(payload);
        out.push(PACKET_TRAILING_BYTE);
        out
    }

    #[test]
    fn checksum_sums_bytes() {
        assert_eq!(checksum(&[1, 2, 3, 4]), 10);
        assert_eq!(checksum(&[0xff; 4]), 0xff * 4);
        assert_eq!(checksum(&[]), 0);
    }

    #[test]
    fn send_data_writes_header_payload_trailer_and_consumes_ack() {
        let mut framing = KdFraming::new(Loopback::new(ack_for(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
        )));
        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"hello")
            .unwrap();

        let out = &framing.transport.outbound;
        assert_eq!(out.len(), HEADER_SIZE + 5 + 1);
        // leader
        assert_eq!(&out[0..4], &DATA_PACKET_LEADER.to_le_bytes());
        // payload
        assert_eq!(&out[HEADER_SIZE..HEADER_SIZE + 5], b"hello");
        // trailer
        assert_eq!(out[HEADER_SIZE + 5], PACKET_TRAILING_BYTE);
    }

    #[test]
    fn send_data_toggles_packet_id_after_ack() {
        let mut framing = KdFraming::new(Loopback::new(ack_for(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
        )));
        let before = framing.current_packet_id;
        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &[])
            .unwrap();
        let after = framing.current_packet_id;
        assert_eq!(after, (before & !SYNC_PACKET_ID) ^ 1);
    }

    #[test]
    fn recv_data_returns_payload_and_acks() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, INITIAL_PACKET_ID, &payload);
        let mut framing = KdFraming::new(Loopback::new(inbound));

        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.packet_type, PACKET_TYPE_KD_STATE_CHANGE64);
        assert_eq!(pkt.payload, payload);

        // our outbound should be an ACK with the matching id
        let out = &framing.transport.outbound;
        assert_eq!(out.len(), HEADER_SIZE);
        let h = Header::decode(out.as_slice().try_into().unwrap());
        assert_eq!(h.leader, CONTROL_PACKET_LEADER);
        assert_eq!(h.packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
        assert_eq!(h.packet_id, INITIAL_PACKET_ID);
    }

    #[test]
    fn recv_data_skips_garbage_before_leader() {
        let payload = vec![0x01, 0x02];
        let mut inbound = vec![0xAA, 0x55, 0x12, 0x34]; // garbage
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            &payload,
        ));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, payload);
    }

    #[test]
    fn recv_data_resyncs_when_leader_byte_changes_mid_match() {
        let mut inbound = vec![DATA_LEADER_BYTE, DATA_LEADER_BYTE];
        inbound.extend(ack_for(0));
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            b"good",
        ));

        let mut framing = KdFraming::new(Loopback::new(inbound));
        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, b"good");
    }

    #[test]
    fn recv_data_acks_and_skips_unexpected_packet_id() {
        let payload = vec![0xAB];
        let mut inbound = data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID ^ 1, // wrong id, should be ACK'd then ignored
            &payload,
        );
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            b"good",
        ));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, b"good");
        // we should have ACKed both
        assert_eq!(framing.transport.outbound.len(), 2 * HEADER_SIZE);
    }

    #[test]
    fn recv_data_requests_resend_after_bad_checksum() {
        let payload = vec![0x11, 0x22];
        let mut inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, INITIAL_PACKET_ID, &payload);
        // corrupt the checksum field
        inbound[12] = inbound[12].wrapping_add(1);
        inbound.extend(data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            b"resent",
        ));

        let mut framing = KdFraming::new(Loopback::new(inbound));
        let pkt = framing.recv_data().unwrap();
        assert_eq!(pkt.payload, b"resent");

        let out = &framing.transport.outbound;
        assert_eq!(out.len(), 2 * HEADER_SIZE);
        let resend = Header::decode(out[0..HEADER_SIZE].try_into().unwrap());
        assert_eq!(resend.packet_type, PACKET_TYPE_KD_RESEND);
        let ack = Header::decode(out[HEADER_SIZE..2 * HEADER_SIZE].try_into().unwrap());
        assert_eq!(ack.packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
    }

    #[test]
    fn send_breakin_writes_one_breakin_byte() {
        let mut framing = KdFraming::new(Loopback::new(Vec::new()));
        framing.send_breakin().unwrap();
        assert_eq!(framing.transport.outbound, vec![BREAKIN_BYTE]);
    }

    #[test]
    fn send_data_retries_on_resend() {
        // first response is RESEND, second is the expected ACK
        let resend = {
            let h = Header {
                leader: CONTROL_PACKET_LEADER,
                packet_type: PACKET_TYPE_KD_RESEND,
                byte_count: 0,
                packet_id: 0,
                checksum: 0,
            };
            h.encode().to_vec()
        };
        let mut inbound = resend;
        inbound.extend(ack_for(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
        ));
        let mut framing = KdFraming::new(Loopback::new(inbound));
        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"x")
            .unwrap();
        // We should have written the data packet twice
        let expected_per_attempt = HEADER_SIZE + 1 + 1;
        assert_eq!(framing.transport.outbound.len(), expected_per_attempt * 2);
    }

    #[test]
    fn send_data_queues_fresh_data_received_before_ack() {
        let mut inbound = data_packet(PACKET_TYPE_KD_STATE_CHANGE64, INITIAL_PACKET_ID, b"stop");
        inbound.extend(ack_for(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
        ));
        let mut framing = KdFraming::new(Loopback::new(inbound));

        framing
            .send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"x")
            .unwrap();
        let pkt = framing.recv_data().unwrap();

        assert_eq!(pkt.packet_type, PACKET_TYPE_KD_STATE_CHANGE64);
        assert_eq!(pkt.payload, b"stop");
        assert_eq!(framing.remote_packet_id, INITIAL_PACKET_ID ^ 1);
        // one ACK for the queued inbound data; one ACK was consumed from inbound
        let out = &framing.transport.outbound;
        assert_eq!(out.len(), (HEADER_SIZE + 1 + 1) + HEADER_SIZE);
    }
}
