#!/usr/bin/env python3
"""Host side of picosniff: capture, auto-detect the protocol and decode.

  ./sniff.py run                    capture, auto-detect, then decode live
  ./sniff.py run --detect 20        spend 20 s on detection first
  ./sniff.py run --uart GP2:115200 --uart GP3:115200 --uart GP6:115200
  ./sniff.py analyze cap.bin        re-analyse a saved capture offline
  ./sniff.py vcd cap.bin            export to VCD (open with PulseView/GTKWave)

Channels (v2 firmware; directions as seen from the Zigbee module):
  GP2 = ZB_TX   GP3 = ZB_RX   GP4 = ZB_RTS   GP5 = ZB_CTS
  GP6 = ESP32 UART0 TX       GP7 = ESP32 UART0 RX
Captures from the v1 (4-channel) firmware still load with their old names.
"""
import argparse
import json
import os
import signal
import sys
import time

import numpy as np

CH_NAMES_V1 = ["GP2/PB01", "GP3/PB00", "GP4/PA00", "GP5/ESP_TX"]
CH_NAMES_V2 = ["GP2/ZB_TX", "GP3/ZB_RX", "GP4/ZB_RTS", "GP5/ZB_CTS", "GP6/ESP_TX0", "GP7/ESP_RX0", "GP8/ESP_TXn", "GP9/ESP_RXn"]
CH_NAMES = CH_NAMES_V2
NCH = len(CH_NAMES)
FLOW_CH = {2, 3}          # ZB_RTS / ZB_CTS: active-low UART flow control
HEADER_V1 = b"\xA5\x5APS"
HEADER_V2 = b"\xA5\x5APT"
# Internal event codes: 0..0xFF = new pin state, else one of these.
KEEP = 0x100
OVERFLOW = 0x200


def set_layout(version, nch=None):
    global CH_NAMES, NCH, FLOW_CH
    if version == 1:
        CH_NAMES, FLOW_CH = CH_NAMES_V1, set()
    else:
        CH_NAMES = CH_NAMES_V2[:nch] + [f"GP{2 + i}" for i in range(len(CH_NAMES_V2), nch or 0)]
        FLOW_CH = {2, 3}
    NCH = len(CH_NAMES)
STD_BAUDS = [1200, 2400, 4800, 9600, 14400, 19200, 38400, 57600, 74880, 76800,
             115200, 128000, 230400, 250000, 256000, 460800, 500000, 576000,
             921600, 1000000, 1152000, 1500000, 2000000, 3000000, 4000000]

HERE = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(HERE, "ezsp_ids.json")) as f:
        EZSP_NAMES = {int(k, 16): v for k, v in json.load(f).items()}
except OSError:
    EZSP_NAMES = {}


def log(msg=""):
    try:
        print(msg, flush=True)
    except BrokenPipeError:
        sys.exit(0)


# --------------------------------------------------------------------------
# Stream parsing

class EventParser:
    """Turns the device byte stream into (sample_time, code) tuples."""

    def __init__(self, version=2):
        self.version = version
        self.t = 0
        self.acc = 0
        self.shift = 0
        self.kind = None      # v2: kind of pending event awaiting state byte

    def feed(self, data):
        out = []
        v2 = self.version == 2
        for b in data:
            if self.kind is not None:
                out.append((self.t, b))
                self.kind = None
                continue
            self.acc |= (b & 0x7F) << self.shift
            self.shift += 7
            if b & 0x80:
                continue
            v, self.acc, self.shift = self.acc, 0, 0
            if v2:
                self.t += v >> 2
                k = v & 3
                if k == 0:
                    self.kind = 0
                else:
                    out.append((self.t, KEEP if k == 1 else OVERFLOW))
            else:
                self.t += v
                self.kind = -1
        if not v2:
            return [(t, OVERFLOW if c == 0xF0 else KEEP if c & 0x10 else c & 0x0F) for t, c in out]
        return out


def parse_header(buf):
    """Returns (offset_after_header, rate, version) or None."""
    for hdr, ver, ln in ((HEADER_V2, 2, 10), (HEADER_V1, 1, 8)):
        i = buf.find(hdr)
        if i >= 0 and len(buf) >= i + ln:
            rate = int.from_bytes(buf[i + 4:i + 8], "little")
            set_layout(ver, buf[i + 8] if ver == 2 else None)
            return i, i + ln, rate, ver
    return None


def load_capture(path):
    raw = open(path, "rb").read()
    h = parse_header(raw)
    if not h:
        sys.exit(f"{path}: no picosniff header")
    _, off, rate, ver = h
    return rate, EventParser(ver).feed(raw[off:])


# --------------------------------------------------------------------------
# Device I/O

def find_port():
    from serial.tools import list_ports
    ports = [p.device for p in list_ports.comports() if p.vid == 0x2E8A]
    if not ports:
        sys.exit("No Raspberry Pi Pico found. Is picosniff firmware flashed and USB connected?")
    return ports[0].replace("/dev/tty.", "/dev/cu.")


class Device:
    def __init__(self, port, rate):
        import serial
        self.s = serial.Serial(port, 115200, timeout=0.2)
        self.s.write(b"X")
        time.sleep(0.2)
        self.s.reset_input_buffer()
        self.s.write(b"?")
        info = self.s.readline().decode(errors="replace").strip()
        if not info.startswith("PICOSNIFF"):
            sys.exit(f"Unexpected reply from {port}: {info!r}")
        self.s.write(f"R{rate}\n".encode())
        self.s.readline()
        log(f"[pico] {info} -> rate {rate} Hz on {port}")
        self.s.reset_input_buffer()
        self.s.write(b"S")
        buf = b""
        deadline = time.time() + 3
        while not parse_header(buf):
            buf += self.s.read(64)
            if time.time() > deadline:
                sys.exit("No stream header from Pico")
        start, off, self.rate, self.version = parse_header(buf)
        self.header = buf[start:off]
        self.pending = buf[off:]

    def read(self):
        if self.pending:
            d, self.pending = self.pending, b""
            return d
        return self.s.read(max(1, self.s.in_waiting))

    def close(self):
        try:
            self.s.write(b"X")
            self.s.close()
        except Exception:
            pass


# --------------------------------------------------------------------------
# Low level decoders. All get tick(t) for every event (time advances),
# init(t, state) on the first/resynced state and change(t, prev, state).

class Decoder:
    def reset(self):
        pass

    def tick(self, t):
        pass

    def init(self, t, st):
        pass

    def change(self, t, prev, st):
        pass


class UartDecoder(Decoder):
    def __init__(self, ch, rate, baud, sink, idle=1):
        self.ch, self.rate, self.baud, self.sink = ch, rate, baud, sink
        self.bit = rate / baud
        self.idle = idle
        self.reset()

    def reset(self):
        self.level = None
        self.start = None
        self.edges = []

    def init(self, t, st):
        self.level = (st >> self.ch) & 1

    def tick(self, t):
        if self.start is not None and t > self.start + 9.5 * self.bit:
            self._finish()

    def change(self, t, prev, st):
        lvl = (st >> self.ch) & 1
        if self.level is None:
            self.level = lvl
            return
        if lvl == self.level:
            return
        self.level = lvl
        if self.start is None:
            if lvl != self.idle:
                self.start, self.edges = t, []
        else:
            self.edges.append(t)

    def _level_at(self, x):
        lvl = 1 - self.idle
        for e in self.edges:
            if e > x:
                break
            lvl ^= 1
        return lvl

    def _finish(self):
        s, b = self.start, self.bit
        v = 0
        for i in range(8):
            if self._level_at(s + (1.5 + i) * b) == self.idle:
                v |= 1 << i
        err = self._level_at(s + 9.5 * b) != self.idle
        self.start = None
        self.sink(self.ch, s / self.rate, v, err)


class SpiDecoder(Decoder):
    def __init__(self, clk, datas, sample_level, rate, gap, sink, cs=None):
        self.clk, self.datas, self.sample_level = clk, datas, sample_level
        self.rate, self.gap, self.sink, self.cs = rate, gap, sink, cs
        self.reset()

    def reset(self):
        self.bits = {d: [] for d in self.datas}
        self.bytes = {d: [] for d in self.datas}
        self.last_clk = None
        self.burst_t = None

    def _flush(self):
        if self.burst_t is None:
            return
        out = {}
        for d in self.datas:
            bs = self.bytes[d][:]
            if self.bits[d]:
                bs.append(("partial", len(self.bits[d]),
                           int("".join(map(str, self.bits[d])), 2)))
            out[d] = bs
        self.sink(self.burst_t / self.rate, out)
        self.reset()

    def tick(self, t):
        if self.last_clk is not None and t - self.last_clk > self.gap:
            self._flush()

    def change(self, t, prev, st):
        if self.cs is not None and ((prev ^ st) >> self.cs) & 1:
            self._flush()
            return
        if not ((prev ^ st) >> self.clk) & 1:
            return
        if self.cs is not None and (st >> self.cs) & 1:
            return          # CS inactive (assumes active low)
        self.last_clk = t
        if ((st >> self.clk) & 1) != self.sample_level:
            return
        if self.burst_t is None:
            self.burst_t = t
        for d in self.datas:
            self.bits[d].append((prev >> d) & 1)
            if len(self.bits[d]) == 8:
                self.bytes[d].append(int("".join(map(str, self.bits[d])), 2))
                self.bits[d] = []


class I2cDecoder(Decoder):
    def __init__(self, scl, sda, rate, sink):
        self.scl, self.sda, self.rate, self.sink = scl, sda, rate, sink
        self.reset()

    def reset(self):
        self.active = False
        self.bits = []
        self.bytes = []
        self.t0 = 0

    def change(self, t, prev, st):
        scl_p, sda_p = (prev >> self.scl) & 1, (prev >> self.sda) & 1
        scl, sda = (st >> self.scl) & 1, (st >> self.sda) & 1
        if scl_p and scl and sda_p and not sda:          # START / repeated START
            if self.active and self.bytes:
                self.sink(self.t0 / self.rate, self.bytes, "Sr")
            self.active, self.bits, self.bytes, self.t0 = True, [], [], t
        elif scl_p and scl and not sda_p and sda:        # STOP
            if self.active:
                self.sink(self.t0 / self.rate, self.bytes, "P")
            self.reset()
        elif self.active and not scl_p and scl:          # SCL rising: sample
            self.bits.append(sda)
            if len(self.bits) == 9:
                v = int("".join(map(str, self.bits[:8])), 2)
                self.bytes.append((v, "A" if self.bits[8] == 0 else "N"))
                self.bits = []


class Dispatcher:
    def __init__(self, decoders):
        self.decoders = decoders
        self.prev = None

    def event(self, t, code):
        if code == OVERFLOW:
            log(f"!! Pico overflow at {t:,} samples - data lost, lower --rate")
            for d in self.decoders:
                d.reset()
            self.prev = None
            return
        for d in self.decoders:
            d.tick(t)
        if code == KEEP:
            return
        st = code
        if self.prev is None:
            for d in self.decoders:
                d.init(t, st)
        else:
            for d in self.decoders:
                d.change(t, self.prev, st)
        self.prev = st


# --------------------------------------------------------------------------
# Byte stream protocol layers (on top of UART)

def crc_ccitt(data, crc=0xFFFF):
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def crc_x25(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def ash_randomize(data):
    out, r = bytearray(), 0x42
    for b in data:
        out.append(b ^ r)
        r = (r >> 1) ^ 0xB8 if r & 1 else r >> 1
    return bytes(out)


EZSP_STATUS = {0x00: "SUCCESS", 0x43: "SECURITY_KEY_ALREADY_SET", 0x44: "SECURITY_TYPE_INVALID",
               0x45: "SECURITY_PARAMETERS_INVALID", 0x46: "SECURITY_PARAMETERS_ALREADY_SET",
               0x47: "SECURITY_KEY_NOT_SET", 0x48: "SECURITY_PARAMETERS_NOT_SET"}
_last_get_value = {}      # seq -> valueId of a pending getValue command

RST_CODES = {0x00: "unknown", 0x01: "external", 0x02: "power-on", 0x03: "watchdog",
             0x06: "assert", 0x09: "bootloader", 0x0B: "software"}


def ezsp_kind(fc):
    if not fc & 0x80:
        return "CMD"
    return {1: "SYNC-CB", 2: "ASYNC-CB"}.get((fc >> 3) & 3, "RSP")


def ezsp_secure_describe(d):
    """Frame-control high byte bit 7 (securityEnabled, UG600 table 3-9): the
    frame ID and parameters are encrypted. Layout after the 3-byte header, as
    observed on the Home Mini (not documented by Silicon Labs):
      u8 ?(0x00) | 8-byte per-direction session id | u32 LE frame counter |
      u8 security level (5 = ENC-MIC-32) | ciphertext | 4-byte MIC"""
    seq, fc, sec = d[0], d[1], d[3:]
    kind = ezsp_kind(fc)
    if len(sec) < 18:
        return f"EZSP[secure] seq={seq:3d} {kind:8s} short {sec.hex(' ')}"
    ctr = int.from_bytes(sec[9:13], "little")
    ct, mic = sec[14:-4], sec[-4:]
    pad = " pad" if d[2] & 0x40 else ""
    return (f"EZSP[secure{pad}] seq={seq:3d} {kind:8s} ctr={ctr:<6d} sid={sec[1:9].hex()} "
            f"lvl={sec[13]} enc[{len(ct):3d}]={ct.hex()} mic={mic.hex()}")


def ezsp_describe(d):
    if len(d) < 3:
        return f"EZSP? {d.hex(' ')}"
    seq, fc = d[0], d[1]
    if len(d) >= 3 and d[2] & 0x3F == 0x01 and d[2] & 0x80:   # v8+ with EZSP security
        return ezsp_secure_describe(d)
    if len(d) >= 5 and d[2] & 0x3F == 0x01:      # v8+ frame format
        fid, params, fmt = d[3] | d[4] << 8, d[5:], "v8+"
    elif d[2] == 0xFF and len(d) >= 5:           # v5-v7 extended legacy
        fid, params, fmt = d[4], d[5:], "ext"
    else:
        fid, params, fmt = d[2], d[3:], "legacy"
    resp = bool(fc & 0x80)
    name = EZSP_NAMES.get(fid, f"id_{fid:#06x}")
    kind = ezsp_kind(fc)
    extra = ""
    if fid == 0xAA and not resp and params:
        _last_get_value[seq] = params[0]
    if fid == 0x00CD and resp and len(params) >= 5:
        st = int.from_bytes(params[1:5], "little")
        extra = (f"  status={EZSP_STATUS.get(params[0], hex(params[0]))} "
                 f"securityType={ {0: 'TEMPORARY', 0x12345678: 'PERMANENT'}.get(st, hex(st)) }")
    elif fid == 0x00CB and not resp and len(params) >= 17:
        extra = f"  securityLevel={params[0]}{' (ENC-MIC-32)' if params[0] == 5 else ''} hostRandom={params[1:17].hex()}"
    elif fid == 0x00CB and resp and len(params) >= 17:
        extra = f"  status={EZSP_STATUS.get(params[0], hex(params[0]))} ncpRandom={params[1:17].hex()}"
    elif fid == 0xAA and resp and len(params) >= 2 and _last_get_value.get(seq) == 0x11 and len(params) >= 9:
        v = params[2:]
        extra = (f"  VERSION_INFO: EmberZNet {v[2]}.{v[3]}.{v[4]}.{v[5]} build {v[0] | v[1] << 8}"
                 f" type={'GA' if v[6] == 0xAA else hex(v[6])}")
    elif fid == 0x00 and not resp and params:
        extra = f"  desiredProtocolVersion={params[0]}"
    elif fid == 0x00 and resp and len(params) >= 4:
        sv = params[2] | params[3] << 8
        extra = (f"  protocolVersion={params[0]} stackType={params[1]} "
                 f"stackVersion={sv >> 12}.{(sv >> 8) & 15}.{(sv >> 4) & 15}.{sv & 15}")
    return (f"EZSP[{fmt}] seq={seq:3d} {kind:8s} {name}{extra}"
            + (f"  params={params.hex(' ')}" if params else ""))


class FramedStream:
    """Collects bytes of one UART direction; recognises ASH (EZSP), HDLC-lite
    (Spinel/OpenThread), or falls back to text / hex dumps."""

    def __init__(self, name, show_raw):
        self.name = name
        self.show_raw = show_raw
        self.buf = bytearray()
        self.esc = False
        self.t0 = None
        self.line = bytearray()
        self.line_t = None
        self.last_t = 0
        self.flags = 0
        self.stats = {"ash": 0, "secure": 0, "hdlc": 0, "bad": 0, "bytes": 0, "text": 0}

    def _out(self, t, msg):
        log(f"{t:12.6f}  {self.name:<11} {msg}")

    def byte(self, t, b, err):
        self.stats["bytes"] += 1
        if self.show_raw:
            self._out(t, f"raw {b:02x}{' FRAMING-ERR' if err else ''}")
        # text heuristic (ESP32 console etc.)
        if 0x20 <= b < 0x7F or b in (9, 10, 13):
            if not self.line:
                self.line_t = t
            if b == 10:
                self._text_line()
            elif b != 13:
                self.line.append(b)
        else:
            self._text_line()
        # framing
        if self.t0 is None:
            self.t0 = t
        if b == 0x7E:
            self.flags += 1
            if self.buf:
                self._frame(self.t0, bytes(self.buf))
            self.buf.clear()
            self.esc = False
            self.t0 = None
        elif b == 0x1A:
            if self.flags:
                self._out(t, "ASH CANCEL (0x1A)")
            self.buf.clear()
            self.t0 = None
        elif b in (0x11, 0x13) and self.flags:
            self._out(t, "XON" if b == 0x11 else "XOFF")
        elif b == 0x7D:
            self.esc = True
        else:
            if self.esc:
                b ^= 0x20
                self.esc = False
            self.buf.append(b)
            if len(self.buf) > 600:           # not a framed protocol
                self.buf.clear()
                self.t0 = None

    def _text_line(self):
        if len(self.line) >= 4 and self.flags == 0:
            self.stats["text"] += 1
            self._out(self.line_t, "TXT " + self.line.decode(errors="replace"))
        elif self.line and self.flags == 0 and len(self.line) < 4:
            pass
        self.line.clear()

    def _frame(self, t, f):
        if len(f) >= 3 and crc_ccitt(f[:-2]) == (f[-2] << 8 | f[-1]):
            self.stats["ash"] += 1
            if f[0] & 0x80 == 0:
                d = ash_randomize(f[1:-2])
                if len(d) >= 3 and d[2] & 0xBF == 0x81:
                    self.stats["secure"] += 1
            self._out(t, self._ash(f[0], f[1:-2]))
        elif len(f) >= 3 and crc_x25(f[:-2]) == (f[-2] | f[-1] << 8):
            self.stats["hdlc"] += 1
            self._out(t, f"HDLC-lite (Spinel?) {f[:-2].hex(' ')}")
        else:
            self.stats["bad"] += 1
            self._out(t, f"frame(bad crc/unknown) {f.hex(' ')}")

    def _ash(self, c, data):
        if c & 0x80 == 0:
            frm, retx, ack = (c >> 4) & 7, (c >> 3) & 1, c & 7
            hdr = f"ASH DATA frm={frm} ack={ack}{' reTx' if retx else ''} | "
            return hdr + ezsp_describe(ash_randomize(data))
        if c & 0xE0 == 0x80:
            return f"ASH ACK  ack={c & 7}{' nRdy' if c & 8 else ''}"
        if c & 0xE0 == 0xA0:
            return f"ASH NAK  ack={c & 7}{' nRdy' if c & 8 else ''}"
        if c == 0xC0:
            return "ASH RST"
        if c == 0xC1 and len(data) >= 2:
            return f"ASH RSTACK version={data[0]} reset={RST_CODES.get(data[1], hex(data[1]))}"
        if c == 0xC2 and len(data) >= 2:
            return f"ASH ERROR version={data[0]} code={data[1]:#04x}"
        return f"ASH ctrl={c:#04x} {data.hex(' ')}"

    def flush(self):
        self._text_line()


# --------------------------------------------------------------------------
# Auto-detection

def channel_edges(times, states, ch):
    bits = (states >> ch) & 1
    idx = np.nonzero(np.diff(bits))[0] + 1
    return times[idx], bits[idx], int(bits[0])


def to_arrays(events):
    """Returns times/states (edges only) and overflow times."""
    t, s, ovf = [], [], []
    for tt, c in events:
        if c == OVERFLOW:
            ovf.append(tt)
        elif c != KEEP:
            t.append(tt)
            s.append(c)
    return np.array(t, dtype=np.int64), np.array(s, dtype=np.int64), ovf


def uart_fit(widths, bit):
    if bit < 3:
        return 0.0, 0
    r = widths / bit
    k = np.rint(r)
    inframe = (k >= 1) & (k <= 9)
    n = int(inframe.sum())
    if n < 20:
        return 0.0, n
    tol = np.maximum(1.5, 0.18 * bit)
    ok = np.abs(widths[inframe] - k[inframe] * bit) <= tol
    ones = np.sum(k[inframe] == 1) / n
    if ones < 0.05 or len(np.unique(k[inframe])) < 3:   # real data has varied runs
        return 0.0, n
    return float(ok.mean()), n


def guess_baud(widths, rate):
    widths = widths[widths >= 2].astype(float)
    if len(widths) < 20:
        return None, 0
    best = None
    for b in STD_BAUDS:           # lowest fitting baud wins (multiples also fit)
        score, n = uart_fit(widths, rate / b)
        if score > 0.93:
            best = (b, score)
            break
    if best:
        return best
    m = np.percentile(widths, 3)
    cluster = widths[(widths >= m) & (widths <= 1.4 * m)]
    bit = float(np.median(cluster))
    score, _ = uart_fit(widths, bit)
    if score > 0.9:
        return int(round(rate / bit)), score
    return None, score


def detect(events, rate, report=True):
    times, states, ovf = to_arrays(events)
    if len(times) == 0:
        log("No data at all.")
        return {}
    dur = (events[-1][0] - events[0][0]) / rate
    log(f"\n==== Detection report ({dur:.2f} s @ {rate/1e6:g} MHz, {len(times)} edges"
        f"{', %d OVERFLOWS' % len(ovf) if ovf else ''}) ====")
    info = {}
    for ch in range(NCH):
        et, eb, first = channel_edges(times, states, ch)
        w = np.diff(et)
        # time spent high -> idle level
        levels = (states >> ch) & 1
        seg = np.diff(np.append(times, events[-1][0]))
        high = seg[levels == 1].sum() / max(1, seg.sum())
        idle = 1 if high > 0.5 else 0
        d = {"edges": len(et), "idle": idle, "high_frac": high, "widths": w}
        if len(w) >= 20:
            wf = w[w >= 2]
            d["wmin"] = int(np.percentile(wf, 1)) if len(wf) else 0
            d["wmed"] = int(np.median(wf)) if len(wf) else 0
            # Non-idle pulses (start bit + data bits) are whole bit multiples;
            # idle-level pulses include inter-byte gaps, so ignore those.
            active = w[eb[:-1] != idle]
            d["baud"], d["uart_score"] = guess_baud(active, rate)
        info[ch] = d
        if report:
            line = f"  {CH_NAMES[ch]:<11}: {len(et):7d} edges, idle={'HIGH' if idle else 'LOW '} ({high*100:5.1f}% high)"
            if "wmin" in d:
                line += f", min pulse {d['wmin']/rate*1e6:8.2f} us, median {d['wmed']/rate*1e6:8.2f} us"
            if d.get("baud"):
                line += f"  -> UART-like ~{d['baud']} baud (fit {d['uart_score']:.2f})"
            log(line)

    # Validate UART candidates by decoding
    config = {"uart": {}, "spi": None, "i2c": None, "rate": rate}
    for ch, d in info.items():
        if d.get("baud"):
            res, vals = [], set()
            dec = UartDecoder(ch, rate, d["baud"],
                              lambda c, t, v, e: (res.append(e), vals.add(v)), d["idle"])
            disp = Dispatcher([dec])
            for tt, c in events:
                disp.event(tt, c)
            dec.tick(1 << 62)
            if res:
                ferr = sum(res) / len(res)
                if report:
                    log(f"  {CH_NAMES[ch]:<11}: UART decode {len(res)} bytes, {ferr*100:.1f}% framing errors")
                if ferr < 0.1 and len(vals) >= 3:
                    config["uart"][ch] = d["baud"]
                    if d["idle"] == 0:
                        config.setdefault("uart_inverted", []).append(ch)

    # Clock-like channels among the rest
    rest = [c for c in range(NCH) if c not in config["uart"] and info[c]["edges"] >= 32]
    clocks = []
    for ch in rest:
        w = info[ch]["widths"].astype(float)
        m = np.median(w)
        inburst = w[w <= 4 * m]          # drop gaps between bursts
        regular = np.mean((inburst >= 0.75 * m) & (inburst <= 1.33 * m)) if len(inburst) else 0
        info[ch]["regular"] = regular
        if regular > 0.85:
            clocks.append((info[ch]["edges"], ch, m))
    if clocks:
        clocks.sort(reverse=True)
        _, clk, half = clocks[0]
        others = [c for c in rest if c != clk]
        freq = rate / (2 * half)
        if report:
            log(f"  {CH_NAMES[clk]} looks like a CLOCK (~{freq/1e3:.1f} kHz, idle {'HIGH' if info[clk]['idle'] else 'LOW'})")
        # I2C: start condition = other line falls while clock is high
        i2c_sda, starts = None, 0
        clkbits = (states >> clk) & 1
        for c in others:
            b = (states >> c) & 1
            fall = np.nonzero((b[1:] == 0) & (b[:-1] == 1))[0] + 1
            s = int(np.sum((clkbits[fall] == 1) & (clkbits[fall - 1] == 1)))
            if s > starts:
                i2c_sda, starts = c, s
        n_bursts = int(np.sum(info[clk]["widths"] > 8 * half)) + 1
        if info[clk]["idle"] == 1 and i2c_sda is not None and starts >= max(1, n_bursts // 2) \
                and info[i2c_sda]["idle"] == 1:
            config["i2c"] = (clk, i2c_sda)
            if report:
                log(f"  -> I2C: SCL={CH_NAMES[clk]} SDA={CH_NAMES[i2c_sda]} ({starts} START conditions)")
        else:
            # data lines change on the shift edge; sample on the other one
            et, eb, _ = channel_edges(times, states, clk)
            votes = []
            cs = None
            datas = []
            for c in others:
                dt, _, _ = channel_edges(times, states, c)
                if len(dt) == 0:
                    continue
                if len(dt) < n_bursts * 3:
                    # CS only if it is low (asserted) while the clock runs
                    clk_idx = np.searchsorted(times, et)
                    low = np.mean(((states[np.minimum(clk_idx, len(states) - 1)] >> c) & 1) == 0)
                    if cs is None and low > 0.95:
                        cs = c
                    continue
                datas.append(c)
                j = np.searchsorted(et, dt, side="right") - 1
                j = j[j >= 0]
                votes.extend(eb[j].tolist())
            shift_level = int(round(np.mean(votes))) if votes else 0
            sample_level = 1 - shift_level
            config["spi"] = {"clk": clk, "datas": datas, "sample_level": sample_level,
                             "gap": int(half * 16), "cs": cs}
            if report:
                mode = {(0, 1): 0, (0, 0): 1, (1, 0): 2, (1, 1): 3}[(info[clk]["idle"], sample_level)]
                log(f"  -> SPI-like: SCK={CH_NAMES[clk]} data={[CH_NAMES[c] for c in datas]} "
                    f"sample on {'rising' if sample_level else 'falling'} edge (mode {mode})"
                    + (f", CS/strobe={CH_NAMES[cs]}" if cs is not None else ""))

    # Rarely toggling lines (reset / irq / wake / flow control)
    used = set(config["uart"])
    if config["spi"]:
        used |= {config["spi"]["clk"], *config["spi"]["datas"]}
        if config["spi"]["cs"] is not None:
            used.add(config["spi"]["cs"])
    if config["i2c"]:
        used |= set(config["i2c"])
    aux = [c for c in range(NCH) if c not in used and 0 < info[c]["edges"]]
    # Lines carrying the same waveform (within 1 us) are reported once.
    same = {}
    seg = np.diff(np.append(times, events[-1][0]))
    for i, a in enumerate(aux):
        for b in aux[i + 1:]:
            if b in same:
                continue
            differ = (((states >> a) ^ (states >> b)) & 1).astype(bool)
            if info[a]["edges"] == info[b]["edges"] and (not differ.any() or seg[differ].max() <= rate // 1000000 + 1):
                same[b] = a
    config["aux"] = [c for c in aux if c not in same]
    config["aux_idle"] = {c: info[c]["idle"] for c in aux}
    config["aux_same"] = same
    for c in config["aux"]:
        if report:
            twins = [b for b, a in same.items() if a == c]
            et, eb, _ = channel_edges(times, states, c)
            idle = info[c]["idle"]
            w = np.diff(et)[eb[:-1] != idle] / rate * 1e6
            name = "+".join(CH_NAMES[x] for x in [c] + twins)
            log(f"  {name}: {len(et)} transitions, idle {'HIGH' if idle else 'LOW'}, not a serial data line.")
            if twins:
                log(f"      NOTE: {', '.join(CH_NAMES[x] for x in twins)} identical to {CH_NAMES[c]} "
                    f"(max skew <1 us): shorted, or driven together.")
            if len(w):
                vals, cnt = np.unique(np.round(w, 0), return_counts=True)
                top = sorted(zip(cnt, vals), reverse=True)[:6]
                log(f"      active pulses: n={len(w)}, min {w.min():.1f} us, median {np.median(w):.1f} us, "
                    f"max {w.max():.1f} us; most common: "
                    + ", ".join(f"{v:.0f}us x{n}" for n, v in top))
                if c in FLOW_CH:
                    log("      UART flow control (active LOW = ready); pulses above are "
                        f"'{'not ready' if idle == 0 else 'ready'}' periods.")
                elif 100 < np.median(w) < 6000 and w.max() < 6000:
                    log("      pulse lengths match 802.15.4 air-time (32 us/byte, max frame 4.26 ms): "
                        "looks like radio activity / PTA coexistence (REQUEST/PRIORITY/GRANT).")
    if report:
        for c in range(NCH):
            if info[c]["edges"] == 0:
                log(f"  {CH_NAMES[c]}: no activity (stuck {'HIGH' if info[c]['idle'] else 'LOW'})")
        if not config["uart"] and not config["spi"] and not config["i2c"]:
            log("  No serial data (UART/SPI/I2C) on these pins. Power-cycle the Home Mini during "
                "capture, or move probes to other pads; `vcd` exports for PulseView.")
        log("=" * 60 + "\n")
    return config


# --------------------------------------------------------------------------
# Building decoders from a config

class AuxWatcher(Decoder):
    """Prints one line per pulse on non-data lines."""

    def __init__(self, chs, rate, twins=None):
        self.chs, self.rate = chs, rate
        self.names = {c: "+".join(CH_NAMES[x] for x in [c] + [b for b, a in (twins or {}).items() if a == c])
                      for c in chs}
        self.reset()

    def reset(self):
        self.idle = getattr(self, "idle", {})
        self.t0 = {}
        self.runs = {}

    def init(self, t, st):
        for c in self.chs:
            self.idle.setdefault(c, (st >> c) & 1)

    def change(self, t, prev, st):
        for c in self.chs:
            if not ((prev ^ st) >> c) & 1:
                continue
            lvl = (st >> c) & 1
            if lvl != self.idle.get(c, 1 - lvl):
                self.t0[c] = t
            elif c in self.t0:
                self._pulse(c, self.t0.pop(c), t, lvl)

    def _pulse(self, c, t0, t1, lvl):
        """Prints a pulse, folding runs of similar periodic pulses into one line."""
        w = t1 - t0
        run = self.runs.get(c)
        if run:
            period = t0 - run["last"]
            similar = abs(w - run["w"]) <= 0.2 * run["w"] and \
                (run["period"] is None or abs(period - run["period"]) <= 0.1 * run["period"])
            if similar and period < 0.2 * self.rate:
                run.update(n=run["n"] + 1, last=t0, period=period if run["period"] is None else run["period"])
                return
            self._end_run(c)
        log(f"{t0/self.rate:12.6f}  {self.names[c]:<11} {'HIGH' if not lvl else 'LOW'} pulse {w/self.rate*1e6:9.1f} us")
        self.runs[c] = {"w": w, "last": t0, "period": None, "n": 1, "start": t0}

    def _end_run(self, c):
        run = self.runs.pop(c, None)
        if run and run["n"] > 1:
            log(f"{run['last']/self.rate:12.6f}  {self.names[c]:<11} ...repeated {run['n']} times every "
                f"{run['period']/self.rate*1e3:.1f} ms since {run['start']/self.rate:.6f}")

    def tick(self, t):
        for c, run in list(self.runs.items()):
            if run["period"] and t - run["last"] > 3 * run["period"]:
                self._end_run(c)


def build_decoders(config, show_raw=False):
    rate = config["rate"]
    decs = []
    streams = {}
    for ch, baud in config["uart"].items():
        fs = FramedStream(CH_NAMES[ch], show_raw)
        streams[ch] = fs
        idle = 0 if ch in config.get("uart_inverted", []) else 1
        decs.append(UartDecoder(ch, rate, baud, lambda c, t, v, e, fs=fs: fs.byte(t, v, e), idle))
    if config.get("spi"):
        sp = config["spi"]

        def spi_sink(t, out):
            for d, bs in out.items():
                txt = " ".join(f"{b:02x}" if isinstance(b, int) else f"[{b[1]}b:{b[2]:x}]" for b in bs)
                log(f"{t:12.6f}  SPI {CH_NAMES[d]:<11} {txt}")
        decs.append(SpiDecoder(sp["clk"], sp["datas"], sp["sample_level"], rate, sp["gap"],
                               spi_sink, sp["cs"]))
    if config.get("i2c"):
        scl, sda = config["i2c"]

        def i2c_sink(t, bs, end):
            if not bs:
                return
            addr = bs[0][0]
            rest = " ".join(f"{v:02x}{a}" for v, a in bs[1:])
            log(f"{t:12.6f}  I2C addr={addr >> 1:#04x} {'R' if addr & 1 else 'W'} "
                f"{bs[0][1]} | {rest} {end}")
        decs.append(I2cDecoder(scl, sda, rate, i2c_sink))
    if config.get("aux"):
        aw = AuxWatcher(config["aux"], rate, config.get("aux_same"))
        aw.idle.update(config.get("aux_idle", {}))
        decs.append(aw)
    return decs, streams


def summarize(streams):
    for ch, fs in streams.items():
        fs.flush()
        s = fs.stats
        verdict = []
        if s["ash"]:
            verdict.append(f"{s['ash']} valid ASH frames => Silicon Labs EZSP over ASH (UART NCP)")
        if s["secure"]:
            verdict.append(f"{s['secure']} EZSP frames have securityEnabled set => payloads encrypted")
        if s["hdlc"]:
            verdict.append(f"{s['hdlc']} HDLC-lite frames => Spinel/OpenThread-style RCP")
        if s["text"]:
            verdict.append(f"{s['text']} text lines => console/log output")
        if s["bad"]:
            verdict.append(f"{s['bad']} unrecognised 0x7E-delimited frames")
        log(f"  {CH_NAMES[ch]:<11}: {s['bytes']} bytes. " + ("; ".join(verdict) or "unrecognised byte stream (use --raw)"))


def parse_manual(args, rate):
    cfg = {"uart": {}, "spi": None, "i2c": None, "aux": [], "rate": rate}
    for u in args.uart or []:
        gp, baud = u.split(":")
        cfg["uart"][int(gp.upper().lstrip("GP")) - 2] = int(baud)
    cfg["aux"] = [c for c in range(NCH) if c not in cfg["uart"]]
    return cfg


# --------------------------------------------------------------------------
# Commands

def cmd_run(args):
    port = args.port or find_port()
    dev = Device(port, args.rate)
    rate = dev.rate
    out = open(args.output, "wb")
    out.write(dev.header)
    parser = EventParser(dev.version)
    events = []
    cfg = parse_manual(args, rate) if args.uart else None
    disp = None
    stop = []
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    try:
        if cfg is None:
            log(f"[detect] capturing {args.detect} s. Power-cycle / use the Home Mini NOW "
                f"(boot traffic is the most informative)...")
            t_end = time.time() + args.detect
            while time.time() < t_end and not stop:
                d = dev.read()
                out.write(d)
                events.extend(parser.feed(d))
            cfg = detect(events, rate)
            if not (cfg["uart"] or cfg["spi"] or cfg["i2c"]):
                log("Continuing to record raw data; Ctrl-C to stop, then run `analyze` on the file.")
        decs, streams = build_decoders(cfg, args.raw)
        disp = Dispatcher(decs)
        for t, c in events:
            disp.event(t, c)
        log("[live] decoding, Ctrl-C to stop")
        while not stop:
            d = dev.read()
            if not d:
                continue
            out.write(d)
            for t, c in parser.feed(d):
                disp.event(t, c)
    except KeyboardInterrupt:
        pass
    finally:
        dev.close()
        out.close()
    if disp:
        for d in disp.decoders:
            d.tick(1 << 62)
        log("\n==== Summary ====")
        summarize(streams)
    log(f"Raw capture saved to {args.output}")


def cmd_analyze(args):
    rate, events = load_capture(args.file)
    cfg = parse_manual(args, rate) if args.uart else detect(events, rate)
    decs, streams = build_decoders(cfg, args.raw)
    disp = Dispatcher(decs)
    for t, c in events:
        disp.event(t, c)
    for d in decs:
        d.tick(1 << 62)
    log("\n==== Summary ====")
    summarize(streams)


def cmd_vcd(args):
    rate, events = load_capture(args.file)
    path = args.out or os.path.splitext(args.file)[0] + ".vcd"
    ids = "!\"#$%&'()*"
    with open(path, "w") as f:
        # VCD only allows 1/10/100 multipliers, so use 1 ns (or 1 ps) and scale.
        unit, per = ("ns", 10**9) if 10**9 % rate == 0 else ("ps", 10**12)
        f.write(f"$timescale 1 {unit} $end\n$scope module picosniff $end\n")
        for i, n in enumerate(CH_NAMES):
            f.write(f"$var wire 1 {ids[i]} {n.replace('/', '_')} $end\n")
        f.write("$upscope $end\n$enddefinitions $end\n")
        prev = None
        for t, c in events:
            if c in (KEEP, OVERFLOW):
                continue
            st = c
            lines = [f"{(st >> i) & 1}{ids[i]}" for i in range(NCH)
                     if prev is None or ((prev ^ st) >> i) & 1]
            if lines:
                f.write(f"#{t * per // rate}\n" + "\n".join(lines) + "\n")
            prev = st
    log(f"wrote {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="capture + detect + live decode")
    r.add_argument("--port")
    r.add_argument("--rate", type=int, default=4000000,
                   help="sample rate Hz; divisors of 200 MHz are best (default 4 MHz)")
    r.add_argument("--detect", type=float, default=15, help="seconds of capture used for detection")
    r.add_argument("-o", "--output", default=time.strftime("cap_%Y%m%d_%H%M%S.bin"))
    for p in (r, sub.add_parser("analyze", help="analyse a saved capture")):
        p.add_argument("--uart", action="append", help="manual UART, e.g. GP2:115200 (skips detection)")
        p.add_argument("--raw", action="store_true", help="also print every UART byte")
        if p is not r:
            p.add_argument("file")
    v = sub.add_parser("vcd", help="export capture to VCD")
    v.add_argument("file")
    v.add_argument("--out")
    args = ap.parse_args()
    {"run": cmd_run, "analyze": cmd_analyze, "vcd": cmd_vcd}[args.cmd](args)


if __name__ == "__main__":
    main()
