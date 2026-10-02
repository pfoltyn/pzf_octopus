"""Generate synthetic picosniff captures to self-test sniff.py."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sniff import crc_ccitt, ash_randomize, HEADER_V1 as HEADER, HEADER_V2

RATE = 4000000

def varint(n):
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80); n >>= 7
    out.append(n); return out

class Wave:
    def __init__(self): self.changes = []   # (t, ch, level)
    def uart(self, ch, t, data, baud):
        bit = RATE / baud
        for b in data:
            bits = [0] + [(b >> i) & 1 for i in range(8)] + [1]
            for i, v in enumerate(bits):
                self.changes.append((int(t + i * bit), ch, v))
            t += 10 * bit + bit * 0.5
        return t
    def encode(self, init=0xF):
        st, last, out = init, 0, bytearray(HEADER + RATE.to_bytes(4, "little"))
        out += varint(0) + bytes([st])
        for t, ch, v in sorted((int(a), b, c) for a, b, c in self.changes):
            ns = (st & ~(1 << ch)) | (v << ch)
            if ns != st:
                out += varint(t - last) + bytes([ns]); last = t; st = ns
        out += varint(RATE // 20) + bytes([st | 0x10])
        return bytes(out)

    def encode_v2(self, init=0b001111, nch=6):
        st, last = init, 0
        out = bytearray(HEADER_V2 + RATE.to_bytes(4, "little") + bytes([nch, 2]))
        out += varint(0) + bytes([st])
        for t, ch, v in sorted((int(a), b, c) for a, b, c in self.changes):
            ns = (st & ~(1 << ch)) | (v << ch)
            if ns != st:
                out += varint((t - last) << 2) + bytes([ns]); last = t; st = ns
        out += varint((RATE // 20) << 2 | 1)
        return bytes(out)

def stuff(b):
    out = bytearray()
    for x in b:
        if x in (0x7E, 0x7D, 0x11, 0x13, 0x18, 0x1A):
            out += bytes([0x7D, x ^ 0x20])
        else: out.append(x)
    return out

def ash(ctrl, payload=b"", randomize=True):
    body = bytes([ctrl]) + (ash_randomize(payload) if randomize else payload)
    c = crc_ccitt(body)
    return stuff(body + bytes([c >> 8, c & 0xFF])) + b"\x7e"

def ash_mode():
    w = Wave()
    B = 115200
    t = 1000
    t = w.uart(3, t, b"rst:0x1 (POWERON_RESET),boot:0x13\r\nI (312) zb: starting NCP\r\n", B)
    w.changes += [(t, 2, 0), (t + 4000, 2, 1)]       # PA00 reset pulse
    t += 20000
    host, ncp = 0, 1
    t = w.uart(host, t, b"\x1a" + ash(0xC0, randomize=False), B) + 5000
    t = w.uart(ncp, t, ash(0xC1, b"\x02\x02", randomize=False), B) + 5000
    t = w.uart(host, t, ash(0x00, bytes([0, 0, 0, 8])), B) + 5000   # version(8)
    t = w.uart(ncp, t, ash(0x01, bytes([0, 0x80, 0, 8, 2, 0x30, 0x74])), B) + 5000
    t = w.uart(host, t, ash(0x81), B) + 5000
    t = w.uart(host, t, ash(0x11, bytes([1, 0, 1, 0x17, 0, 0x7e, 0x11])), B) + 5000  # networkInit v8
    t = w.uart(ncp, t, ash(0x12, bytes([1, 0x80, 1, 0x17, 0, 0x00])), B) + 5000
    for i in range(30):
        t = w.uart(3, t, f"I ({1000+i}) app: tick {i}\r\n".encode(), B)
    return w.encode()

def spi_mode():
    w = Wave()
    t, half = 1000, 20
    for n in range(40):
        for byte in (0x0A, n, 0x55, 0xC3):
            for i in range(8):
                v = (byte >> (7 - i)) & 1
                w.changes.append((t, 1, v))          # MOSI on GP3, changes on falling edge
                w.changes.append((t + half, 0, 1))  # SCK rising: sample
                w.changes.append((t + 2 * half, 0, 0))
                t += 2 * half
        w.changes += [(t + 100, 2, 0), (t + 300, 2, 1)]   # irq-ish
        t += 5000
    return w.encode(init=0b1000 | 0b0100)

def uart_flow_v2():
    """ZB_TX=0 ZB_RX=1 ZB_RTS=2 ZB_CTS=3 ESP_TX0=4 ESP_RX0=5, 115200 8N1."""
    w = Wave()
    B = 115200
    t = 1000
    t = w.uart(4, t, b"ESP-ROM:esp32 boot\r\nI (320) app: starting zigbee host\r\n", B) + 2000
    host, ncp = 1, 0          # host->NCP is ZB_RX, NCP->host is ZB_TX
    t = w.uart(host, t, b"\x1a" + ash(0xC0, randomize=False), B) + 3000
    w.changes += [(t, 2, 1), (t + 800, 2, 0)]      # NCP briefly not ready
    t += 1500
    t = w.uart(ncp, t, ash(0xC1, b"\x02\x0b", randomize=False), B) + 3000
    t = w.uart(host, t, ash(0x00, bytes([0, 0, 0, 13])), B) + 3000
    t = w.uart(ncp, t, ash(0x01, bytes([0, 0x80, 0, 13, 2, 0x30, 0x74])), B) + 3000
    t = w.uart(host, t, ash(0x81), B) + 3000
    for i in range(10):
        t = w.uart(host, t, ash(((i + 1) & 7) << 4 | ((i + 1) & 7), bytes([i + 1, 0, 1, 0x26, 0])), B) + 2000
        t = w.uart(ncp, t, ash(((i + 1) & 7) << 4 | ((i + 2) & 7),
                              bytes([i + 1, 0x80, 1, 0x26, 0, 1, 2, 3, 4, 5, 6, 7, 8])), B) + 2000
        t = w.uart(4, t, f"I ({400 + i}) zb: eui64 read {i}\r\n".encode(), B) + 1000
    t = w.uart(5, t, b"help\r\n" * 4, B)
    return w.encode_v2(init=0b110011)   # TX/RX/ESP lines idle high, RTS/CTS low


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    open(os.path.join(here, "ash.bin"), "wb").write(ash_mode())
    open(os.path.join(here, "spi.bin"), "wb").write(spi_mode())
    open(os.path.join(here, "uart_flow_v2.bin"), "wb").write(uart_flow_v2())
