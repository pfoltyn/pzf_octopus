#!/usr/bin/env python3
"""sekey: Secure EZSP key tools, ported byte-for-byte from Gecko SDK 4.0
(app/util/secure-ezsp/{aes-mmo.c,hmac.c} and app/util/ezsp/secure-ezsp.c).

The Secure EZSP session IDs are HMAC-AES-MMO(permKey, hostRand || ncpRand), and
we observe them on the wire. So a candidate 16-byte key can be verified offline
against a capture with NO hardware. That turns an ESP32 flash dump into an
automatic key search:

  ./sekey.py selftest                 validate AES-MMO against the Zigbee vector
  ./sekey.py scan dump.bin            search a flash dump for the key (uses the
                                      cap_boot session params baked in below)
  ./sekey.py check <hexkey>           test one candidate key against the capture
  ./sekey.py decrypt cap.bin <hexkey> decrypt the Secure EZSP frames in a capture

Once the key is found, the same crypto (AES-CCM*, nonce = 00|sid8|ctr4|05) lets
us decrypt every captured Secure EZSP frame.
"""
import os
import sys
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

BLOCK = 16
HERE_DIR = os.path.dirname(os.path.abspath(__file__))


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def aes_mmo(data: bytes) -> bytes:
    """AES-MMO (Matyas-Meyer-Oseas) hash, matching emberAesMmoHash*()."""
    H = bytes(BLOCK)
    n = len(data)
    full = n - (n % BLOCK)
    for off in range(0, full, BLOCK):
        blk = data[off:off + BLOCK]
        H = bytes(a ^ b for a, b in zip(_aes_ecb(H, blk), blk))
    rem = data[full:]
    rlen = len(rem)
    temp = bytearray(BLOCK)
    temp[:rlen] = rem
    temp[rlen] = 0x80
    big = (n * 8) > 0xFFFF
    strlen = 7 if big else 3
    if (BLOCK - rlen) < strlen:
        H = bytes(a ^ b for a, b in zip(_aes_ecb(H, bytes(temp)), bytes(temp)))
        temp = bytearray(BLOCK)
    bits = n * 8
    if big:
        temp[BLOCK - 6] = (bits >> 24) & 0xFF
        temp[BLOCK - 5] = (bits >> 16) & 0xFF
        temp[BLOCK - 4] = (bits >> 8) & 0xFF
        temp[BLOCK - 3] = bits & 0xFF
    else:
        temp[BLOCK - 2] = (bits >> 8) & 0xFF
        temp[BLOCK - 1] = bits & 0xFF
    H = bytes(a ^ b for a, b in zip(_aes_ecb(H, bytes(temp)), bytes(temp)))
    return H


def hmac_aes_mmo(key: bytes, data: bytes) -> bytes:
    """HMAC using AES-MMO (emberHmacAesHash): ipad 0x36, opad 0x5C, block 16."""
    ipad = bytes(k ^ 0x36 for k in key)
    inner = aes_mmo(ipad + data)
    opad = bytes(k ^ 0x5C for k in key)
    return aes_mmo(opad + inner)


def session_ids(key: bytes, host_rand: bytes, ncp_rand: bytes):
    """Returns (hostSessionId, ncpSessionId), each 8 bytes."""
    out = hmac_aes_mmo(key, host_rand + ncp_rand)
    return out[:8], out[8:16]


# ---- captured session parameters (from cap_boot.bin) ----
# setSecurityParameters: host random (command) and ncp random (response).
HOST_RAND = bytes.fromhex("41497107175d98b4d0937a632d276f68")
NCP_RAND  = bytes.fromhex("df177beedfac760e98eebd3d87f2ba00")
# session IDs observed in the encrypted frames of that same session.
OBS_HOST_SID = bytes.fromhex("1d29ca22fde7c20a")   # ESP->NCP frames (cap_boot)
OBS_NCP_SID  = bytes.fromhex("3b93a03c6786b523")   # NCP->ESP frames (cap_boot)


def matches(key: bytes) -> bool:
    h, n = session_ids(key, HOST_RAND, NCP_RAND)
    return h == OBS_HOST_SID and n == OBS_NCP_SID


# ---- Secure EZSP frame AES-CCM* decryption ----
# De-randomized secure EZSP frame layout (from secure-ezsp.c):
#   [0]=SEQ [1]=FC_LB [2]=FC_HB(0x81) [3]=authCtl(0) [4:12]=sessionId
#   [12:16]=frameCounter(LE) [16]=secLevel(0x05) [17:19]=encFrameId
#   [19:-4]=encParams  [-4:]=MIC(4)
# CCM*: key = permanent key; nonce(13) = authCtl|sessionId|frameCounter;
# AAD(17) = frame[0:17]; ciphertext+tag = frame[17:]. (M=4 => standard CCM.)

def ccm_decrypt(key: bytes, frame: bytes):
    """Returns decrypted [frameId_lb, frameId_hb, params...] or None if MIC fails."""
    if len(frame) < 17 + 2 + 4:
        return None
    nonce = frame[3:16]          # authCtl(1) + sessionId(8) + frameCounter(4)
    aad = frame[0:17]
    ct_and_tag = frame[17:]      # encFrameId(2) + encParams + MIC(4)
    try:
        return AESCCM(key, tag_length=4).decrypt(nonce, ct_and_tag, aad)
    except Exception:
        return None


def ccm_encrypt(key: bytes, session_id: bytes, counter: int, seq: int,
                plain: bytes, fc_lb: int = 0x80) -> bytes:
    """Build a de-randomized Secure EZSP frame (SEQ..MIC) for transmission.
    plain = frameId(2 LE) + params. session_id/counter are the SENDER's
    (for NCP->host responses, use the ncpSessionId and our own counter).
    fc_lb 0x80 = response bit set; fc_hb 0x81 = secure + extended format."""
    hdr = (bytes([seq & 0xFF, fc_lb & 0xFF, 0x81, 0x00]) + session_id
           + int(counter).to_bytes(4, "little") + bytes([0x05]))
    nonce = hdr[3:16]
    ct = AESCCM(key, tag_length=4).encrypt(nonce, plain, hdr[0:17])
    return hdr + ct


def cmd_selftest():
    # 1) Zigbee published AES-MMO test vector: hash of the 18-byte install code
    #    (16-byte code + 2-byte CRC) yields the derived link key.
    install = bytes.fromhex("83FED3407A939723A5C639B26916D505C3B5")
    expect  = bytes.fromhex("66B6900981E1EE3CA4206B6B861C02BB")
    got = aes_mmo(install)
    ok = got == expect
    print(f"AES-MMO(install code) = {got.hex()}")
    print(f"expected link key     = {expect.hex()}")
    print("AES-MMO self-test:", "PASS" if ok else "FAIL")

    # 2) RFC 3610 CCM Packet Vector #1 (M=8, L=2, 13-byte nonce) validates our
    #    nonce/AAD/tag wiring against standard CCM (Zigbee CCM* == CCM for M>0).
    key = bytes.fromhex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
    nonce = bytes.fromhex("00000003020100A0A1A2A3A4A5")
    aad = bytes.fromhex("0001020304050607")
    ct_tag = bytes.fromhex("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384"
                           "17E8D12CFDF926E0")
    pt = AESCCM(key, tag_length=8).decrypt(nonce, ct_tag, aad)
    ccm_ok = pt == bytes.fromhex("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")
    print("CCM (RFC3610 PV#1) self-test:", "PASS" if ccm_ok else "FAIL")

    # 3) round-trip our exact Secure-EZSP framing with tag_length=4
    k = bytes.fromhex("00112233445566778899aabbccddeeff")
    hdr = bytes([0x00, 0x00, 0x81, 0x00]) + bytes(range(8)) + bytes([1, 0, 0, 0]) + bytes([0x05])
    plain = bytes([0x26, 0x00, 0xde, 0xad, 0xbe, 0xef])   # frameId 0x0026 + params
    nonce = hdr[3:16]
    ct = AESCCM(k, tag_length=4).encrypt(nonce, plain, hdr[0:17])
    frame = hdr + ct
    rt = ccm_decrypt(k, frame)
    rt_ok = rt == plain
    print("CCM* round-trip self-test:", "PASS" if rt_ok else "FAIL")
    return ok and ccm_ok and rt_ok


def cmd_check(hexkey):
    key = bytes.fromhex(hexkey.replace(" ", ""))
    if len(key) != 16:
        sys.exit("key must be 16 bytes")
    h, n = session_ids(key, HOST_RAND, NCP_RAND)
    print(f"derived hostSid={h.hex()} ncpSid={n.hex()}")
    print(f"observed hostSid={OBS_HOST_SID.hex()} ncpSid={OBS_NCP_SID.hex()}")
    print("KEY MATCHES CAPTURE" if matches(key) else "no match")


def cmd_scan(path):
    data = open(path, "rb").read()
    print(f"scanning {len(data)} bytes for the Secure EZSP key "
          f"(oracle: HMAC-AES-MMO(key,rands) == observed session IDs)...")
    for off in range(0, len(data) - 16 + 1):
        if matches(data[off:off + 16]):
            key = data[off:off + 16]
            print(f"\n*** FOUND KEY at offset 0x{off:x}: {key.hex()} ***")
            return
        if off and off % 0x100000 == 0:
            print(f"  ...{off // 0x100000} MB")
    print("key not found (dump may be flash-encrypted, or key stored transformed)")


def cmd_decrypt(capfile, hexkey):
    """Decrypt the Secure EZSP frames in a picosniff capture using the key."""
    key = bytes.fromhex(hexkey.replace(" ", ""))
    if len(key) != 16:
        sys.exit("key must be 16 bytes")
    d = HERE_DIR
    nt = _load(d + "/ncptalk.py", "nt")
    sniff = _load(d + "/sniff.py", "sniff")
    rate, ev = sniff.load_capture(capfile)
    streams = {0: [], 1: []}
    decs = [sniff.UartDecoder(ch, rate, 115200,
            lambda c, t, v, e, ch=ch: streams[ch].append(v)) for ch in (0, 1)]
    disp = sniff.Dispatcher(decs)
    for t, c in ev:
        disp.event(t, c)
    for x in decs:
        x.tick(1 << 62)
    names = getattr(sniff, "EZSP_NAMES", {})
    n_ok = n_fail = 0
    for ch, who in ((1, "ESP->NCP"), (0, "NCP->ESP")):
        rd = nt.AshReader()
        for f in rd.feed(bytes(streams[ch])):
            if not f or f["type"] != "DATA":
                continue
            e = f["ezsp"]
            if len(e) < 3 or not (e[2] & 0x80):     # only securityEnabled frames
                continue
            pt = ccm_decrypt(key, e)
            if pt is None:
                n_fail += 1
                continue
            n_ok += 1
            fid = pt[0] | pt[1] << 8
            nm = names.get(fid, f"id_{fid:#06x}")
            ctr = int.from_bytes(e[12:16], "little")
            print(f"{who}  ctr={ctr:<5d} {nm:<26} {pt[2:].hex(' ')}")
    print(f"\ndecrypted {n_ok} frames, {n_fail} MIC failures"
          + ("  (wrong key?)" if n_fail and not n_ok else ""))


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
    if len(sys.argv) < 2:
        print(__doc__); return
    cmd = sys.argv[1]
    if cmd == "selftest":
        cmd_selftest()
    elif cmd == "check" and len(sys.argv) > 2:
        cmd_check(sys.argv[2])
    elif cmd == "scan" and len(sys.argv) > 2:
        cmd_scan(sys.argv[2])
    elif cmd == "decrypt" and len(sys.argv) > 3:
        cmd_decrypt(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
