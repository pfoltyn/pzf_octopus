# Octopus Home Mini — Zigbee NCP reverse engineering

Reverse engineering of an **Octopus Energy Home Mini** (authorised research on my
own device, educational) to understand the internal ESP32 ↔ Zigbee-module link
and recover the keys that protect the smart-meter HAN traffic.

**Result: full compromise.** The Secure-EZSP UART key, the Zigbee network key,
the trust-center link key and the install code were all extracted. See
[Outcome](#outcome).

---

## 1. The device

Two chips on one board, talking over a 4-wire UART:

| Chip | Role | Notes |
|------|------|-------|
| **Silicon Labs MGM210P22A** (EFR32MG21) | Zigbee **NCP** (network co-processor) | EmberZNet 6.7.9.0 GA build 405, **EZSP v8 only**. Holds all Zigbee/link secrets in NVM3. |
| **Espressif ESP32-WROOM-32E** | **Host** (WiFi/BLE, app logic) | Secure Boot v2 + Flash Encryption on. UART download fused off. |

- **Link:** EZSP over ASH, UART **115200 8N1**, RTS/CTS hardware flow control.
- **Security:** Secure EZSP is enabled (frame-control HB `0x81`, level 5
  `ENC-MIC-32`). Every real command is AES-CCM\* encrypted; the key never
  appears on the wire in normal operation.
- **Meter side:** the Home Mini is a DCC-managed **CAD** (consumer access
  device). It *joins* the meter's HAN and *receives* the network key over the
  air from the comms hub — it does not form the network.

### Key architecture (as discovered)
Every secret lives in the **NCP** (or arrives over the air):
- **Secure-EZSP UART key** — NCP NVM3 token (creator `0x5240`), type TEMPORARY.
  Provisioned once at manufacture when the NCP is blank; the ESP sets it via a
  *plaintext* `setSecurityKey`. Persists across normal factory resets.
- **Install code** — NCP manufacturing token `0x0A`. The ESP reads it; the link
  key is *derived in the NCP* from it (`GET_PRECONFIGURED_KEY_FROM_INSTALL_CODE`).
- **Network key** — delivered by the meter OTA during join, stored in NCP NVM3.

The ESP is a "thin" host: it references NCP-held secrets by flag/token and
transmits none of them in normal operation. That's why passive sniffing and
NCP/ESP impersonation alone yield nothing — see [Avenues](#4-avenues-tried).

---

## 2. The rig

A Raspberry Pi Pico (RP2040) sits on the cut ESP↔NCP UART. Different firmwares
give passive, transparent-bridge, or host-takeover behaviour. Reflash by
1200-baud touch → BOOTSEL (picosniff uses a `'B'` command), then copy the `.uf2`.

### Wiring (MITM / passthru)
Directions are electrical; "mirror in→out" is the transparent bridge.

| Line | ESP side | Pico | NCP side | Pico |
|------|----------|------|----------|------|
| EZSP data (ESP→NCP) | ESP TX | GP9 | NCP RX | GP2 |
| EZSP data (NCP→ESP) | ESP RX | GP8 | NCP TX | GP3 |
| RTS (ESP→NCP)       | ESP RTS | GP11 | NCP RTS-in | GP4 |
| CTS (NCP→ESP)       | ESP CTS | GP14 | NCP CTS-out | GP15 |
| ESP debug console   | ESP U0TXD | GP6 | — | — |

**Gotcha:** `GP8` is the ESP's **GPIO12/MTDI flash-voltage strap**. Driving it
during ESP reset causes an `invalid header` boot loop. The bridge holds GP8
high-Z until 250 ms after the `ets Jul` ROM banner on the GP6 console tap.

### Passive-sniff wiring (`picosniff`, high-Z taps only)
`GP2 ← NCP TX`, `GP3 ← ESP TX`, `GND`. Requires the ESP↔NCP traces intact.

### Firmwares (sources in `firmware/`, prebuilt images in `firmware/prebuilt/`)
| uf2 | dir | what it does |
|-----|-----|--------------|
| `picosniff_gp2-9.uf2` | `sniffer.c` | passive logic sniffer, GP2..GP9, RLE stream over USB |
| `passthru_pico.uf2` | `passthru/` | transparent PIO level-mirror bridge + logs tagged `[dir,byte]` pairs |
| `ncpbridge_ht.uf2` | `ncpbridge/` | host-takeover: USB↔NCP bridge, drives NCP, ESP isolated |
| `fakencp_pico.uf2` | `fakencp/` | raw USB↔ESP-EZSP pipe (impersonate the NCP toward the ESP) |
| `rewrite_v8.uf2` | `rewrite/` | store-and-forward EZSP `version` rewriter (downgrade experiment) |

Build: `cd firmware/<dir> && PICO_SDK_PATH=~/pico-sdk cmake -B build && make -C build`.

---

## 3. Toolchain (Python)

### `sniff.py` — logic-sniffer host
Captures the picosniff stream, auto-detects UART/SPI/I2C, decodes ASH/EZSP, VCD export.
```
./sniff.py run --uart GP3:115200 --uart GP2:115200 -o cap.bin
./sniff.py analyze cap.bin
```

### `ncptalk.py` — ASH/EZSP host + attack tooling
ASH framing/codec, EZSP parse, and the attack commands:
```
./ncptalk.py monitor --out cap.bin            # decode passthru log live, save raw, flag plaintext keys
./ncptalk.py passthru-decrypt cap.bin [--key] # offline: recover UART key + decrypt both directions
./ncptalk.py fakencp --complete               # impersonate NCP to the ESP (session under a known key)
./ncptalk.py reset-ncp --force                # DESTRUCTIVE: resetToFactoryDefaults to the real NCP
./ncptalk.py secure-query --key <uartkey>     # open a Secure-EZSP session, read getKey/params
```

### `sekey.py` — Secure-EZSP crypto
Ported byte-for-byte from Gecko SDK 4.0
(`app/util/{ezsp/secure-ezsp.c, secure-ezsp/aes-mmo.c, secure-ezsp/hmac.c}`,
`stack/framework/ccm-star.c`). Self-tests pass against the Zigbee AES-MMO
install-code vector and RFC 3610 CCM PV#1.
- `aes_mmo`, `hmac_aes_mmo`, `session_ids(key, hostRand, ncpRand)`
- `ccm_encrypt` / `ccm_decrypt` (AES-CCM\*, nonce = `authCtl|sid8|ctr4|0x05`, 4-byte MIC)
```
./sekey.py selftest
./sekey.py decrypt cap.bin <hexkey>
```

### Secure-EZSP frame layout (de-randomised)
```
SEQ | FC_LB | FC_HB(0x81) | authCtl(0) | sessionId(8) | frameCtr(4 LE) | secLvl(0x05)
    | ENC[ frameId(2) + params ] | MIC(4)
```
- session ids = `HMAC-AES-MMO(uartKey, hostRand16 ‖ ncpRand16)` split 8+8 (host ‖ ncp)
- async callbacks use FC_LB `0x90` (RESPONSE | ASYNCH_CB)

---

## 4. Avenues tried

Everything short of the reset was defeated by design — documented here because
the negative results map the attack surface.

| Avenue | Result |
|--------|--------|
| Passive sniff of normal traffic | Encrypted; key never on the wire |
| ESP32 UART download (esptool) | `UART_DOWNLOAD_DIS` eFuse set — dead |
| MG21 SWD | Locked (Secure Vault) |
| EZSP version downgrade | NCP is v8-only → `invalidCommand` |
| Pre-secure key query to NCP | `SECURITY_PARAMETERS_NOT_SET` — real cmds gated |
| ESP32 flash dump | app flash-encrypted; key in NVS is **single XTS**, XTS key behind flash-enc + read-protected eFuse |
| **Fake NCP → ESP** (`fakencp`) | Session under a *known random* key; drove the ESP through full init + a faked scan/join. But ESP holds no real secrets — `setInitialSecurityState` uses `GET_PRECONFIGURED_KEY_FROM_INSTALL_CODE` (placeholder key), install code is read *from* the NCP. No real key obtainable. |
| **Fake ESP → NCP** (reprovision) | `setSecurityKey` refuses when a key exists; the only clear path (`resetToFactoryDefaults`) is welded to `emberLeaveNetwork()`. |
| Commissioning capture (factory reset) | User factory reset clears only ESP state; the NCP stays `ALREADY_SET` — no plaintext key |

### Crypto notes (why the "obvious" attacks fail)
- **Known-plaintext codebook on the flash NVS key:** impossible. XTS is a
  16-byte block cipher with full avalanche (no byte↔byte map), a block codebook
  is 2¹²⁸, and NVS is log-structured so rewrites move offsets (tweak changes).
- **Nonce/keystream reuse:** the NCP→ESP direction uses two counter streams
  (normal + async-callback) sharing one session id, both starting at 0 → limited
  keystream reuse, but it never reveals the AES key or network key.

---

## 5. The working attack chain

The NCP defends against a *normal* host, but `resetToFactoryDefaults` is reachable
**pre-authentication**, and re-provisioning a blank NCP puts the UART key on the
wire in the clear.

```
Phase 1 — blank the NCP (destructive: leaves the HAN)
  flash ncpbridge_ht  (ESP isolated)
  power-cycle Mini
  ./ncptalk.py reset-ncp --force
    → resetToFactoryDefaults → SUCCESS; getSecurityKeyStatus 0x43→0x47 (NOT_SET)

Phase 2 — capture the re-provisioning  (the timing-critical part)
  power OFF the Mini            # <-- essential: keeps the ESP from re-provisioning
  flash passthru               #     during the reflash gap (one-shot key, easy to miss)
  ./ncptalk.py monitor --out cap_reprovision.bin
  power ON the Mini
    → getSecurityKeyStatus 0x47 (NOT_SET)
    → PLAINTEXT setSecurityKey(0xCA) = UART key   ← captured

Phase 3 — read the secrets
  ./ncptalk.py passthru-decrypt cap_reprovision.bin   # decrypts whole session (install code, TC link key, certs)
  flash ncpbridge_ht ; power-cycle
  ./ncptalk.py secure-query --key <uartkey>           # getKey(3) = NETWORK KEY

Restore
  flash passthru ; power-cycle → ESP re-syncs (UART key stable), rejoins meter (NETWORK_UP)
```

### Why it works
On a blank NCP the ESP's `SETUP_SECURITY_ON_INIT` generates a fresh random
Secure-EZSP key and sends it via `setSecurityKey`, which is a **pre-secure,
plaintext** command. Capturing that one frame yields the live UART key; with it
you can decrypt the whole session *and* open your own Secure-EZSP session to the
NCP and `getKey` the network key directly. The one-time-at-manufacture
provisioning assumption is the weak link.

### Recovery
`resetToFactoryDefaults` calls `emberLeaveNetwork()`, so the Mini drops off the
HAN. In practice it **rejoined automatically** on the next boot (observed
`stackStatusHandler → NETWORK_UP`), because the install code (NCP mfg token) and
DCC registration are unchanged. Not guaranteed for every meter — treat it as
"may need supplier/DCC re-authorisation."

---

## 6. Outcome

| Secret | Value |
|--------|-------|
| **Zigbee network key** (HAN NWK-layer) | `REDACTED` |
| **Secure-EZSP UART key** | `REDACTED` |
| **Trust Center link key** | `REDACTED` |
| Install-code MFG token (raw) | `REDACTED` |
| Meter/TC EUI64 · channel | `REDACTED` · 11 |

Values are device-specific and change if the NCP is re-provisioned; the network
key may be rotated by the trust center (re-read with `secure-query`).

**Using the network key:** it decrypts the *over-the-air* HAN frames, not the
UART. Point a Zigbee radio sniffer (CC2531 / nRF / MG21 sniffer FW) at channel
11, capture the meter↔Mini traffic, and decrypt the NWK layer with the key.

### Meter readings — directly over the UART (no radio needed)
The captured session already contains **live meter data in cleartext**. The NCP
NWK/APS-decrypts the HAN and passes the ZCL up to the ESP as EZSP
`incomingMessageHandler` (0x45) callbacks. Cluster **0x0702 (Simple Metering)**
Read-Attributes-Responses carry the readings — decrypted here with the UART key:

| Attribute | Raw | Scaled (Divisor 1000) |
|-----------|-----|-----------------------|
| InstantaneousDemand (0x0400) | 278–290 | **~0.28 kW live power** |
| CurrentSummationDelivered (0x0000) | 16,096,090 → …110 | **~16,096.11 kWh total import** |
| CurrentSummationReceived (0x0001) | 6,923,195 | export/second register |
| 2nd meter (UnitOfMeasure 0x0300=01) | ~6,228,911 | gas (m³) / second register |

So with just the **Secure-EZSP UART key** and a passive tap, `passthru-decrypt`
yields the live meter feed — the network key and an OTA radio sniffer are **not
required** for the readings.

Full decrypted real session: `captures/cap_reprovision_decrypted.txt` (2887 lines).

---

## 7. Security assessment

Well-designed overall — every passive, impersonation, flash, and normal-host
path is closed, and the crypto (Secure-EZSP AES-CCM\*, NVS XTS, flash-enc + eFuse)
is sound. The single weakness:

- `resetToFactoryDefaults` is accepted **unauthenticated** (pre-secure) and
  blanks the NCP.
- A blanked NCP is re-provisioned by the host with a **plaintext** `setSecurityKey`.
- Anyone with physical access to the UART can therefore force a fresh key onto
  the wire, capture it, and read all NCP-held keys.

Mitigations would be: provision the UART key out-of-band (never on the wire),
require the existing session/key to authorise a reset, or gate
`resetToFactoryDefaults` behind a secured session.

---

## 8. Home Assistant integration (`esphome/`)

A permanent, passive reader: an **ESP32-C3 Supermini** taps the NCP-TX line,
decodes the bus on-device with the UART key, and exposes native sensors to Home
Assistant via ESPHome. **One signal wire** — the readings ride the NCP->ESP
direction and each secure frame self-contains its nonce, so the key alone
decrypts them (no handshake, no network key, no OTA radio).

- Wiring: `MGM210P TX -> ESP32-C3 GPIO4` (RX only, passive) + `GND`. GPIO4 avoids
  the C3's strapping pins (2/8/9), USB (18/19) and UART0 log pins (20/21);
  GPIO3/5/6/7/10 work equally.
- `esphome/components/octopus_mini/` — ESPHome **external component** (`__init__.py`
  codegen + `octopus_mini.h`): ASH de-stuff/CRC/de-randomize -> mbedTLS AES-CCM*
  decrypt -> EZSP `incomingMessageHandler` -> ZCL Metering (0x0702) -> sensors.
- `esphome/octopus-mini.yaml` — config (board `esp32-c3-devkitm-1`, `esp-idf`).
  Copy `esphome/secrets.yaml.example` to `esphome/secrets.yaml` and set your
  WiFi/API/OTA plus `octopus_uart_key`.
- Build/flash: `esphome run esphome/octopus-mini.yaml`. Sensors (`power` W,
  `import`/`export` kWh, `gas` m³) auto-discover in HA; `total_increasing` feeds
  the Energy Dashboard. Electricity and gas are separate meter endpoints,
  classified by UnitOfMeasure with per-endpoint scaling.
- **Key caveat:** the UART key is stable until the NCP is re-provisioned (a
  `resetToFactoryDefaults`). If that ever happens, re-capture the plaintext
  `setSecurityKey` and update `octopus_uart_key`.

## 9. Safety / ethics

Authorised research on my own hardware for education. `ncptalk.py` keeps a
command whitelist; `resetToFactoryDefaults` was enabled deliberately and only
run with explicit intent, knowing it drops the HAN. The device was restored and
verified back on the meter after each destructive step. Extracted keys are for
this one device only. For the actual energy data without any of this, use a
DCC-registered CAD (Hildebrand Glow) with the meter's install code, or the
n3rgy / Octopus API.

---

## 10. File index

```
README.md                      this writeup
sniff.py                       logic-sniffer host (capture/decode/VCD)
ncptalk.py                     ASH/EZSP host: monitor, passthru-decrypt, fakencp, reset-ncp, secure-query
sekey.py                       Secure-EZSP crypto (session ids, AES-CCM* encrypt/decrypt)
ezsp_ids.json                  EZSP frame-id -> name table
firmware/                      Pico firmware sources (passthru, ncpbridge, fakencp, rewrite, sniffer.c, ...)
firmware/prebuilt/             prebuilt *.uf2 images (see table §2)
esphome/octopus-mini.yaml      ESP32-C3 passive meter reader -> Home Assistant
esphome/components/octopus_mini/   ESPHome external component (decoder)
esphome/secrets.yaml.example   copy to secrets.yaml (gitignored) and fill in
hardware/pcb/                  KiCad board project
hardware/symbols/              MGM210P22A KiCad symbol + generator
tests/                         decoder test fixtures (synth.py + sample captures)
captures/cap_reprovision.bin           raw capture of the successful re-provisioning
captures/cap_reprovision_decrypted.txt full decrypted real ESP↔NCP session
captures/cap_boot.bin                   reference boot+secure-session capture
```
