#pragma once
// ESPHome external component: passively decode the Octopus Home Mini's
// ESP32<->MGM210P UART and publish live smart-meter readings to Home Assistant.
//
// The MGM210P (Zigbee NCP) already NWK/APS-decrypts the HAN traffic and passes
// it to its host as EZSP `incomingMessageHandler` (0x45) callbacks over ASH.
// Those callbacks are Secure-EZSP encrypted (AES-CCM*), but every frame carries
// its own sessionId+counter in the nonce, so a passive listener that holds the
// 16-byte Secure-EZSP UART key can decrypt them independently -- no session
// handshake, no OTA radio, no network key needed.
//
// Pipeline per byte: ASH de-stuff -> flag -> CRC16-CCITT check -> de-randomize
// (LFSR seed 0x42) -> AES-CCM* decrypt (mbedTLS) -> EZSP incomingMessageHandler
// -> ZCL Simple Metering (cluster 0x0702) Read-Attributes-Response -> sensors.
//
// Tap NCP TX -> S2 UART RX (rx-only). See octopus-mini.yaml.

#include "esphome/core/component.h"
#include "esphome/components/uart/uart.h"
#include "esphome/components/sensor/sensor.h"
#include "mbedtls/ccm.h"
#include <vector>
#include <map>
#include <cstring>

namespace esphome {
namespace octopus_mini {

class OctopusMini : public Component, public uart::UARTDevice {
 public:
  void set_key(const std::vector<uint8_t> &k) { key_ = k; }
  void set_power_sensor(sensor::Sensor *s) { power_ = s; }
  void set_import_sensor(sensor::Sensor *s) { import_ = s; }
  void set_export_sensor(sensor::Sensor *s) { export_ = s; }
  void set_gas_sensor(sensor::Sensor *s) { gas_ = s; }
  void set_elec_price_sensor(sensor::Sensor *s) { elec_price_ = s; }
  void set_gas_price_sensor(sensor::Sensor *s) { gas_price_ = s; }

  float get_setup_priority() const override { return setup_priority::DATA; }

  void loop() override {
    while (available()) {
      uint8_t b = read();
      if (b == 0x7E) { process_frame_(); reset_buf_(); }       // flag = frame end
      else if (b == 0x1A) { reset_buf_(); }                    // CAN -> abort frame
      else if (b == 0x11 || b == 0x13) { /* XON/XOFF: ignore */ }
      else if (b == 0x7D) { esc_ = true; }                     // escape next byte
      else { buf_.push_back(esc_ ? (b ^ 0x20) : b); esc_ = false; }
      if (buf_.size() > 300) reset_buf_();                     // sanity guard
    }
  }

 protected:
  std::vector<uint8_t> key_, buf_;
  bool esc_{false};
  sensor::Sensor *power_{nullptr}, *import_{nullptr}, *export_{nullptr}, *gas_{nullptr};
  sensor::Sensor *elec_price_{nullptr}, *gas_price_{nullptr};
  uint8_t elec_meter_ep_{0xFF};        // electricity metering endpoint (for price routing)

  // Per-endpoint scaling/type: electricity and gas are separate endpoints with
  // their OWN UnitOfMeasure / Multiplier / Divisor.
  struct Ep { uint8_t unit{0xFF}; uint32_t mult{1}, div{1000}; };
  std::map<uint8_t, Ep> eps_;

  void reset_buf_() { buf_.clear(); esc_ = false; }

  static uint16_t crc16_(const uint8_t *d, size_t n) {
    uint16_t c = 0xFFFF;
    for (size_t i = 0; i < n; i++) {
      c ^= (uint16_t) d[i] << 8;
      for (int k = 0; k < 8; k++) c = (c & 0x8000) ? (uint16_t)((c << 1) ^ 0x1021) : (uint16_t)(c << 1);
    }
    return c;
  }
  static void derand_(uint8_t *d, size_t n) {              // ASH data-field LFSR
    uint8_t r = 0x42;
    for (size_t i = 0; i < n; i++) { d[i] ^= r; r = (r & 1) ? ((r >> 1) ^ 0xB8) : (r >> 1); }
  }

  bool ccm_decrypt_(const uint8_t *f, size_t len, uint8_t *out, size_t &outlen) {
    if (key_.size() != 16 || len < 17 + 2 + 4) return false;
    size_t ctlen = len - 17 - 4;
    const uint8_t *nonce = f + 3, *aad = f, *ct = f + 17, *tag = f + 17 + ctlen;
    mbedtls_ccm_context ctx; mbedtls_ccm_init(&ctx);
    bool ok = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key_.data(), 128) == 0 &&
              mbedtls_ccm_auth_decrypt(&ctx, ctlen, nonce, 13, aad, 17, ct, out, tag, 4) == 0;
    mbedtls_ccm_free(&ctx);
    outlen = ctlen;
    return ok;
  }

  void process_frame_() {
    size_t n = buf_.size();
    if (n < 3) return;
    uint16_t rx_crc = ((uint16_t) buf_[n - 2] << 8) | buf_[n - 1];
    if (crc16_(buf_.data(), n - 2) != rx_crc) return;
    if (buf_[0] & 0x80) return;                              // not an ASH DATA frame
    size_t elen = n - 3;                                     // strip ctrl + 2 CRC
    if (elen < 3 || elen > 255) return;
    uint8_t ez[256];
    memcpy(ez, &buf_[1], elen);
    derand_(ez, elen);
    if (!(ez[2] & 0x80)) return;                             // only Secure-EZSP frames
    uint8_t pt[256]; size_t ptlen = 0;
    if (!ccm_decrypt_(ez, elen, pt, ptlen)) return;          // wrong key / not for us
    if (ptlen < 3) return;
    if ((pt[0] | (pt[1] << 8)) != 0x0045) return;            // incomingMessageHandler
    parse_incoming_(pt + 2, ptlen - 2);
  }

  // incomingMessageHandler params: type(1) profileId(2) clusterId(2) srcEp(1)
  //   destEp(1) options(2) groupId(2) seq(1) lqi(1) rssi(1) sender(2) binding(1)
  //   addrIndex(1) msgLen(1) message[msgLen]
  void parse_incoming_(const uint8_t *p, size_t n) {
    if (n < 19) return;
    uint16_t cluster = p[3] | (p[4] << 8);
    uint8_t ep = p[5];
    uint8_t msglen = p[18];
    if ((size_t) 19 + msglen > n || msglen < 3) return;
    const uint8_t *z = p + 19;
    if (cluster == 0x0702) parse_metering_(z, msglen, ep);     // Simple Metering
    else if (cluster == 0x0700) parse_price_(z, msglen, ep);   // Price
  }

  void parse_metering_(const uint8_t *z, uint8_t msglen, uint8_t ep) {
    if (z[2] != 0x01) return;                                  // ZCL Read Attributes Response
    size_t i = 3;
    while (i + 3 <= msglen) {
      uint16_t aid = z[i] | (z[i + 1] << 8);
      uint8_t status = z[i + 2]; i += 3;
      if (status != 0) continue;
      if (i >= msglen) break;
      uint8_t type = z[i++];
      size_t vl = type_len_(type, z + i, msglen - i);
      if (vl == 0 || i + vl > msglen) break;
      handle_attr_(aid, type, z + i, vl, ep);
      i += vl;
    }
  }

  // Price cluster PublishPrice (cluster-specific cmd 0x00). Pull the unit Price
  // and its trailing-digit scaling. Route to electricity vs gas by whether the
  // endpoint matches the electricity *metering* endpoint we latched.
  void parse_price_(const uint8_t *z, uint8_t msglen, uint8_t ep) {
    if (!(z[0] & 0x01) || z[2] != 0x00) return;                // cluster-specific PublishPrice
    const uint8_t *f = z + 3;
    size_t fn = (size_t) msglen - 3, i = 0;
    auto need = [&](size_t k) { return i + k <= fn; };
    if (!need(4)) return; i += 4;                              // providerID
    if (!need(1)) return; uint8_t rl = f[i++];                 // rateLabel length
    if (!need(rl)) return; i += rl;                            // rateLabel
    if (!need(4)) return; i += 4;                              // issuerEventID
    if (!need(4)) return; i += 4;                              // currentTime
    if (!need(1)) return; i += 1;                              // unitOfMeasure
    if (!need(2)) return; i += 2;                              // currency
    if (!need(1)) return; uint8_t trailing = f[i++] >> 4;      // priceTrailingDigit & tier
    if (!need(1)) return; i += 1;                              // numberOfPriceTiers & registerTier
    if (!need(4)) return; i += 4;                              // startTime
    if (!need(2)) return; i += 2;                              // durationInMinutes
    if (!need(4)) return; double price = (double) uintle_(f + i, 4);
    for (uint8_t t = 0; t < trailing; t++) price /= 10.0;      // -> currency per unit (e.g. GBP/kWh)
    if (ep == elec_meter_ep_) { if (elec_price_) elec_price_->publish_state(price); }
    else { if (gas_price_) gas_price_->publish_state(price); }
  }

  static size_t type_len_(uint8_t t, const uint8_t *d, size_t avail) {
    switch (t) {
      case 0x10: case 0x18: case 0x20: case 0x28: case 0x30: return 1;
      case 0x21: case 0x29: return 2;
      case 0x22: case 0x2a: return 3;
      case 0x23: case 0x2b: return 4;
      case 0x24: return 5;
      case 0x25: return 6;
      case 0x41: case 0x42: return avail ? (size_t) d[0] + 1 : 0;   // octet/char string
      default: return 0;
    }
  }
  static int64_t uintle_(const uint8_t *d, size_t n) {
    int64_t v = 0; for (size_t i = 0; i < n; i++) v |= (int64_t) d[i] << (8 * i); return v;
  }
  static int64_t intle_(const uint8_t *d, size_t n) {
    int64_t v = uintle_(d, n); if (n && (d[n - 1] & 0x80)) v -= (int64_t) 1 << (8 * n); return v;
  }

  // Classify each endpoint by UnitOfMeasure (0=electricity kWh, 1=gas m3),
  // track its own multiplier/divisor, and route readings to the right sensor.
  // InstantaneousDemand only exists on the electricity meter, so it also serves
  // as a fallback classifier if UnitOfMeasure is somehow missed.
  void handle_attr_(uint16_t aid, uint8_t type, const uint8_t *d, size_t n, uint8_t ep) {
    Ep &e = eps_[ep];
    double scale = (double) e.mult / (double) e.div;         // uses this ep's current mult/div
    switch (aid) {
      case 0x0300: e.unit = (uint8_t) uintle_(d, n); if (e.unit == 0x00) elec_meter_ep_ = ep; break;  // UnitOfMeasure
      case 0x0301: { uint32_t v = uintle_(d, n); if (v) e.mult = v; } break;  // Multiplier
      case 0x0302: { uint32_t v = uintle_(d, n); if (v) e.div = v; } break;   // Divisor
      case 0x0400:                                                      // InstantaneousDemand -> W
        if (e.unit == 0xFF) e.unit = 0x00;                              // demand => electricity
        elec_meter_ep_ = ep;
        if (power_) power_->publish_state((double) intle_(d, n) * scale * 1000.0);
        break;
      case 0x0000:                                                      // CurrentSummationDelivered
        if (e.unit == 0x01) { if (gas_)    gas_->publish_state((double) uintle_(d, n) * scale); }     // m3
        else if (e.unit == 0x00) { if (import_) import_->publish_state((double) uintle_(d, n) * scale); }  // kWh
        break;                                                          // unit unknown -> wait for UnitOfMeasure
      case 0x0001:                                                      // CurrentSummationReceived (elec export)
        if (e.unit == 0x00 && export_) export_->publish_state((double) uintle_(d, n) * scale);
        break;
    }
  }
};

}  // namespace octopus_mini
}  // namespace esphome
