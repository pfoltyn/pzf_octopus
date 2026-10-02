"""Generate KiCad symbol for Silicon Labs MGM210P22A (OPN MGM210PA22JIA2).
Pinout: MGM210P datasheet Rev 1.5, Table 6.1 / Figure 6.1 (31-pin LGA)."""

G = 2.54
HALF_W = 15.24          # body half width
TOP = 17.78             # first pin row

# (number, name, electrical type) ; None = spacer row
LEFT = [
    (13, "VDD", "power_in"),
    (14, "IOVDD", "power_in"),
    None,
    (27, "RESETn", "input"),
    (11, "DECOUPLE", "power_out"),
    None,
    (4, "PA00", "bidirectional"),
    (5, "PA01/SWCLK", "bidirectional"),
    (6, "PA02/SWDIO", "bidirectional"),
    (7, "PA03/SWV", "bidirectional"),
    (8, "PA04/TDI", "bidirectional"),
    (9, "PA05", "bidirectional"),
    (10, "PA06", "bidirectional"),
    None,
    (29, "RF2G4_IO2", "passive"),
]
RIGHT = [
    (3, "PB00", "bidirectional"),
    (2, "PB01", "bidirectional"),
    None,
    (21, "PC00", "bidirectional"),
    (22, "PC01", "bidirectional"),
    (23, "PC02", "bidirectional"),
    (24, "PC03", "bidirectional"),
    (25, "PC04", "bidirectional"),
    (26, "PC05", "bidirectional"),
    None,
    (19, "PD00/LFXO_O", "bidirectional"),
    (18, "PD01/LFXO_I", "bidirectional"),
    (17, "PD02", "bidirectional"),
    (16, "PD03", "bidirectional"),
    (15, "PD04", "bidirectional"),
]
GND = [1, 12, 20, 28, 30, 31]


def pin(etype, x, y, ang, name, num):
    return (f'\t\t\t(pin {etype} line (at {x:g} {y:g} {ang}) (length {G:g})\n'
            f'\t\t\t\t(name "{name}" (effects (font (size 1.27 1.27))))\n'
            f'\t\t\t\t(number "{num}" (effects (font (size 1.27 1.27))))\n'
            f'\t\t\t)\n')


def prop(k, v, x, y, hide=False):
    h = " (hide yes)" if hide else ""
    return (f'\t\t(property "{k}" "{v}" (at {x:g} {y:g} 0)\n'
            f'\t\t\t(effects (font (size 1.27 1.27)){h})\n\t\t)\n')


rows = len(LEFT)
assert rows == len(RIGHT)
bottom = TOP - (rows - 1) * G
body_top, body_bot = TOP + G, bottom - 3 * G

pins = ""
for i, p in enumerate(LEFT):
    if p:
        pins += pin(p[2], -HALF_W - G, round(TOP - i * G, 2), 0, p[1], p[0])
for i, p in enumerate(RIGHT):
    if p:
        pins += pin(p[2], HALF_W + G, round(TOP - i * G, 2), 180, p[1], p[0])
for i, n in enumerate(GND):
    x = round((i - (len(GND) - 1) / 2) * G - G / 2, 2)
    pins += pin("power_in", x, round(body_bot - G, 2), 90, "GND", n)

nums = sorted([p[0] for p in LEFT + RIGHT if p] + GND)
assert nums == list(range(1, 32)), nums

out = f'''(kicad_symbol_lib
\t(version 20231120)
\t(generator "gen_mgm210p")
\t(generator_version "1.0")
\t(symbol "MGM210P22A"
\t\t(exclude_from_sim no)
\t\t(in_bom yes)
\t\t(on_board yes)
{prop("Reference", "U", -HALF_W, body_top + 1.27)}{prop("Value", "MGM210P22A", HALF_W - 7.62, body_top + 1.27)}{prop("Footprint", "", 0, body_bot - 7.62, True)}{prop("Datasheet", "https://www.silabs.com/documents/public/data-sheets/mgm210p-datasheet.pdf", 0, body_bot - 10.16, True)}{prop("Description", "Silicon Labs MGM210P Mighty Gecko module (EFR32MG21), Zigbee/Thread/BLE, 10 dBm, built-in antenna, 1024 kB flash, 96 kB RAM, 31-pin LGA 12.9x15.0 mm. OPN MGM210PA22JIA2", 0, body_bot - 12.7, True)}{prop("ki_keywords", "zigbee thread bluetooth EFR32MG21 module silabs", 0, body_bot - 15.24, True)}\t\t(symbol "MGM210P22A_0_1"
\t\t\t(rectangle (start {-HALF_W:g} {body_top:g}) (end {HALF_W:g} {body_bot:g})
\t\t\t\t(stroke (width 0.254) (type default))
\t\t\t\t(fill (type background))
\t\t\t)
\t\t)
\t\t(symbol "MGM210P22A_1_1"
{pins}\t\t)
\t)
)
'''
open(__file__.replace("gen_mgm210p.py", "MGM210P22A.kicad_sym"), "w").write(out)
print("ok", len(nums), "pins")
