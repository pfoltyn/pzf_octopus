import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import uart, sensor
from esphome.const import (
    CONF_ID,
    CONF_POWER,
    DEVICE_CLASS_POWER,
    DEVICE_CLASS_ENERGY,
    DEVICE_CLASS_GAS,
    STATE_CLASS_MEASUREMENT,
    STATE_CLASS_TOTAL_INCREASING,
    UNIT_WATT,
    UNIT_KILOWATT_HOURS,
)

DEPENDENCIES = ["uart"]

octopus_mini_ns = cg.esphome_ns.namespace("octopus_mini")
OctopusMini = octopus_mini_ns.class_("OctopusMini", cg.Component, uart.UARTDevice)

CONF_KEY = "key"
CONF_IMPORT = "import_energy"
CONF_EXPORT = "export_energy"
CONF_GAS = "gas"


def _parse_key(value):
    s = cv.string_strict(value).replace(" ", "").replace(":", "")
    try:
        b = bytes.fromhex(s)
    except ValueError as err:
        raise cv.Invalid("key must be hex") from err
    if len(b) != 16:
        raise cv.Invalid("Secure-EZSP key must be 16 bytes (32 hex chars)")
    return list(b)


CONFIG_SCHEMA = (
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(OctopusMini),
            cv.Required(CONF_KEY): _parse_key,
            cv.Optional(CONF_POWER): sensor.sensor_schema(
                unit_of_measurement=UNIT_WATT,
                device_class=DEVICE_CLASS_POWER,
                state_class=STATE_CLASS_MEASUREMENT,
                accuracy_decimals=0,
            ),
            cv.Optional(CONF_IMPORT): sensor.sensor_schema(
                unit_of_measurement=UNIT_KILOWATT_HOURS,
                device_class=DEVICE_CLASS_ENERGY,
                state_class=STATE_CLASS_TOTAL_INCREASING,
                accuracy_decimals=3,
            ),
            cv.Optional(CONF_EXPORT): sensor.sensor_schema(
                unit_of_measurement=UNIT_KILOWATT_HOURS,
                device_class=DEVICE_CLASS_ENERGY,
                state_class=STATE_CLASS_TOTAL_INCREASING,
                accuracy_decimals=3,
            ),
            cv.Optional(CONF_GAS): sensor.sensor_schema(
                unit_of_measurement="m³",
                device_class=DEVICE_CLASS_GAS,
                state_class=STATE_CLASS_TOTAL_INCREASING,
                accuracy_decimals=3,
            ),
        }
    )
    .extend(cv.COMPONENT_SCHEMA)
    .extend(uart.UART_DEVICE_SCHEMA)
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await uart.register_uart_device(var, config)

    key_init = cg.RawExpression(
        "{" + ", ".join(f"0x{b:02x}" for b in config[CONF_KEY]) + "}"
    )
    cg.add(var.set_key(key_init))

    if CONF_POWER in config:
        cg.add(var.set_power_sensor(await sensor.new_sensor(config[CONF_POWER])))
    if CONF_IMPORT in config:
        cg.add(var.set_import_sensor(await sensor.new_sensor(config[CONF_IMPORT])))
    if CONF_EXPORT in config:
        cg.add(var.set_export_sensor(await sensor.new_sensor(config[CONF_EXPORT])))
    if CONF_GAS in config:
        cg.add(var.set_gas_sensor(await sensor.new_sensor(config[CONF_GAS])))
