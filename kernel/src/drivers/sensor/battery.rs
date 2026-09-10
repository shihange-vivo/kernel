// Copyright (c) 2026 vivo Mobile Communication Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/LICENSE/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Battery driver for the AXP2101 PMIC.
//!
//! The Waveshare ESP32-C6-Touch-AMOLED-2.16 board has no discrete battery
//! voltage divider on an ESP32 ADC pin. Instead, the onboard AXP2101 PMIC
//! (I²C address `0x34`) provides battery voltage, state-of-charge, and charging
//! status through its internal fuel gauge and ADC. This driver reads those
//! registers and exposes them as `/dev/battery`.
//!
//! Register reference: XPowersLib (`XPowersAXP2101.tpp`, `REG/AXP2101Constants.h`)
//! from the board's official `01_Arduino_Libraries/XPowersLib` distribution.
//!
//! The device appears in userspace as `/dev/battery`. A `read()` returns an
//! 8-byte [`BatteryReport`] — little-endian — containing the battery voltage in
//! millivolts, the state-of-charge percentage reported by the fuel gauge, and
//! the charging state from the PMIC's STATUS2 register.

use blueos_driver::i2c::I2cConfig;
use embedded_io::ErrorKind;

use crate::{
    devices::{
        Device, DeviceClass, DeviceData, DeviceId, DeviceManager,
        bus::{Bus, BusWrapper},
        i2c_core::block_i2c::BlockI2c,
    },
    drivers::{DriverModule, InitDriver, Result as DriverResult},
    sync::SpinLock,
};
use alloc::{string::String, sync::Arc};

// ---------------------------------------------------------------------------
// AXP2101 I²C register addresses (from REG/AXP2101Constants.h)
// ---------------------------------------------------------------------------

/// AXP2101 I²C 7-bit slave address.
const AXP2101_I2C_ADDR: u8 = 0x34;

/// STATUS1 register — battery-present, VBUS good, etc.
const REG_STATUS1: u8 = 0x00;
/// STATUS2 register — charging state (bits[7:5]).
const REG_STATUS2: u8 = 0x01;
/// IC_TYPE register — chip ID check (should read 0x4A).
const REG_IC_TYPE: u8 = 0x03;

/// Battery voltage ADC data: high 5 bits in REG 0x34, low 8 bits in REG 0x35.
/// readRegisterH5L8: `((reg[0x34] & 0x1F) << 8) | reg[0x35]` → millivolts.
const REG_BAT_VOLTAGE_H: u8 = 0x34;
const REG_BAT_VOLTAGE_L: u8 = 0x35;

/// Fuel-gauge battery percentage (0–100).
const REG_BAT_PERCENT: u8 = 0xA4;

// ---------------------------------------------------------------------------
// STATUS1 bit definitions
// ---------------------------------------------------------------------------

/// Bit 3 of STATUS1 — battery connected.
const STATUS1_BAT_CONNECT: u8 = 1 << 3;

// ---------------------------------------------------------------------------
// STATUS2 charging-state definitions (bits[7:5])
// ---------------------------------------------------------------------------

/// Charging state values from `xpowers_chg_status_t` (XPowersAXP2101.tpp:292).
/// `(STATUS2 >> 5)` yields:
///   0 = standby (not charging, not discharging)
///   1 = charging (constant-current)
///   2 = discharging
///   3 = constant-voltage charge
///   4 = charge done
///   5 = not charging (stopped)
const CHG_STATE_STANDBY: u8 = 0x00;
const CHG_STATE_CHARGING: u8 = 0x01;
const CHG_STATE_DISCHARGING: u8 = 0x02;
const CHG_STATE_CV: u8 = 0x03;
const CHG_STATE_DONE: u8 = 0x04;
const CHG_STATE_STOPPED: u8 = 0x05;

// ---------------------------------------------------------------------------
// Device identity
// ---------------------------------------------------------------------------

const BATTERY_DEVICE_NAME: &str = "battery";
const BATTERY_DEVICE_MAJOR: usize = 242;
const BATTERY_DEVICE_MINOR: usize = 0;

// ---------------------------------------------------------------------------
// Binary report (8 bytes, little-endian)
// ---------------------------------------------------------------------------

/// Binary report returned by `/dev/battery` (8 bytes, little-endian).
///
/// Layout:
/// - byte 0: format version (`1`)
/// - bytes 1..=2: battery voltage in millivolts (`u16`)
/// - byte 3: state-of-charge percentage (0–100, `u8`)
/// - byte 4: charging state (see `CHG_STATE_*` constants, `u8`)
/// - bytes 5..=7: reserved (zeros)
pub const BATTERY_REPORT_SIZE: usize = 8;
const BATTERY_REPORT_VERSION: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct BatteryReport {
    version: u8,
    voltage_mv: u16,
    percent: u8,
    charging_state: u8,
    reserved: [u8; 3],
}

impl BatteryReport {
    fn encode(voltage_mv: u16, percent: u8, charging_state: u8) -> [u8; BATTERY_REPORT_SIZE] {
        let mut bytes = [0u8; BATTERY_REPORT_SIZE];
        bytes[0] = BATTERY_REPORT_VERSION;
        bytes[1..3].copy_from_slice(&voltage_mv.to_le_bytes());
        bytes[3] = percent;
        bytes[4] = charging_state;
        bytes
    }
}

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct BatteryState<T: blueos_hal::i2c::I2c<I2cConfig, ()> + 'static> {
    i2c: BusWrapper<BlockI2c<T>>,
    /// Cached last reading so a failed I²C transaction still returns stale
    /// data instead of zeros.
    last: (u16, u8, u8), // (voltage_mv, percent, charging_state)
}

pub struct BatteryDevice<T: blueos_hal::i2c::I2c<I2cConfig, ()> + 'static> {
    state: SpinLock<BatteryState<T>>,
}

impl<T: blueos_hal::i2c::I2c<I2cConfig, ()> + 'static> BatteryDevice<T> {
    fn new(i2c: BusWrapper<BlockI2c<T>>) -> Self {
        Self {
            state: SpinLock::new(BatteryState {
                i2c,
                last: (0, 0, CHG_STATE_STANDBY),
            }),
        }
    }

    /// Read one register from the AXP2101.
    fn read_reg(i2c: &BusWrapper<BlockI2c<T>>, reg: u8) -> Result<u8, ErrorKind> {
        use embedded_hal::i2c::I2c;
        let mut bus = i2c.clone();
        let mut buf = [0u8; 1];
        bus.transaction(
            AXP2101_I2C_ADDR,
            &mut [embedded_hal::i2c::Operation::Write(&[reg]), embedded_hal::i2c::Operation::Read(&mut buf)],
        )
        .map_err(|_| ErrorKind::Other)?;
        Ok(buf[0])
    }

    /// Read the battery voltage from AXP2101 ADC registers 0x34/0x35.
    ///
    /// Mirrors `readRegisterH5L8(0x34, 0x35)` in XPowersAXP2101.tpp:2389:
    /// `((reg_h & 0x1F) << 8) | reg_l` → millivolts.
    fn read_voltage(i2c: &BusWrapper<BlockI2c<T>>) -> Result<u16, ErrorKind> {
        let h = Self::read_reg(i2c, REG_BAT_VOLTAGE_H)?;
        let l = Self::read_reg(i2c, REG_BAT_VOLTAGE_L)?;
        Ok(((h as u16 & 0x1F) << 8) | l as u16)
    }

    /// Read the battery percentage from the AXP2101 fuel gauge (0xA4).
    fn read_percent(i2c: &BusWrapper<BlockI2c<T>>) -> Result<u8, ErrorKind> {
        let pct = Self::read_reg(i2c, REG_BAT_PERCENT)?;
        Ok(pct.min(100))
    }

    /// Check whether a battery is connected (STATUS1 bit 3).
    fn is_battery_connected(i2c: &BusWrapper<BlockI2c<T>>) -> bool {
        Self::read_reg(i2c, REG_STATUS1)
            .map(|s| (s & STATUS1_BAT_CONNECT) != 0)
            .unwrap_or(false)
    }

    /// Read the charging state from STATUS2 bits[7:5].
    ///
    /// Returns the raw `(STATUS2 >> 5)` value (0–5, see `CHG_STATE_*`
    /// constants). On I²C failure the last cached state is returned.
    fn read_charging_state(i2c: &BusWrapper<BlockI2c<T>>) -> Result<u8, ErrorKind> {
        let status2 = Self::read_reg(i2c, REG_STATUS2)?;
        Ok(status2 >> 5)
    }

    /// Read the battery, update the cached reading, and return (mv, pct, chg).
    fn read_battery(&self) -> (u16, u8, u8) {
        let state = self.state.lock();
        let i2c = state.i2c.clone();
        let last = state.last;
        drop(state);

        if !Self::is_battery_connected(&i2c) {
            log::warn!("battery: no battery connected (AXP2101 STATUS1)");
            return last;
        }
        let mv = Self::read_voltage(&i2c).unwrap_or_else(|e| {
            log::warn!("battery: voltage read failed: {:?}", e);
            last.0
        });
        let pct = Self::read_percent(&i2c).unwrap_or_else(|e| {
            log::warn!("battery: percent read failed: {:?}", e);
            last.1
        });
        let chg = Self::read_charging_state(&i2c).unwrap_or_else(|e| {
            log::warn!("battery: charging-state read failed: {:?}", e);
            last.2
        });
        let mut state = self.state.lock();
        state.last = (mv, pct, chg);
        (mv, pct, chg)
    }
}

impl<T: blueos_hal::i2c::I2c<I2cConfig, ()> + 'static> Device for BatteryDevice<T> {
    fn name(&self) -> String {
        String::from(BATTERY_DEVICE_NAME)
    }

    fn class(&self) -> DeviceClass {
        DeviceClass::Char
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(BATTERY_DEVICE_MAJOR, BATTERY_DEVICE_MINOR)
    }

    fn read(
        &self,
        _pos: u64,
        buf: &mut [u8],
        _is_nonblocking: bool,
    ) -> Result<usize, ErrorKind> {
        if buf.len() < BATTERY_REPORT_SIZE {
            return Err(ErrorKind::InvalidInput);
        }
        let (mv, pct, chg) = self.read_battery();
        let report = BatteryReport::encode(mv, pct, chg);
        buf[..BATTERY_REPORT_SIZE].copy_from_slice(&report);
        Ok(BATTERY_REPORT_SIZE)
    }

    fn write(
        &self,
        _pos: u64,
        _buf: &[u8],
        _is_nonblocking: bool,
    ) -> Result<usize, ErrorKind> {
        Err(ErrorKind::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// Bus-attached driver configuration (matches CST9220 pattern)
// ---------------------------------------------------------------------------

pub struct BatteryConfig {}

impl<T: blueos_hal::i2c::I2c<I2cConfig, ()> + 'static> InitDriver<BlockI2c<T>>
    for BatteryConfig
{
    type Data = ();

    fn init(self, bus: &Bus<BlockI2c<T>>) -> DriverResult<Self::Data> {
        let i2c = bus.intf.clone();

        // Verify the AXP2101 is present by reading its chip ID register
        // (should be 0x4A per XPOWERS_AXP2101_CHIP_ID).
        let chip_id = BatteryDevice::<T>::read_reg(&i2c, REG_IC_TYPE).map_err(|e| {
            crate::kearly_println!("AXP2101: I2C read failed: {:?}", e);
            log::warn!("AXP2101: I2C read failed: {:?}", e);
            crate::error::code::EIO
        })?;

        if chip_id != 0x4A {
            crate::kearly_println!(
                "AXP2101: unexpected chip ID 0x{:02X} (expected 0x4A)",
                chip_id
            );
            log::warn!(
                "AXP2101: unexpected chip ID 0x{:02X} (expected 0x4A)",
                chip_id
            );
            return Err(crate::error::code::ENODEV);
        }

        let device = Arc::new(BatteryDevice::<T>::new(i2c));
        DeviceManager::get()
            .register_device(String::from(BATTERY_DEVICE_NAME), device)
            .map_err(|_| crate::error::code::EIO)?;

        crate::kearly_println!("AXP2101 battery registered as /dev/battery");
        log::info!("AXP2101 battery registered as /dev/battery");
        Ok(())
    }
}

pub struct BatteryDriverModule {
    _marker: core::marker::PhantomData<()>,
}

impl BatteryDriverModule {
    pub const fn new() -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }
}

impl<T: blueos_hal::i2c::I2c<I2cConfig, ()> + 'static> DriverModule<BlockI2c<T>>
    for BatteryDriverModule
{
    type Data = BatteryConfig;

    fn probe(_dev: &DeviceData) -> DriverResult<Self::Data> {
        // The AXP2101 is always present on the Waveshare board's I2C0 bus.
        // Unlike the CST9220 it has no reset GPIO, so the config is trivial.
        Ok(BatteryConfig {})
    }
}
