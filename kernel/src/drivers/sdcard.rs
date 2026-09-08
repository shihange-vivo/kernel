// Copyright (c) 2026 vivo Mobile Communication Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! SD cards connected through the ESP32 SPI peripheral.

use alloc::{string::String, sync::Arc};
use embedded_io::ErrorKind;

use crate::{
    devices::{
        block::{Block, BlockDriverOps, BlockError, ErrorType},
        bus::Bus,
        spi_core::{block_spi::BlockSpi, ExclusiveSpiWithCs},
        DeviceData, DeviceManager,
    },
    drivers::{DriverModule, InitDriver},
    sync::SpinLock,
};

const SECTOR_SIZE: usize = 512;
const R1_RETRIES: usize = 8;
const INIT_RETRIES: usize = 4_000;
const INIT_TOKEN_RETRIES: usize = 10_000;
const DATA_TOKEN_RETRIES: usize = 100_000;
const BUSY_RETRIES: usize = 1_000_000;

const CMD0: u8 = 0;
const CMD8: u8 = 8;
const CMD9: u8 = 9;
const CMD16: u8 = 16;
const CMD17: u8 = 17;
const CMD24: u8 = 24;
const CMD41: u8 = 41;
const CMD55: u8 = 55;
const CMD58: u8 = 58;

const DATA_START_TOKEN: u8 = 0xfe;
const DATA_ACCEPTED: u8 = 0x05;

#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum SdCardError {
    #[error("SPI error: {0}")]
    Spi(crate::error::Error),
    #[error("SD card did not respond")]
    NoCard,
    #[error("SD card response timeout")]
    Timeout,
    #[error("unexpected SD card response: 0x{0:02x}")]
    Response(u8),
    #[error("unexpected SD card data token: 0x{0:02x}")]
    DataToken(u8),
    #[error("SD card capacity is invalid")]
    InvalidCapacity,
    #[error("SD card operation is unsupported")]
    Unsupported,
    #[error("SD card argument is invalid")]
    InvalidParam,
}

impl From<crate::error::Error> for SdCardError {
    fn from(error: crate::error::Error) -> Self {
        Self::Spi(error)
    }
}

impl SdCardError {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Spi(_) => ErrorKind::Other,
            Self::NoCard => ErrorKind::NotFound,
            Self::Timeout => ErrorKind::TimedOut,
            Self::Response(_) | Self::DataToken(_) => ErrorKind::InvalidData,
            Self::InvalidCapacity | Self::InvalidParam => ErrorKind::InvalidInput,
            Self::Unsupported => ErrorKind::Unsupported,
        }
    }
}

fn spi_result(result: Result<(), crate::error::Error>) -> Result<(), SdCardError> {
    result.map_err(SdCardError::Spi)
}

fn transfer_ff<T, G>(bus: &mut BlockSpi<T, G>, read: &mut [u8]) -> Result<(), SdCardError>
where
    T: blueos_hal::spi::Spi<blueos_driver::spi::SpiConfig, ()>,
    G: blueos_hal::gpio::OutputPin,
{
    let fill = [0xffu8; 64];
    for chunk in read.chunks_mut(fill.len()) {
        spi_result(bus.transfer(chunk, &fill[..chunk.len()]))?;
    }
    Ok(())
}

fn read_byte<T, G>(bus: &mut BlockSpi<T, G>) -> Result<u8, SdCardError>
where
    T: blueos_hal::spi::Spi<blueos_driver::spi::SpiConfig, ()>,
    G: blueos_hal::gpio::OutputPin,
{
    let mut byte = [0u8];
    transfer_ff(bus, &mut byte)?;
    Ok(byte[0])
}

fn send_command<T, G>(
    bus: &mut BlockSpi<T, G>,
    command: u8,
    argument: u32,
    crc: u8,
) -> Result<u8, SdCardError>
where
    T: blueos_hal::spi::Spi<blueos_driver::spi::SpiConfig, ()>,
    G: blueos_hal::gpio::OutputPin,
{
    let packet = [
        0x40 | command,
        (argument >> 24) as u8,
        (argument >> 16) as u8,
        (argument >> 8) as u8,
        argument as u8,
        crc | 1,
    ];
    spi_result(bus.write(&packet))?;
    for _ in 0..R1_RETRIES {
        let response = read_byte(bus)?;
        if response & 0x80 == 0 {
            return Ok(response);
        }
    }
    Err(SdCardError::Timeout)
}

fn wait_token<T, G>(bus: &mut BlockSpi<T, G>, token: u8, retries: usize) -> Result<(), SdCardError>
where
    T: blueos_hal::spi::Spi<blueos_driver::spi::SpiConfig, ()>,
    G: blueos_hal::gpio::OutputPin,
{
    for _ in 0..retries {
        let value = read_byte(bus)?;
        if value == token {
            return Ok(());
        }
        if value != 0xff {
            return Err(SdCardError::DataToken(value));
        }
    }
    Err(SdCardError::Timeout)
}

pub struct SdCard<T, G>
where
    T: blueos_hal::spi::Spi<blueos_driver::spi::SpiConfig, ()>,
    G: blueos_hal::gpio::OutputPin,
{
    spi: ExclusiveSpiWithCs<T, G>,
    sectors: u64,
    high_capacity: bool,
}

impl<T, G> SdCard<T, G>
where
    T: blueos_hal::spi::Spi<blueos_driver::spi::SpiConfig, ()>,
    G: blueos_hal::gpio::OutputPin,
{
    fn new(spi: ExclusiveSpiWithCs<T, G>) -> Self {
        Self {
            spi,
            sectors: 0,
            high_capacity: false,
        }
    }

    fn command(&mut self, command: u8, argument: u32, crc: u8) -> Result<u8, SdCardError> {
        self.with_card_selected(|bus| send_command(bus, command, argument, crc))
    }

    /// Run one SD SPI transaction and provide the mandatory trailing clock
    /// after releasing chip select. Without that extra byte some cards keep
    /// their command state active, so the next command receives a stale or
    /// malformed R1 response.
    fn with_card_selected<R>(
        &mut self,
        f: impl FnOnce(&mut BlockSpi<T, G>) -> Result<R, SdCardError>,
    ) -> Result<R, SdCardError> {
        let result = self.spi.with_cs(f);
        let trailing_clock = self.spi.clock_idle(&[0xff]).map_err(SdCardError::Spi);
        match result {
            Ok(value) => trailing_clock.map(|()| value),
            Err(error) => {
                let _ = trailing_clock;
                Err(error)
            }
        }
    }

    fn with_card_selected_config<R>(
        &mut self,
        config: &blueos_driver::spi::SpiConfig,
        f: impl FnOnce(&mut BlockSpi<T, G>) -> Result<R, SdCardError>,
    ) -> Result<R, SdCardError> {
        let result = self.spi.with_cs_config(config, f);
        let trailing_clock = self.spi.clock_idle(&[0xff]).map_err(SdCardError::Spi);
        match result {
            Ok(value) => trailing_clock.map(|()| value),
            Err(error) => {
                let _ = trailing_clock;
                Err(error)
            }
        }
    }

    fn block_address(&self, block_id: usize, index: usize) -> Result<u32, SdCardError> {
        let block = (block_id as u64)
            .checked_add(index as u64)
            .ok_or(SdCardError::InvalidParam)?;
        let address = if self.high_capacity {
            block
        } else {
            block
                .checked_mul(SECTOR_SIZE as u64)
                .ok_or(SdCardError::InvalidParam)?
        };
        if address > u32::MAX as u64 {
            return Err(SdCardError::InvalidParam);
        }
        Ok(address as u32)
    }

    fn initialize(&mut self) -> Result<(), SdCardError> {
        self.spi.clock_idle(&[0xff; 10]).map_err(SdCardError::Spi)?;

        let response = self.command(CMD0, 0, 0x95).map_err(|error| match error {
            SdCardError::Timeout => SdCardError::NoCard,
            error => error,
        })?;
        if response != 0x01 {
            return Err(SdCardError::Response(response));
        }

        let cmd8 = self.with_card_selected(|bus| {
            let response = send_command(bus, CMD8, 0x1aa, 0x87)?;
            if response == 0x01 {
                let mut r7 = [0u8; 4];
                transfer_ff(bus, &mut r7)?;
                if r7[2] != 0x01 || r7[3] != 0xaa {
                    return Err(SdCardError::Response(r7[3]));
                }
            }
            Ok(response)
        })?;
        let v2 = match cmd8 {
            0x01 => true,
            0x05 => false,
            response => return Err(SdCardError::Response(response)),
        };

        let argument = if v2 { 1 << 30 } else { 0 };
        let mut ready = false;
        for _ in 0..INIT_RETRIES {
            let r55 = self.command(CMD55, 0, 0x01)?;
            if r55 > 0x01 && r55 != 0x05 {
                return Err(SdCardError::Response(r55));
            }
            let r41 = self.command(CMD41, argument, 0x01)?;
            if r41 == 0 {
                ready = true;
                break;
            }
            if r41 != 0x01 {
                return Err(SdCardError::Response(r41));
            }
        }
        if !ready {
            return Err(SdCardError::Timeout);
        }

        let ocr = self.with_card_selected(|bus| {
            let response = send_command(bus, CMD58, 0, 0x01)?;
            if response != 0 {
                return Err(SdCardError::Response(response));
            }
            let mut data = [0u8; 4];
            transfer_ff(bus, &mut data)?;
            Ok(u32::from_be_bytes(data))
        })?;
        self.high_capacity = ocr & (1 << 30) != 0;

        let csd = self.with_card_selected(|bus| {
            let response = send_command(bus, CMD9, 0, 0x01)?;
            if response != 0 {
                return Err(SdCardError::Response(response));
            }
            wait_token(bus, DATA_START_TOKEN, INIT_TOKEN_RETRIES)?;
            let mut data = [0u8; 16];
            transfer_ff(bus, &mut data)?;
            let mut crc = [0u8; 2];
            transfer_ff(bus, &mut crc)?;
            Ok(data)
        })?;
        self.sectors = parse_csd_capacity(&csd)?;
        if self.sectors == 0 {
            return Err(SdCardError::InvalidCapacity);
        }

        if !self.high_capacity {
            let response = self.command(CMD16, SECTOR_SIZE as u32, 0x01)?;
            if response != 0 {
                return Err(SdCardError::Response(response));
            }
        }
        Ok(())
    }

    fn read_blocks(&mut self, block_id: usize, buf: &mut [u8]) -> Result<(), SdCardError> {
        if buf.is_empty() || buf.len() % SECTOR_SIZE != 0 {
            return Err(SdCardError::InvalidParam);
        }
        let count = buf.len() / SECTOR_SIZE;
        let end = (block_id as u64)
            .checked_add(count as u64)
            .ok_or(SdCardError::InvalidParam)?;
        if end > self.sectors {
            return Err(SdCardError::InvalidParam);
        }
        for (index, chunk) in buf.chunks_mut(SECTOR_SIZE).enumerate() {
            let address = self.block_address(block_id, index)?;
            self.with_card_selected_config(
                &blueos_driver::spi::SpiConfig::sd_card_default(),
                |bus| {
                    let response = send_command(bus, CMD17, address, 0x01)?;
                    if response != 0 {
                        return Err(SdCardError::Response(response));
                    }
                    wait_token(bus, DATA_START_TOKEN, DATA_TOKEN_RETRIES)?;
                    transfer_ff(bus, chunk)?;
                    let mut crc = [0u8; 2];
                    transfer_ff(bus, &mut crc)?;
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    fn write_blocks(&mut self, block_id: usize, buf: &[u8]) -> Result<(), SdCardError> {
        if buf.is_empty() || buf.len() % SECTOR_SIZE != 0 {
            return Err(SdCardError::InvalidParam);
        }
        let count = buf.len() / SECTOR_SIZE;
        let end = (block_id as u64)
            .checked_add(count as u64)
            .ok_or(SdCardError::InvalidParam)?;
        if end > self.sectors {
            return Err(SdCardError::InvalidParam);
        }
        for (index, chunk) in buf.chunks(SECTOR_SIZE).enumerate() {
            let address = self.block_address(block_id, index)?;
            self.with_card_selected_config(
                &blueos_driver::spi::SpiConfig::sd_card_default(),
                |bus| {
                    let response = send_command(bus, CMD24, address, 0x01)?;
                    if response != 0 {
                        return Err(SdCardError::Response(response));
                    }
                    spi_result(bus.write(&[DATA_START_TOKEN]))?;
                    spi_result(bus.write(chunk))?;
                    spi_result(bus.write(&[0xff, 0xff]))?;
                    let response = read_byte(bus)?;
                    if response & 0x1f != DATA_ACCEPTED {
                        return Err(SdCardError::Response(response));
                    }
                    for _ in 0..BUSY_RETRIES {
                        if read_byte(bus)? == 0xff {
                            return Ok(());
                        }
                    }
                    Err(SdCardError::Timeout)
                },
            )?;
        }
        Ok(())
    }
}

fn parse_csd_capacity(csd: &[u8; 16]) -> Result<u64, SdCardError> {
    match (csd[0] >> 6) & 0x03 {
        1 => {
            let c_size = ((csd[7] as u32 & 0x3f) << 16) | ((csd[8] as u32) << 8) | csd[9] as u32;
            (c_size as u64 + 1)
                .checked_mul(1024)
                .ok_or(SdCardError::InvalidCapacity)
        }
        0 => {
            let read_bl_len = csd[5] & 0x0f;
            let c_size =
                (((csd[6] as u32) & 0x03) << 10) | ((csd[7] as u32) << 2) | ((csd[8] as u32) >> 6);
            let c_size_mult = (((csd[9] as u32) & 0x03) << 1) | ((csd[10] as u32) >> 7);
            let block_len = 1u64
                .checked_shl(read_bl_len.into())
                .ok_or(SdCardError::InvalidCapacity)?;
            let capacity_bytes = (c_size as u64 + 1)
                .checked_mul(1u64 << (c_size_mult + 2))
                .and_then(|value| value.checked_mul(block_len))
                .ok_or(SdCardError::InvalidCapacity)?;
            Ok(capacity_bytes / SECTOR_SIZE as u64)
        }
        _ => Err(SdCardError::Unsupported),
    }
}

pub struct SdCardBlockDriver<T, G>
where
    T: blueos_hal::spi::Spi<blueos_driver::spi::SpiConfig, ()>,
    G: blueos_hal::gpio::OutputPin,
{
    card: SdCard<T, G>,
}

impl<T, G> ErrorType for SdCardBlockDriver<T, G>
where
    T: blueos_hal::spi::Spi<blueos_driver::spi::SpiConfig, ()>,
    G: blueos_hal::gpio::OutputPin,
{
    type Error = BlockError<SdCardError>;
}

impl<T, G> BlockDriverOps for SdCardBlockDriver<T, G>
where
    T: blueos_hal::spi::Spi<blueos_driver::spi::SpiConfig, ()> + Send + Sync,
    G: blueos_hal::gpio::OutputPin + Send + Sync,
{
    fn capacity(&self) -> u64 {
        self.card.sectors
    }

    fn sector_size(&self) -> u16 {
        SECTOR_SIZE as u16
    }

    fn read_blocks(&mut self, block_id: usize, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.card
            .read_blocks(block_id, buf)
            .map_err(BlockError::Driver)
    }

    fn write_blocks(&mut self, block_id: usize, buf: &[u8]) -> Result<(), Self::Error> {
        self.card
            .write_blocks(block_id, buf)
            .map_err(BlockError::Driver)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct SdCardConfig<G: blueos_hal::gpio::OutputPin> {
    pub name: &'static str,
    pub cs: &'static G,
}

impl<G: blueos_hal::gpio::OutputPin> SdCardConfig<G> {
    pub const fn new(name: &'static str, cs: &'static G) -> Self {
        Self { name, cs }
    }
}

impl<T, G> InitDriver<BlockSpi<T, G>> for SdCardConfig<G>
where
    T: blueos_hal::spi::Spi<blueos_driver::spi::SpiConfig, ()> + Send + Sync,
    G: blueos_hal::gpio::OutputPin + Send + Sync,
{
    type Data = ();

    fn init(self, bus: &Bus<BlockSpi<T, G>>) -> crate::drivers::Result<Self::Data> {
        use blueos_driver::spi::SpiConfig;

        bus.intf
            .0
            .lock()
            .configure(&SpiConfig::sd_card_init())
            .map_err(|_| crate::error::code::EIO)?;
        let spi = ExclusiveSpiWithCs::new(bus.intf.clone(), self.cs);
        let mut card = SdCard::new(spi);
        card.initialize().map_err(|error| match error {
            SdCardError::NoCard
            | SdCardError::Response(_)
            | SdCardError::DataToken(_)
            | SdCardError::InvalidCapacity
            | SdCardError::Unsupported => crate::error::code::ENODEV,
            SdCardError::Timeout => crate::error::code::ETIMEDOUT,
            _ => crate::error::code::EIO,
        })?;
        bus.intf
            .0
            .lock()
            .configure(&SpiConfig::sd_card_default())
            .map_err(|_| crate::error::code::EIO)?;

        log::info!("SD card initialized: {} sectors", card.sectors);

        let block_driver = SdCardBlockDriver { card };
        let block = Block::<BlockError<SdCardError>, SECTOR_SIZE>::new(
            self.name,
            Arc::new(SpinLock::new(block_driver)),
        )
        .map_err(|_| crate::error::code::EOVERFLOW)?;
        DeviceManager::get()
            .register_device(String::from(self.name), Arc::new(block))
            .map_err(|_| crate::error::code::EEXIST)?;
        Ok(())
    }
}

pub struct SdCardDriverModule<G> {
    _marker: core::marker::PhantomData<G>,
}

impl<G> SdCardDriverModule<G> {
    pub const fn new() -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }
}

impl<T, G> DriverModule<BlockSpi<T, G>> for SdCardDriverModule<G>
where
    T: blueos_hal::spi::Spi<blueos_driver::spi::SpiConfig, ()> + Send + Sync,
    G: blueos_hal::gpio::OutputPin + Send + Sync,
{
    type Data = SdCardConfig<G>;

    fn probe(dev: &DeviceData) -> crate::drivers::Result<Self::Data> {
        match dev {
            DeviceData::Native(native_dev) if !native_dev.is_attached() => native_dev
                .config::<SdCardConfig<G>>()
                .map(|config| SdCardConfig {
                    name: config.name,
                    cs: config.cs,
                })
                .ok_or(crate::error::code::ENODEV),
            _ => Err(crate::error::code::ENODEV),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blueos_test_macro::test;

    #[test]
    fn parse_sd_v2_capacity() {
        let mut csd = [0u8; 16];
        csd[0] = 0x40;
        csd[8] = 0x0f;
        csd[9] = 0xff;
        assert_eq!(parse_csd_capacity(&csd), Ok(4_194_304));
    }

    #[test]
    fn parse_sd_v1_capacity() {
        let mut csd = [0u8; 16];
        csd[5] = 9;
        csd[8] = 3 << 6;
        assert_eq!(parse_csd_capacity(&csd), Ok(16));
    }
}
