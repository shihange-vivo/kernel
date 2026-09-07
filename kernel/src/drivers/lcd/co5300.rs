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

//! CO5300 AMOLED driver over a QSPI-flash-style transport.

use alloc::vec::Vec;
use core::{
    future::Future,
    marker::PhantomData,
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};

use blueos_driver::spi::SpiConfig;
use display_driver::{
    bus::{DisplayBus, ErrorType, Metadata, QspiFlashBus},
    panel::reset::LCDResetOption,
    Area, ColorFormat, DisplayDriver, DisplayError, FrameControl,
};
use display_driver_co5300::{spec::Co5300Spec, Co5300};

use crate::{
    devices::{
        bus::{Bus, BusWrapper},
        gpio::{GeneralGpio, Level},
        spi_core::block_spi::BlockSpi,
        DeviceData,
    },
    drivers::{DriverModule, InitDriver},
    sync::KernelDelay,
};

/// Physical bus used under [`QspiFlashBus`]. The four-byte command/address
/// header is sent on SIO0; only the payload following opcode 0x32 uses all four
/// data lines. CS remains asserted across both phases.
pub struct QspiDisplayBus<T, G>
where
    T: blueos_hal::spi::Spi<SpiConfig, ()> + blueos_hal::spi::Qspi,
    G: blueos_hal::gpio::OutputPin,
{
    spi: BusWrapper<BlockSpi<T, G>>,
    cs: &'static G,
}

impl<T, G> QspiDisplayBus<T, G>
where
    T: blueos_hal::spi::Spi<SpiConfig, ()> + blueos_hal::spi::Qspi,
    G: blueos_hal::gpio::OutputPin,
{
    fn new(spi: BusWrapper<BlockSpi<T, G>>, cs: &'static G) -> Self {
        Self { spi, cs }
    }

    fn transaction(
        &mut self,
        transfer: impl FnOnce(&mut BlockSpi<T, G>) -> crate::drivers::Result<()>,
    ) -> crate::drivers::Result<()> {
        self.cs.set_low().map_err(|_| crate::error::code::EIO)?;
        let result = transfer(&mut self.spi.0.lock());
        let cs_result = self.cs.set_high().map_err(|_| crate::error::code::EIO);
        result.and(cs_result)
    }
}

impl<T, G> ErrorType for QspiDisplayBus<T, G>
where
    T: blueos_hal::spi::Spi<SpiConfig, ()> + blueos_hal::spi::Qspi,
    G: blueos_hal::gpio::OutputPin,
{
    type Error = crate::error::Error;
}

impl<T, G> DisplayBus for QspiDisplayBus<T, G>
where
    T: blueos_hal::spi::Spi<SpiConfig, ()> + blueos_hal::spi::Qspi,
    G: blueos_hal::gpio::OutputPin,
{
    async fn write_cmd(&mut self, cmd: &[u8]) -> Result<(), Self::Error> {
        self.transaction(|spi| spi.write(cmd))
    }

    async fn write_cmd_with_params(
        &mut self,
        cmd: &[u8],
        params: &[u8],
    ) -> Result<(), Self::Error> {
        self.transaction(|spi| {
            spi.write(cmd)?;
            spi.write(params)
        })
    }

    async fn write_pixels(
        &mut self,
        cmd: &[u8],
        data: &[u8],
        _metadata: Metadata,
    ) -> Result<(), DisplayError<Self::Error>> {
        let header: &[u8; 4] = cmd
            .try_into()
            .map_err(|_| DisplayError::BusError(crate::error::code::EINVAL))?;
        self.transaction(|spi| spi.write_qspi(header, data))
            .map_err(DisplayError::BusError)
    }
}

type Co5300Display<T, G, S> = DisplayDriver<
    QspiFlashBus<QspiDisplayBus<T, G>>,
    Co5300<S, GeneralGpio<G>, QspiFlashBus<QspiDisplayBus<T, G>>>,
>;

/// Kernel-facing synchronous LCD object.
///
/// CO5300 accepts only even X/Y origins and even width/height. A one-row cache
/// lets ordinary framebuffer writes be combined into valid two-row panel
/// transactions without allocating a full-screen shadow buffer. A full shadow
/// for the common 410x502 panel would consume more than 400 KiB and cannot fit
/// alongside the kernel in ESP32-C6 HP RAM.
pub struct Co5300Lcd<T, G, S>
where
    T: blueos_hal::spi::Spi<SpiConfig, ()> + blueos_hal::spi::Qspi,
    G: blueos_hal::gpio::OutputPin,
    S: Co5300Spec,
{
    display: Co5300Display<T, G, S>,
    even_row_cache: Vec<u8>,
    cached_even_row: Option<u16>,
    width: u16,
    height: u16,
}

impl<T, G, S> Co5300Lcd<T, G, S>
where
    T: blueos_hal::spi::Spi<SpiConfig, ()> + blueos_hal::spi::Qspi,
    G: blueos_hal::gpio::OutputPin,
    S: Co5300Spec,
{
    fn init(
        bus: QspiDisplayBus<T, G>,
        reset: Option<GeneralGpio<G>>,
    ) -> crate::drivers::Result<Self> {
        let reset = match reset {
            Some(reset) => LCDResetOption::new_pin(reset),
            None => LCDResetOption::None,
        };
        let panel = Co5300::<S, GeneralGpio<G>, QspiFlashBus<QspiDisplayBus<T, G>>>::new(reset);
        let mut delay = BlockingKernelDelay(KernelDelay);
        let display = block_on_sync(
            DisplayDriver::builder(QspiFlashBus::new(bus), panel)
                .with_color_format(ColorFormat::RGB565)
                .init(&mut delay),
        )
        .map_err(|_| crate::error::code::EINVAL)?;

        let width = S::PHYSICAL_WIDTH;
        let height = S::PHYSICAL_HEIGHT;
        let row_len = usize::from(width)
            .checked_mul(super::LCD_BYTES_PER_PIXEL as usize)
            .ok_or(crate::error::code::ENOMEM)?;

        Ok(Self {
            display,
            even_row_cache: alloc::vec![0; row_len],
            cached_even_row: None,
            width,
            height,
        })
    }

    fn aligned_row(
        source: &[u8],
        source_x: u32,
        clipped_end_x: u32,
        aligned_x: u32,
        aligned_end_x: u32,
    ) -> Result<Vec<u8>, super::LcdError> {
        let bytes_per_pixel = super::LCD_BYTES_PER_PIXEL as usize;
        let aligned_pixels =
            usize::try_from(aligned_end_x - aligned_x).map_err(|_| super::LcdError::InvalidArea)?;
        let mut row = alloc::vec![0; aligned_pixels * bytes_per_pixel];
        let destination_pixel =
            usize::try_from(source_x - aligned_x).map_err(|_| super::LcdError::InvalidArea)?;
        let copy_pixels = usize::try_from(clipped_end_x - source_x + 1)
            .map_err(|_| super::LcdError::InvalidArea)?;
        let destination = destination_pixel * bytes_per_pixel;
        let copy_bytes = copy_pixels * bytes_per_pixel;
        row[destination..destination + copy_bytes].copy_from_slice(&source[..copy_bytes]);

        // Repeat edge pixels for the one-pixel expansion needed by odd X
        // origins/ends. This avoids touching unrelated memory or reading GRAM.
        if destination_pixel != 0 {
            let first = source
                .get(..bytes_per_pixel)
                .ok_or(super::LcdError::InvalidColorData)?;
            row[..bytes_per_pixel].copy_from_slice(first);
        }
        if aligned_end_x > clipped_end_x + 1 {
            let last = source
                .get(copy_bytes - bytes_per_pixel..copy_bytes)
                .ok_or(super::LcdError::InvalidColorData)?;
            let end = row.len();
            row[end - bytes_per_pixel..].copy_from_slice(last);
        }
        Ok(row)
    }

    fn cache_even_row(
        &mut self,
        panel_y: u16,
        aligned_x: u32,
        row: &[u8],
    ) -> Result<(), super::LcdError> {
        if self.cached_even_row != Some(panel_y) {
            self.even_row_cache.fill(0);
            self.cached_even_row = Some(panel_y);
        }
        let bytes_per_pixel = super::LCD_BYTES_PER_PIXEL as usize;
        let start = usize::try_from(aligned_x)
            .ok()
            .and_then(|x| x.checked_mul(bytes_per_pixel))
            .ok_or(super::LcdError::InvalidArea)?;
        let end = start
            .checked_add(row.len())
            .ok_or(super::LcdError::InvalidColorData)?;
        self.even_row_cache
            .get_mut(start..end)
            .ok_or(super::LcdError::InvalidArea)?
            .copy_from_slice(row);
        Ok(())
    }

    fn cached_aligned_row(
        &self,
        aligned_x: u32,
        aligned_end_x: u32,
    ) -> Result<Vec<u8>, super::LcdError> {
        let bytes_per_pixel = super::LCD_BYTES_PER_PIXEL as usize;
        let start = usize::try_from(aligned_x)
            .ok()
            .and_then(|x| x.checked_mul(bytes_per_pixel))
            .ok_or(super::LcdError::InvalidArea)?;
        let end = usize::try_from(aligned_end_x)
            .ok()
            .and_then(|x| x.checked_mul(bytes_per_pixel))
            .ok_or(super::LcdError::InvalidArea)?;
        self.even_row_cache
            .get(start..end)
            .map(|row| row.to_vec())
            .ok_or(super::LcdError::InvalidArea)
    }

    fn write_row_pair(
        &mut self,
        x: u16,
        y: u16,
        top: &[u8],
        bottom: &[u8],
    ) -> Result<(), super::LcdError> {
        if top.len() != bottom.len() {
            return Err(super::LcdError::InvalidColorData);
        }
        let mut pixels = Vec::with_capacity(top.len() + bottom.len());
        pixels.extend_from_slice(top);
        pixels.extend_from_slice(bottom);
        let width = top.len() / super::LCD_BYTES_PER_PIXEL as usize;
        let area = Area::new(x, y, width as u16, 2);
        block_on_sync(
            self.display
                .write_pixels(area, FrameControl::new_standalone(), &pixels),
        )
        .map_err(|_| super::LcdError::Bus)
    }
}

impl<T, G, S> super::Lcd for Co5300Lcd<T, G, S>
where
    T: blueos_hal::spi::Spi<SpiConfig, ()> + blueos_hal::spi::Qspi,
    G: blueos_hal::gpio::OutputPin,
    S: Co5300Spec,
{
    fn draw_area(&mut self, area: super::DrawArea, color: &[u8]) -> Result<(), super::LcdError> {
        let source_width = area
            .col_end
            .checked_sub(area.col_start)
            .ok_or(super::LcdError::InvalidArea)?
            + 1;
        let source_height = area
            .row_end
            .checked_sub(area.row_start)
            .ok_or(super::LcdError::InvalidArea)?
            + 1;
        let expected_len = usize::try_from(source_width)
            .ok()
            .and_then(|width| width.checked_mul(source_height as usize))
            .and_then(|pixels| pixels.checked_mul(super::LCD_BYTES_PER_PIXEL as usize))
            .ok_or(super::LcdError::InvalidColorData)?;
        if color.len() != expected_len {
            return Err(super::LcdError::InvalidColorData);
        }

        let panel_width = u32::from(self.width);
        let panel_height = u32::from(self.height);

        // The controller accepts rectangles with even origins and dimensions. Forward an
        // already aligned, unclipped multi-row buffer directly so a batched framebuffer write
        // becomes one QSPI transaction instead of being split into two-row transfers.
        if area.col_end < panel_width
            && area.row_end < panel_height
            && area.col_start & 1 == 0
            && area.row_start & 1 == 0
            && source_width & 1 == 0
            && source_height & 1 == 0
        {
            let panel_area = Area::new(
                area.col_start as u16,
                area.row_start as u16,
                source_width as u16,
                source_height as u16,
            );
            block_on_sync(self.display.write_pixels(
                panel_area,
                FrameControl::new_standalone(),
                color,
            ))
            .map_err(|_| super::LcdError::Bus)?;
            self.cached_even_row = None;
            return Ok(());
        }

        if area.col_start >= panel_width || area.row_start >= panel_height {
            return Ok(());
        }
        let clipped_end_x = area.col_end.min(panel_width - 1);
        let clipped_end_y = area.row_end.min(panel_height - 1);
        let x0 = area.col_start & !1;
        let x1 = ((clipped_end_x + 2) & !1).min(panel_width);
        let source_stride = usize::try_from(source_width)
            .ok()
            .and_then(|width| width.checked_mul(super::LCD_BYTES_PER_PIXEL as usize))
            .ok_or(super::LcdError::InvalidColorData)?;
        let clipped_row_bytes = usize::try_from(clipped_end_x - area.col_start + 1)
            .ok()
            .and_then(|width| width.checked_mul(super::LCD_BYTES_PER_PIXEL as usize))
            .ok_or(super::LcdError::InvalidColorData)?;

        let mut y = area.row_start;
        while y <= clipped_end_y {
            let source_row = usize::try_from(y - area.row_start)
                .ok()
                .and_then(|row| row.checked_mul(source_stride))
                .ok_or(super::LcdError::InvalidColorData)?;
            let source = color
                .get(source_row..source_row + clipped_row_bytes)
                .ok_or(super::LcdError::InvalidColorData)?;
            let current = Self::aligned_row(source, area.col_start, clipped_end_x, x0, x1)?;

            if y & 1 == 0 {
                self.cache_even_row(y as u16, x0, &current)?;
                let top = self.cached_aligned_row(x0, x1)?;
                if y < clipped_end_y {
                    let next_source_row = source_row
                        .checked_add(source_stride)
                        .ok_or(super::LcdError::InvalidColorData)?;
                    let next_source = color
                        .get(next_source_row..next_source_row + clipped_row_bytes)
                        .ok_or(super::LcdError::InvalidColorData)?;
                    let bottom =
                        Self::aligned_row(next_source, area.col_start, clipped_end_x, x0, x1)?;
                    self.write_row_pair(x0 as u16, y as u16, &top, &bottom)?;
                    y += 2;
                } else {
                    self.write_row_pair(x0 as u16, y as u16, &top, &top)?;
                    y += 1;
                }
            } else {
                let top = if self.cached_even_row == Some((y - 1) as u16) {
                    self.cached_aligned_row(x0, x1)?
                } else {
                    current.clone()
                };
                self.write_row_pair(x0 as u16, (y - 1) as u16, &top, &current)?;
                y += 1;
            }
        }
        Ok(())
    }
}

pub struct Co5300Config<G, S>
where
    G: blueos_hal::gpio::OutputPin,
    S: Co5300Spec,
{
    pub rst: Option<&'static G>,
    pub cs: &'static G,
    _spec: PhantomData<S>,
}

impl<G, S> Co5300Config<G, S>
where
    G: blueos_hal::gpio::OutputPin,
    S: Co5300Spec,
{
    pub const fn new(cs: &'static G) -> Self {
        Self {
            rst: None,
            cs,
            _spec: PhantomData,
        }
    }

    pub const fn new_with_reset(rst: &'static G, cs: &'static G) -> Self {
        Self {
            rst: Some(rst),
            cs,
            _spec: PhantomData,
        }
    }
}

impl<T, G, S> InitDriver<BlockSpi<T, G>> for Co5300Config<G, S>
where
    T: blueos_hal::spi::Spi<SpiConfig, ()> + blueos_hal::spi::Qspi,
    G: blueos_hal::gpio::OutputPin,
    S: Co5300Spec + 'static,
{
    type Data = ();

    fn init(self, bus: &Bus<BlockSpi<T, G>>) -> crate::drivers::Result<Self::Data> {
        let reset = self
            .rst
            .map(|reset| GeneralGpio::new(reset, Some(Level::High)));
        let qspi = QspiDisplayBus::new(bus.intf.clone(), self.cs);
        let display = Co5300Lcd::<T, G, S>::init(qspi, reset)?;
        super::LcdFramebuffer::register_lcd(
            display,
            u32::from(S::PHYSICAL_WIDTH),
            u32::from(S::PHYSICAL_HEIGHT),
        )
        .map_err(|_| crate::error::code::EINVAL)?;
        log::debug!(
            "CO5300 initialized successfully ({}x{})",
            S::PHYSICAL_WIDTH,
            S::PHYSICAL_HEIGHT
        );
        Ok(())
    }
}

pub struct Co5300DriverModule<G, S> {
    _marker: PhantomData<(G, S)>,
}

impl<G, S> Co5300DriverModule<G, S> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<T, G, S> DriverModule<BlockSpi<T, G>> for Co5300DriverModule<G, S>
where
    T: blueos_hal::spi::Spi<SpiConfig, ()> + blueos_hal::spi::Qspi,
    G: blueos_hal::gpio::OutputPin,
    S: Co5300Spec + 'static,
{
    type Data = Co5300Config<G, S>;

    fn probe(dev: &DeviceData) -> crate::drivers::Result<Self::Data> {
        match dev {
            DeviceData::Native(native_dev) if !native_dev.is_attached() => native_dev
                .config::<Co5300Config<G, S>>()
                .map(|config| Co5300Config {
                    rst: config.rst,
                    cs: config.cs,
                    _spec: PhantomData,
                })
                .ok_or(crate::error::code::ENODEV),
            _ => Err(crate::error::code::ENODEV),
        }
    }
}

/// Async vendor APIs are backed by a blocking register-level bus. Polling them
/// locally avoids depending on the kernel async scheduler during early boot.
fn block_on_sync<F: Future>(future: F) -> F::Output {
    fn clone(_: *const ()) -> RawWaker {
        raw_waker()
    }
    fn no_op(_: *const ()) {}
    fn raw_waker() -> RawWaker {
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTABLE)
    }

    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut context = Context::from_waker(&waker);
    let mut future = core::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => core::hint::spin_loop(),
        }
    }
}

struct BlockingKernelDelay(KernelDelay);

impl embedded_hal_async::delay::DelayNs for BlockingKernelDelay {
    async fn delay_ns(&mut self, ns: u32) {
        embedded_hal::delay::DelayNs::delay_ns(&mut self.0, ns);
    }
}
