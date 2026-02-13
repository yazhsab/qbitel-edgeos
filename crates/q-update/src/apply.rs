// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 Qbitel Inc.

//! Update application

use q_common::Error;
use q_hal::FlashInterface;

/// Apply update to flash
pub fn apply_update<F: FlashInterface>(
    flash: &mut F,
    target_address: u32,
    image: &[u8],
) -> Result<(), Error> {
    // Unlock flash
    flash.unlock().map_err(|_| Error::FlashError)?;

    // Erase target region
    let end_address = target_address + image.len() as u32;
    flash.erase_range(target_address, end_address)
        .map_err(|_| Error::FlashError)?;

    // Write image
    flash.write(target_address, image)
        .map_err(|_| Error::FlashError)?;

    // Verify
    if !flash.verify(target_address, image).map_err(|_| Error::FlashError)? {
        return Err(Error::UpdateCorrupted);
    }

    // Lock flash
    flash.lock().map_err(|_| Error::FlashError)?;

    Ok(())
}
