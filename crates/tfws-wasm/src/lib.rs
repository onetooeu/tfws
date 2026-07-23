#![forbid(unsafe_code)]

use tfws_core::Manifest;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn validate_manifest(json: &str) -> bool {
    match serde_json::from_str::<Manifest>(json) {
        Ok(manifest) => manifest.validate().is_ok(),
        Err(_) => false,
    }
}
