use common::DownloadResult;
use js_sys::{Promise, Uint8Array};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{
    prelude::{wasm_bindgen, JsValue},
    JsCast,
};
use wasm_bindgen_futures::JsFuture;

use crate::actions::SendError;
use std::collections::HashMap;
use web_sys::{Request, RequestInit, Response};

#[derive(Deserialize, Serialize)]
pub struct IrmaSession {
    pub attribute_identifier: String,
    pub attribute_value: String,
    pub timestamp: u64,
}

#[wasm_bindgen(module = "/script/js_functions.js")]
extern "C" {
    pub async fn encrypt(message: String, key: &[u8], iv: &[u8]) -> JsValue;
    pub async fn decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> JsValue;
    pub async fn decrypt_cfb_hmac(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> JsValue;
    pub async fn irma_sign(hash: String) -> JsValue;
    pub fn irma_get_usk(session: JsValue, timestamp: u64) -> Promise;
}

pub async fn download_bytes(url: &str) -> Option<Vec<u8>> {
    let window = web_sys::window()?;
    let response = JsFuture::from(window.fetch_with_str(url)).await.ok()?;
    let response: Response = response.dyn_into().ok()?;
    let data = JsFuture::from(response.array_buffer().ok()?).await.ok()?;
    Some(Uint8Array::new(&data).to_vec())
}

pub async fn download(id: &str) -> Option<DownloadResult> {
    let data = download_bytes(&format!("/api/download/{}", id)).await?;
    Some(serde_json::from_slice(&data).ok()?)
}

#[derive(Deserialize)]
struct PublicKeyResponse {
    public_key: String,
}

pub async fn get_public_key() -> Option<String> {
    let data = download_bytes("https://postguard.eu/pkg").await?;
    Some(
        serde_json::from_slice::<PublicKeyResponse>(&data)
            .ok()?
            .public_key,
    )
}

#[cfg(feature = "send")]
pub async fn send_message(body: &str) -> Result<(), SendError> {
    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.body(Some(&body.into()));

    let request = Request::new_with_str_and_init("/api", &opts).map_err(|_| SendError::NotSent)?;

    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|_| SendError::NotSent)?;

    let window = web_sys::window().ok_or(SendError::NotSent)?;
    let response: Response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| SendError::NotSent)?
        .dyn_into()
        .map_err(|_| SendError::NotSent)?;

    if response.status() >= 200 && response.status() < 300 {
        Ok(())
    } else if response.status() == 413 {
        Err(SendError::TooLarge)
    } else {
        Err(SendError::NotSent)
    }
}

#[cfg(feature = "sign")]
pub async fn verify_signature(signature: &str) -> Option<HashMap<String, String>> {
    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.body(Some(&signature.into()));
    let request = Request::new_with_str_and_init("/api/verify", &opts).ok()?;

    request
        .headers()
        .set("Content-Type", "application/json")
        .ok()?;

    let window = web_sys::window()?;
    let response: Response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .ok()?
        .dyn_into()
        .ok()?;
    if response.status() >= 200 && response.status() < 300 {
        let data = JsFuture::from(response.array_buffer().ok()?).await.ok()?;
        let data = Uint8Array::new(&data).to_vec();
        Some(serde_json::from_slice(&data).ok()?)
    } else {
        None
    }
}
