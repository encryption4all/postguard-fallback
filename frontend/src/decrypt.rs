use core::fmt::Formatter;
use irmaseal_core::api::KeyRequest;
use std::fmt::Display;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::stream::WebUnsealer;
use irmaseal_core::{Attribute, UserSecretKey};
use wasm_streams::readable::{IntoStream, ReadableStream};
use wasm_streams::writable::WritableStream;

use web_sys::File as WebFile;

use crate::attributes::EMAIL_ATTRIBUTE_IDENTIFIER;

#[derive(Debug, PartialEq)]
pub enum DecryptError {
    Deserialize,
    Failed,
    Unknown,
}

impl Display for DecryptError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptError::Deserialize => write!(f, "failed to deserialize"),
            DecryptError::Failed => write!(f, "failed to decrypt"),
            DecryptError::Unknown => write!(f, "unknown file type"),
        }
    }
}

pub async fn read_metadata(file: &WebFile) -> WebUnsealer<IntoStream<'static>> {
    let read = ReadableStream::from_raw(file.stream().dyn_into().unwrap_throw()).into_stream();
    let unsealer = WebUnsealer::new(read).await.unwrap_throw();
    unsealer
}

pub async fn decrypt_file(
    unsealer: &mut WebUnsealer<IntoStream<'static>>,
    identifier: &str,
) -> Result<Vec<u8>, DecryptError> {
    let keyrequest = KeyRequest {
        con: vec![Attribute::new(EMAIL_ATTRIBUTE_IDENTIFIER, Some(identifier))],
        validity: None,
    };

    let timestamp = unsealer
        .meta
        .policies
        .get(identifier)
        .unwrap() // TODO: can panic when user inputs wrong identifier
        .policy
        .timestamp;

    let js_kr = JsValue::from_serde(&keyrequest).or(Err(DecryptError::Failed))?;
    let usk_promise = crate::js_functions::irma_get_usk(js_kr, timestamp);
    let usk_string = JsFuture::from(usk_promise)
        .await
        .or(Err(DecryptError::Failed))?;

    let usk: UserSecretKey<CGWKV> = usk_string.into_serde().unwrap();
    let recording = crate::js_functions::RecordingWritableStream::new();
    let mut write = WritableStream::from_raw(recording.stream()).into_sink();

    unsealer
        .unseal(identifier, &usk, &mut write)
        .await
        .or(Err(DecryptError::Failed))?;

    Ok(recording.written())
}
