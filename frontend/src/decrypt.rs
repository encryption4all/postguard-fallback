use core::fmt::Formatter;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures::sink::Sink;
use std::fmt::Display;

use irmaseal_core::api::KeyRequest;
use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::stream::WebUnsealer;
use irmaseal_core::{Attribute, UserSecretKey};

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use wasm_streams::readable::{IntoStream, ReadableStream};
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

struct IntoVec(pub Vec<u8>);

impl Sink<JsValue> for IntoVec {
    type Error = JsValue;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: JsValue) -> Result<(), Self::Error> {
        let arr: Uint8Array = item.dyn_into()?;
        self.get_mut().0.extend_from_slice(arr.to_vec().as_slice());
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
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
        .unwrap()
        .policy
        .timestamp;

    let js_kr = JsValue::from_serde(&keyrequest).or(Err(DecryptError::Failed))?;
    let usk_promise = crate::js_functions::irma_get_usk(js_kr, timestamp);
    let usk_string = JsFuture::from(usk_promise)
        .await
        .or(Err(DecryptError::Failed))?;

    let usk: UserSecretKey<CGWKV> = usk_string.into_serde().unwrap();
    let mut sink = IntoVec(Vec::new());

    unsealer
        .unseal(identifier, &usk, &mut sink)
        .await
        .or(Err(DecryptError::Failed))?;

    Ok(sink.0)
}
