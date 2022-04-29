pub mod common;
pub mod index;
pub mod layout;

#[cfg(feature = "download")]
pub mod receive_form;
#[cfg(feature = "send")]
pub mod send_form;
#[cfg(feature = "upload")]
pub mod upload;
