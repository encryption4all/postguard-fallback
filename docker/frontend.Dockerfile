FROM rust:bullseye

RUN apt update
RUN apt install -y nodejs yarnpkg

RUN cargo install --locked trunk wasm-bindgen-cli;

RUN rustup target add wasm32-unknown-unknown;
