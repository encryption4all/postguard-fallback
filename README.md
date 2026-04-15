# <p align="center"><img src="./img/pg_logo.svg" height="128px" alt="PostGuard" /></p>

> For full documentation, visit [docs.postguard.eu](https://docs.postguard.eu).

Web-based decryption service for PostGuard encrypted messages, also known as TGuard. This is the fallback for users who do not have a PostGuard client installed. They can open encrypted messages in their browser, verify their identity with [Yivi](https://yivi.app), and decrypt the contents.

The project is a Rust workspace with a Rocket backend and a Yew/WASM frontend compiled with Trunk.

## Development

Docker is the recommended way to run the project:

```bash
docker-compose up
./setup.sh
```

The setup script initializes the database. After that, the application is available at http://tguard.localhost.

For manual development without Docker, you need Rust with the WASM target and the `trunk` and `wasm-bindgen-cli` tools:

```bash
rustup target add wasm32-unknown-unknown
cargo install trunk wasm-bindgen-cli
```

## Releasing

There are no automated releases. New versions are built and deployed as Docker images.

## License

MIT
