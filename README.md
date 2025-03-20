# Mostro Chat

A a minimalist peer-to-peer chat application written in Rust, utilizing the Nostr protocol for decentralized and secure communication. It integrates the `nostr-sdk` for event handling and encryption, and features a terminal-based user interface (TUI) built with `ratatui` and `crossterm`.

## Features

*   **Private Messaging:** Utilizes Nostr protocol for decentralized communication.
*   **End-to-End Encryption:** Employs NIP-44 for encrypting messages, ensuring privacy.
*   **Terminal Interface:** User-friendly text-based interface powered by Ratatui.
*   **Participant Mode:** Send and receive encrypted messages using your private key and the recipient's public key.
*   **Observer Mode:** View encrypted messages using a shared secret key, without the ability to send messages.
*   **Real-time Updates:** Displays messages in real-time as they are received from the Nostr relay.
*   **Message History:** Shows recent messages within a configurable time window (default: 10 minutes).
*   **Shared Key Display:** Option to display or hide the shared secret key in observer mode.

## Prerequisites

*   **Rust and Cargo:** Ensure you have Rust installed. If not, follow the instructions on the [official Rust website](https://www.rust-lang.org/tools/install).
*   **Nostr Relay:** This application is configured to use `wss://relay.mostro.network` by default. You can modify this in the source code if needed.

## Installation

Clone the repository:

```bash
    git clone https://github.com/MostroP2P/mostro-chat.git
    cd mostro-chat
```

Run the program:

```bash
    cargo run -- -s <sender_secret> -p <receiver_pubkey>
```

## Usage
For chat participants the application requires two arguments:
```
    -s, --sender-secret <SENDER_SECRET>: Your private key (in hex or bech32 format, e.g., nsec1...).
    -p, --receiver-pubkey <RECEIVER_PUBKEY>: The recipient’s public key (in hex or bech32 format, e.g., npub1...).
```
Example:
```sh
cargo run -- -s yourprivatekeyhere -p whoyouwanttotalkpubkeyhere
```

For the observer the application requires only the shared key:
```
    -k, --shared-key <SHARED_KEY>: Shared secret key (hex).
```
Example:
```sh
cargo run -- -k sharedprivatekeyhere
```

## Usage

Once the application is running:

*   **Type your message** in the input area at the bottom of the terminal.
*   **Press `Enter`** to send the message (Participant mode only).
*   **Press `Esc`** to exit the application.
*   **Press `Tab`** to toggle the visibility of the shared secret key in the "Shared Key" area.

## Message Display
* Messages appear in the main area.
* Only messages from the last 10 minutes (600 seconds) are shown by default.
* Sent messages are prefixed with "You: ".
* Received messages are prefixed with "hex_pubkey: ".

## Configuration
The following constants in the code can be modified:

* N_SECONDS: Time window for displaying messages (default: 600 seconds). Edit this in main.rs.
* POW_DIFFICULTY: Proof-of-work difficulty for outgoing messages (default: 2). Adjust in main.rs.
* RELAY_URL: Nostr relay URL (default: wss://relay.mostro.network). Change in main.rs.

## How It Works
**Shared Key Generation:** Uses ECDH with the sender’s private key and receiver’s public key to create a shared key.

**Message Encryption:** Messages are wrapped in a simplified NIP-59 event, encrypted with the shared key, and signed with an ephemeral key.

**Event Subscription:** Subscribes to events targeting the shared key’s public key via the Nostr relay.

**Real-Time Updates:** Decrypts and displays incoming messages in the TUI if they fall within the time window.

## Technical Details

NIP-59 Simplification: The app uses a custom, non-standard NIP-59 implementation for gift-wrapped events.

Asynchronous Handling: Employs tokio for managing Nostr client tasks and TUI updates concurrently.

You can find more information about [here](https://mostro.network/protocol/chat.html)

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing
Contributions are encouraged! Feel free to open issues or submit pull requests on GitHub.
