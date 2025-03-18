# Mostro Chat

`mostro-chat` is a minimalist peer-to-peer chat application written in Rust, utilizing the Nostr protocol for decentralized and secure communication. It integrates the `nostr-sdk` for event handling and encryption, and features a terminal-based user interface (TUI) built with `ratatui` and `crossterm`.

## Features

- **Peer-to-Peer Messaging**: Direct communication between users without centralized servers.
- **End-to-End Encryption**: Messages are encrypted using a shared key derived from ECDH (Elliptic Curve Diffie-Hellman).
- **Simplified NIP-59**: Implements a non-standard version of NIP-59 for event wrapping and encryption.
- **Proof of Work**: Applies a configurable proof-of-work requirement to outgoing messages to deter spam.
- **Time-Based Filtering**: Displays messages from the last `N` seconds (default: 600 seconds).

## Prerequisites

- **Rust**: Install Rust from [rust-lang.org](https://www.rust-lang.org/) if you haven’t already.
- **Nostr Relay**: The app connects to `wss://relay.mostro.network`. Ensure access to this relay or use another relay.

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
The application requires two arguments:
```
    -s, --sender-secret <SENDER_SECRET>: Your private key (in hex or bech32 format, e.g., nsec1...).
    -p, --receiver-pubkey <RECEIVER_PUBKEY>: The recipient’s public key (in hex or bech32 format, e.g., npub1...).
```
Example:
```sh
cargo run --release -- -s nsec1yourprivatekeyhere -p npub1recipientpubkeyhere
```

## Controls
* Input Field: Type your message in the bottom section of the TUI.
* Send Message: Press Enter to send the typed message.
* Exit: Press Esc to quit the application.

## Message Display
* Messages appear in the main area.
* Only messages from the last 10 minutes (600 seconds) are shown by default.
* Sent messages are prefixed with "You: ".
* Received messages are prefixed with "Counterpart: ".

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
