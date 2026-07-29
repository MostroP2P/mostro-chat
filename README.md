# Mostro Chat

A a minimalist peer-to-peer chat application written in Rust, utilizing the Nostr protocol for decentralized and secure communication. It integrates the `nostr-sdk` for event handling and encryption, and features a terminal-based user interface (TUI) built with `ratatui` and `crossterm`.

## Features

*   **Private Messaging:** Utilizes Nostr protocol for decentralized communication.
*   **End-to-End Encryption:** Employs NIP-44 for encrypting messages, ensuring privacy.
*   **Terminal Interface:** User-friendly text-based interface powered by Ratatui.
*   **Participant Mode:** Send and receive encrypted messages using your private key and the recipient's public key.
*   **Observer Mode:** Read a conversation with `K_conv`, which cannot sign — read-only is enforced by the key derivation, not by the UI.
*   **Flood Resistant:** Only the two parties can author events in a conversation, so relays discard third-party traffic before it reaches the client.
*   **Real-time Updates:** Displays messages in real-time as they are received from the Nostr relay.
*   **Message History:** Shows recent messages within a configurable time window (default: 10 minutes).
*   **Conversation Key Display:** Option to display or hide `K_conv`, the key you would hand to a dispute solver.

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

For a read-only observer the application requires the conversation key:
```
    -k, --conversation-key <CONVERSATION_KEY>: Conversation key K_conv (hex).
    -a, --author <AUTHOR>: Optional pub(K_sign) (hex), to filter by author instead of by tag.
```
Example:
```sh
cargo run -- -k conversationkeyhere
```

`K_conv` decrypts the conversation but cannot sign for it, so an observer is
**read-only by construction** rather than by convention — this is how a party
hands a dispute solver the transcript without also handing over the ability to
write into it. Press `Tab` in participant mode to reveal the key to share.

## Usage

Once the application is running:

*   **Type your message** in the input area at the bottom of the terminal.
*   **Press `Enter`** to send the message (Participant mode only).
*   **Press `Esc`** to exit the application.
*   **Press `Tab`** to toggle the visibility of `K_conv` in the "Conversation key" area.

## Message Display
* Messages appear in the main area.
* Only messages from the last 10 minutes (600 seconds) are shown by default.
* Sent messages are prefixed with "You: ".
* Received messages are prefixed with "hex_pubkey: ".

## Configuration
The following constants in the code can be modified:

* N_SECONDS: Time window for displaying messages (default: 600 seconds). Edit this in main.rs.
* MAX_CLOCK_SKEW_SECS: Tolerance for clock skew, applied both between the inner and outer timestamps and against the local clock (default: 60).
* MAX_CONTENT_BYTES: Largest encrypted payload accepted before decrypting (default: 64 KiB).
* RATE_PER_MINUTE / RATE_BURST: Token bucket bounding how fast the counterparty can make us work (default: 30/min, burst 60).
* RELAY_URL: Nostr relay URL (default: wss://relay.mostro.network). Change in main.rs.

## How It Works
**Key derivation:** ECDH between the two parties' keys produces a shared secret, which HKDF-SHA256 splits into `K_conv` (encryption, and the `p` tag) and `K_sign` (signs the outer event). Both sides derive the same pair; neither key can be computed from the other.

**Message encryption:** A kind 1 event carrying the message is signed with the sender's own key, NIP-44 encrypted under `K_conv`, and placed in the content of a **kind 14** event signed with `K_sign`. There is no gift wrap and no ephemeral key.

**Event subscription:** Subscribes filtering by `authors = [pub(K_sign)]`. Only someone holding a party's private key can produce that signature, so the relay drops everything else. Filtering by the `p` tag instead would let anyone who has observed that tag flood the conversation.

**Validation:** Incoming events are checked cheapest-first — author, `p` tag, timestamp bounds, size, duplicates, rate limit — before any decryption, and the inner signature is what authenticates the sender.

**Real-time updates:** Decrypts and displays incoming messages in the TUI if they fall within the time window.

## Technical Details

Wire format: implements the [Mostro peer-to-peer chat specification](https://mostro.network/protocol/chat.html), which replaced the previous simplified NIP-59 gift wrap. The ephemeral outer key it used added no privacy — the `p` tag already points at an anonymous per-conversation key — while making participants indistinguishable from attackers, so any observer could harvest a conversation's address from relays and flood it.

Asynchronous Handling: Employs tokio for managing Nostr client tasks and TUI updates concurrently.

You can find more information about [here](https://mostro.network/protocol/chat.html)

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing
Contributions are encouraged! Feel free to open issues or submit pull requests on GitHub.
