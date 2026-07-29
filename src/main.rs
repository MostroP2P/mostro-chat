use clap::Parser;
use crossterm::{
    event::{self, Event as CrosstermEvent, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
// Leading `::` selects the `hkdf` crate: `nostr_sdk::prelude` also exports a
// module by that name, so a plain `use hkdf::Hkdf` is ambiguous.
use ::hkdf::Hkdf;
use nostr_sdk::prelude::*;
use nostr_sdk::{
    Client, Event, EventBuilder, Keys, Kind, PublicKey, RelayPoolNotification, SecretKey, Tag,
    Timestamp,
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use sha2::Sha256;
use std::{
    collections::{HashSet, VecDeque},
    io,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc::{self, Receiver, Sender};

// Relay URL
const RELAY_URL: &str = "wss://relay.mostro.network";

// We set N in seconds (600 seconds = 10 minutes)
const N_SECONDS: u64 = 600;

/// HKDF `info` strings from the spec. Changing either changes the wire format.
const CONV_INFO: &[u8] = b"mostro:chat:conv:v1";
const SIGN_INFO: &[u8] = b"mostro:chat:sign:v1";

/// Tolerance for clock skew, applied both between the inner and outer
/// `created_at` and against our own clock.
const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Upper bound on the encrypted payload, enforced before decrypting.
const MAX_CONTENT_BYTES: usize = 64 * 1024;

/// Token bucket: sustained rate and burst, per the spec's recommendation.
const RATE_PER_MINUTE: f64 = 30.0;
const RATE_BURST: f64 = 60.0;

/// Capacity of the outer-event id cache. It must be bounded: in observer mode
/// without an author locator the subscription falls back to a `p` tag filter,
/// which anyone can publish to, so an unbounded cache is a memory-exhaustion
/// target.
const SEEN_OUTER_CAP: usize = 4096;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Sender's private key (hex or bech32)
    #[arg(short = 's', long = "sender-secret", requires = "receiver_pubkey")]
    sender_secret: Option<String>,

    /// Receiver's public key (hex or bech32)
    #[arg(short = 'p', long = "receiver-pubkey", requires = "sender_secret")]
    receiver_pubkey: Option<String>,

    /// Conversation key K_conv (hex) — read-only access to a conversation
    #[arg(short = 'k', long = "conversation-key", conflicts_with_all = ["sender_secret", "receiver_pubkey"])]
    conversation_key: Option<String>,

    /// Optional author pub(K_sign) (hex), used with -k to filter by author
    /// instead of by tag. It is a locator, not a secret.
    #[arg(short = 'a', long = "author", requires = "conversation_key")]
    author: Option<String>,
}

/// Derives the domain-separated conversation and signing keys for a
/// conversation, from the ECDH secret shared by the two parties.
///
/// Both sides reach the same pair: the ECDH secret is symmetric and HKDF is
/// deterministic.
fn derive_chat_keys(
    own: &Keys,
    peer: &PublicKey,
) -> Result<(Keys, Keys), Box<dyn std::error::Error>> {
    let shared = nostr_sdk::util::generate_shared_key(own.secret_key(), peer)?;
    let hkdf = Hkdf::<Sha256>::new(None, &shared);

    let derive = |info: &[u8]| -> Result<Keys, Box<dyn std::error::Error>> {
        // Retry with a counter byte on the negligible chance that the output
        // is not a valid secp256k1 secret key.
        for counter in 0u16..=255 {
            let mut labelled = info.to_vec();
            if counter > 0 {
                labelled.push(counter as u8);
            }
            let mut out = [0u8; 32];
            hkdf.expand(&labelled, &mut out)
                .map_err(|e| format!("HKDF expand failed: {e}"))?;
            if let Ok(sk) = SecretKey::from_slice(&out) {
                return Ok(Keys::new(sk));
            }
        }
        Err("HKDF failed to produce a valid secret key".into())
    };

    Ok((derive(CONV_INFO)?, derive(SIGN_INFO)?))
}

/// Token bucket used to bound how much work an abusive counterparty can force.
/// The counterparty is the only party who can publish here, and it is a single
/// stable author, so a per-conversation bucket is enough.
struct RateLimiter {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            tokens: RATE_BURST,
            last: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * (RATE_PER_MINUTE / 60.0)).min(RATE_BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Fixed-capacity set of recently seen event ids, evicting oldest first.
///
/// Only used for the *outer* id, which the spec describes as a cheap
/// pre-decryption filter against duplicate relay deliveries and gives no
/// security role — so dropping old entries is safe. Inner ids are kept
/// separately and unbounded, since only events that decrypt under `K_conv`
/// ever reach that set and replay protection depends on it.
struct RecentIds {
    set: HashSet<EventId>,
    order: VecDeque<EventId>,
    cap: usize,
}

impl RecentIds {
    fn new(cap: usize) -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::with_capacity(cap),
            cap,
        }
    }

    /// Records `id`, returning `true` when it had not been seen.
    fn insert(&mut self, id: EventId) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > self.cap
            && let Some(evicted) = self.order.pop_front()
        {
            self.set.remove(&evicted);
        }
        true
    }
}

struct App {
    messages: Arc<Mutex<Vec<(Timestamp, PublicKey, String)>>>, // (timestamp, sender pubkey, message)
    input: String,
    tx: Option<Sender<String>>, // Only used in participant mode
    sender_keys: Option<Keys>,  // Only used in participant mode
    conv_key_display: String,
    is_observer: bool,           // Read-only mode (with -k)
    is_shared_key_visible: bool, // Controls visibility of K_conv
}

impl App {
    fn new(
        messages: Arc<Mutex<Vec<(Timestamp, PublicKey, String)>>>,
        tx: Option<Sender<String>>,
        sender_keys: Option<Keys>,
        conv_keys: &Keys,
        is_observer: bool,
    ) -> Self {
        let conv_key_display = conv_keys.secret_key().to_secret_hex();
        Self {
            messages,
            input: String::new(),
            tx,
            sender_keys,
            conv_key_display,
            is_observer,
            is_shared_key_visible: false,
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    let conv_keys: Keys;
    // Observers hold K_conv only. K_sign cannot be derived from it — HKDF is
    // one-way — so their access is cryptographically read-only.
    let mut sign_keys: Option<Keys> = None;
    let mut sender_keys: Option<Keys> = None;
    let mut allowed_signers: Option<Vec<PublicKey>> = None;
    let mut author_locator: Option<PublicKey> = None;
    let is_observer = args.conversation_key.is_some();

    if let Some(conv_hex) = args.conversation_key {
        // Observer mode: read-only access granted by disclosing K_conv.
        let sk = SecretKey::from_str(&conv_hex).expect("Invalid conversation key");
        conv_keys = Keys::new(sk);
        author_locator = args
            .author
            .as_deref()
            .map(|a| PublicKey::from_str(a).expect("Invalid author pubkey"));
    } else {
        // Participant mode: derive both keys from the ECDH secret.
        let sender_secret = args.sender_secret.expect("Sender secret is required");
        let receiver_pubkey_str = args.receiver_pubkey.expect("Receiver pubkey is required");

        let sender = Keys::parse(&sender_secret).expect("Invalid sender's private key");
        let receiver_pubkey =
            PublicKey::from_str(&receiver_pubkey_str).expect("Invalid recipient public key");

        let (conv, sign) =
            derive_chat_keys(&sender, &receiver_pubkey).expect("Error deriving chat keys");
        conv_keys = conv;
        sign_keys = Some(sign);
        allowed_signers = Some(vec![sender.public_key(), receiver_pubkey]);
        sender_keys = Some(sender);
    }

    // Init terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Set channel and messages
    let (tx, rx) = if !is_observer {
        let (tx, rx) = mpsc::channel(100);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let messages = Arc::new(Mutex::new(Vec::new()));

    let app = App::new(
        messages.clone(),
        tx,
        sender_keys.clone(),
        &conv_keys,
        is_observer,
    );
    let nostr_handle = tokio::spawn(run_nostr(
        sender_keys,
        conv_keys,
        sign_keys,
        allowed_signers,
        author_locator,
        rx,
        messages.clone(),
    ));

    let result = run_app(&mut terminal, app).await;

    // Clean up
    nostr_handle.abort();
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    mut app: App,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| {
            let chunks = Layout::vertical([
                Constraint::Percentage(70), // Messages area
                Constraint::Percentage(15), // Conversation key area
                Constraint::Percentage(15), // Input area
            ])
            .split(f.area());

            // Get the current time in seconds since the UNIX epoch
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Error getting current time")
                .as_secs();

            // Filter messages from the last N seconds
            let messages = app.messages.lock().expect("Error locking messages");
            let recent_messages: Vec<String> = messages
                .iter()
                .filter(|(timestamp, _, _)| now.saturating_sub(timestamp.as_secs()) <= N_SECONDS)
                .map(|(_, pubkey, msg)| {
                    if app.is_observer {
                        // Forensic view: always show who signed the inner event.
                        format!("{}: {}", pubkey, msg)
                    } else if Some(*pubkey) == app.sender_keys.as_ref().map(|k| k.public_key()) {
                        format!("You: {}", msg)
                    } else {
                        format!("{}: {}", pubkey, msg)
                    }
                })
                .collect();

            // Display recent messages
            let lines: Vec<Line> = recent_messages
                .iter()
                .map(|msg| Line::from(Span::raw(msg)))
                .collect();
            let messages_widget = Paragraph::new(lines).block(
                Block::default()
                    .title_top(Line::from("Messages").alignment(Alignment::Left))
                    .title_top(
                        Line::from(Span::styled(
                            "ESC to exit",
                            Style::default().fg(Color::Green),
                        ))
                        .alignment(Alignment::Right),
                    )
                    .borders(Borders::ALL),
            );
            f.render_widget(messages_widget, chunks[0]);

            let key_text = if app.is_shared_key_visible {
                app.conv_key_display.as_str()
            } else {
                &"*".repeat(64)
            };

            // K_conv is the read-only grant: share it to let someone (a dispute
            // solver) read the conversation without being able to write to it.
            let title = if app.is_observer {
                "Conversation key K_conv (read-only)"
            } else {
                "Conversation key K_conv (share for read-only access)"
            };
            let key_widget = Paragraph::new(key_text)
                .style(Style::default().fg(Color::Cyan))
                .block(
                    Block::default()
                        .title(title)
                        .title_top(
                            Line::from(Span::styled(
                                "Tab to Display/Hide",
                                Style::default().fg(Color::Green),
                            ))
                            .alignment(Alignment::Right),
                        )
                        .borders(Borders::ALL),
                );
            f.render_widget(key_widget, chunks[1]);

            // Input field
            let input_title = if app.is_observer {
                "Input (read-only: K_conv cannot sign)"
            } else {
                "Input"
            };
            let input = Paragraph::new(app.input.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().title(input_title).borders(Borders::ALL));
            f.render_widget(input, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(100))?
            && let CrosstermEvent::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Esc => break,
                KeyCode::Char(c) => app.input.push(c),
                KeyCode::Backspace => {
                    app.input.pop();
                }
                KeyCode::Enter => {
                    if !app.input.is_empty() && !app.is_observer {
                        let message = app.input.clone();
                        let now = Timestamp::now();
                        let sender_pubkey = app
                            .sender_keys
                            .as_ref()
                            .map(|k| k.public_key())
                            .expect("participant mode always has sender keys");
                        {
                            let mut messages = app.messages.lock().expect("Error locking messages");
                            messages.push((now, sender_pubkey, message.clone()));
                        }
                        if let Some(tx) = &app.tx
                            && let Err(e) = tx.send(message).await
                        {
                            let mut messages = app.messages.lock().expect("Error locking messages");
                            messages.push((
                                Timestamp::now(),
                                sender_pubkey,
                                format!("Error sending message: {}", e),
                            ));
                        }
                    }
                    app.input.clear();
                }
                KeyCode::Tab => {
                    app.is_shared_key_visible = !app.is_shared_key_visible;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_nostr(
    sender: Option<Keys>,
    conv_keys: Keys,
    sign_keys: Option<Keys>,
    allowed_signers: Option<Vec<PublicKey>>,
    author_locator: Option<PublicKey>,
    rx: Option<Receiver<String>>,
    messages: Arc<Mutex<Vec<(Timestamp, PublicKey, String)>>>,
) {
    let client = Client::new(Keys::generate());
    if let Err(e) = client.add_relay(RELAY_URL).await {
        eprintln!("Error adding relay: {}", e);
        return;
    }
    let _ = client.connect().await;

    // Participants filter by author: only pub(K_sign) can be produced by
    // someone holding a party private key, so the relay drops third-party
    // events before they ever reach us. Filtering by the `p` tag instead would
    // let anyone who has seen that tag flood this subscription.
    //
    // An observer holding only K_conv cannot derive pub(K_sign); it falls back
    // to the tag filter unless the locator was supplied with -a.
    let expected_author = sign_keys
        .as_ref()
        .map(|k| k.public_key())
        .or(author_locator);
    // Bound the backlog, as the spec requires. Without it the relay replays the
    // whole stored history on every start, which both defeats the live rate
    // limit — a burst larger than the bucket is silently truncated — and lets a
    // past flood be re-downloaded on every launch. The UI only renders the last
    // N_SECONDS, so that window is the natural cursor.
    let since = Timestamp::from(Timestamp::now().as_secs().saturating_sub(N_SECONDS));
    let filter = match expected_author {
        Some(author) => nostr_sdk::Filter::new()
            .kind(Kind::PrivateDirectMessage)
            .author(author)
            .since(since),
        None => nostr_sdk::Filter::new()
            .kind(Kind::PrivateDirectMessage)
            .pubkey(conv_keys.public_key())
            .since(since),
    };
    if let Err(e) = client.subscribe(filter, None).await {
        eprintln!("Error subscribing: {}", e);
        return;
    }

    // Our own messages come back on this subscription: we author with the very
    // same K_sign the peer does, so the author filter cannot tell them apart.
    // They are already in the list, added when they were typed.
    let own_pubkey = sender.as_ref().map(|k| k.public_key());

    // Handle outgoing messages (participant mode only)
    if let (Some(sender), Some(sign_keys)) = (sender, sign_keys.clone()) {
        let client_clone = client.clone();
        let conv_clone = conv_keys.clone();
        let messages_clone = messages.clone();
        let own = sender.public_key();
        if let Some(mut rx) = rx {
            tokio::spawn(async move {
                while let Some(message) = rx.recv().await {
                    if let Err(e) =
                        send_message(&client_clone, &sender, &conv_clone, &sign_keys, &message)
                            .await
                    {
                        // The terminal is in alternate-screen mode, so stderr is
                        // invisible: a failed send has to reach the message list
                        // or the user believes it went through.
                        if let Ok(mut messages) = messages_clone.lock() {
                            messages.push((Timestamp::now(), own, format!("[not delivered] {e}")));
                        }
                    }
                }
            });
        }
    }

    // Per-conversation state the validator needs but does not own.
    let mut limiter = RateLimiter::new();
    let mut seen_outer = RecentIds::new(SEEN_OUTER_CAP);
    let mut seen_inner: HashSet<EventId> = HashSet::new();

    let mut notifications = client.notifications();
    while let Ok(notification) = notifications.recv().await {
        let RelayPoolNotification::Event { event, .. } = notification else {
            continue;
        };

        // Cheap checks the validator cannot do for us, in the order the spec
        // prescribes: duplicate wrappers, then the rate-limit budget.
        if !seen_outer.insert(event.id) {
            continue;
        }
        if !limiter.allow() {
            continue;
        }

        let inner = match mostro_unwrap(
            &conv_keys,
            expected_author.as_ref(),
            allowed_signers.as_deref(),
            &event,
            Timestamp::now(),
        ) {
            Ok(inner) => inner,
            Err(_) => continue,
        };

        // Replay guard. In this demo the set lives for the process; a client
        // that persists history MUST persist these ids with it, since an entry
        // that disappears makes its message replayable again.
        if !seen_inner.insert(inner.id) {
            continue;
        }

        // Drop the echo of our own message (see `own_pubkey` above).
        if Some(inner.pubkey) == own_pubkey {
            continue;
        }

        let mut messages = messages.lock().expect("Error locking messages");
        messages.push((inner.created_at, inner.pubkey, inner.content.clone()));
    }
}

async fn send_message(
    client: &Client,
    sender: &Keys,
    conv: &Keys,
    sign: &Keys,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let outer = mostro_wrap(sender, conv, sign, message, vec![]).await?;
    client.send_event(&outer).await?;
    Ok(())
}

/// Builds the outer kind 14 event carrying an encrypted, sender-signed kind 1
/// event.
///
/// The inner event authenticates the sender; the outer event authenticates the
/// conversation and is what clients filter on.
///
/// # Arguments
/// - `sender`: the sender's keys, used to sign the inner event.
/// - `conv`: `K_conv`, used to encrypt and as the `p` tag.
/// - `sign`: `K_sign`, used to sign the outer event.
/// - `message`: the plaintext message.
/// - `extra_tags`: additional tags for the outer event.
pub async fn mostro_wrap(
    sender: &Keys,
    conv: &Keys,
    sign: &Keys,
    message: &str,
    extra_tags: Vec<Tag>,
) -> Result<Event, Box<dyn std::error::Error>> {
    // One timestamp for both events: the real moment the message is sent.
    // Recipients reject a mismatch, which is what makes re-wraps detectable.
    let now = Timestamp::now();

    let inner = EventBuilder::text_note(message)
        .custom_created_at(now)
        .build(sender.public_key())
        .sign(sender)
        .await?;

    // NIP-44 self-encryption: K_conv is both sides of the key exchange.
    let content = nip44::encrypt(
        conv.secret_key(),
        &conv.public_key(),
        inner.as_json(),
        nip44::Version::V2,
    )?;

    // Same bound the receiver applies, enforced here too: publishing an event
    // every recipient will drop would leave the message on our screen while
    // being silently absent for the peer.
    if content.len() > MAX_CONTENT_BYTES {
        return Err("message is too large to send".into());
    }

    // Exactly one `p` tag, ours. A caller-supplied one could hide the message
    // from the `#p` query a dispute solver uses to rebuild the transcript.
    if extra_tags
        .iter()
        .any(|t| t.as_slice().first().map(|s| s.as_str()) == Some("p"))
    {
        return Err("extra_tags must not contain a p tag".into());
    }
    let mut tags = vec![Tag::public_key(conv.public_key())];
    tags.extend(extra_tags);

    let outer = EventBuilder::new(Kind::PrivateDirectMessage, content)
        .tags(tags)
        .custom_created_at(now)
        .sign_with_keys(sign)?;

    Ok(outer)
}

/// Validates an incoming outer event and returns the inner event.
///
/// The rate-limit budget and the event-id caches belong to the caller, which
/// owns the per-conversation state.
///
/// `expected_author` and `allowed_signers` are optional only to support the
/// read-only observer, which may know neither. **A trading client MUST pass
/// both**: without the author check any third party can flood the
/// subscription, and without the signer check any key can claim to be a party
/// to the conversation.
///
/// # Arguments
/// - `conv`: `K_conv`, used to decrypt.
/// - `expected_author`: `pub(K_sign)` of this conversation.
/// - `allowed_signers`: the pubkeys accepted as inner-event signers.
/// - `outer`: the received kind 14 event.
/// - `now`: our current time, for the absolute timestamp bound.
pub fn mostro_unwrap(
    conv: &Keys,
    expected_author: Option<&PublicKey>,
    allowed_signers: Option<&[PublicKey]>,
    outer: &Event,
    now: Timestamp,
) -> Result<Event, Box<dyn std::error::Error>> {
    // A third party cannot produce a valid signature for this author, so this
    // check is what makes flooding impossible. Relays enforce it too, via the
    // `authors` filter; we re-check it locally.
    if let Some(author) = expected_author
        && outer.pubkey != *author
    {
        return Err("outer event is not authored by the conversation signing key".into());
    }
    if outer.kind != Kind::PrivateDirectMessage {
        return Err("outer event is not kind 14".into());
    }

    // Exactly one `p` tag, addressing this conversation. Anything else could be
    // a message engineered to stay out of a dispute solver's `#p` query.
    let conv_hex = conv.public_key().to_hex();
    let mut p_tags = outer
        .tags
        .iter()
        .filter(|t| t.as_slice().first().map(|s| s.as_str()) == Some("p"));
    match (
        p_tags.next().and_then(|t| t.as_slice().get(1).cloned()),
        p_tags.next(),
    ) {
        (Some(pk), None) if pk == conv_hex => {}
        _ => return Err("outer event must carry exactly one p tag for this conversation".into()),
    }

    // Absolute bound against our own clock. Without it a counterparty can date
    // both events far in the future — they agree with each other, so the
    // relative check below passes — and poison a `since` cursor, silencing the
    // conversation until that date. The past is unbounded: catching up after
    // being offline is legitimate.
    if outer.created_at.as_secs() > now.as_secs().saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err("outer event is dated too far in the future".into());
    }

    if outer.content.len() > MAX_CONTENT_BYTES {
        return Err("encrypted payload exceeds the accepted size".into());
    }

    outer.verify()?;

    let decrypted = nip44::decrypt(conv.secret_key(), &conv.public_key(), &outer.content)?;
    let inner = Event::from_json(&decrypted)?;

    // The only authentication of who wrote the message: both parties can sign
    // the outer event, so it cannot tell the two sides apart.
    inner.verify()?;
    if let Some(allowed) = allowed_signers
        && !allowed.contains(&inner.pubkey)
    {
        return Err("inner event is signed by a key that is not a party to this chat".into());
    }
    if inner.kind != Kind::TextNote {
        return Err("inner event is not kind 1".into());
    }

    // Bounds how far back the caller's inner-id dedup has to reach: a re-wrap
    // older than the tolerance is stale and rejected here, while one inside the
    // window is caught by that dedup, never by this check.
    let skew = inner
        .created_at
        .as_secs()
        .abs_diff(outer.created_at.as_secs());
    if skew > MAX_CLOCK_SKEW_SECS {
        return Err("inner and outer timestamps disagree — stale re-wrap".into());
    }

    Ok(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Keys {
        Keys::parse("548f68890c49fa42f104c60352395e60ff030b0b407e955f1eed1400d6c0347a").unwrap()
    }

    fn bob() -> Keys {
        Keys::parse("f258e73f07386d37133718b6127f873dd7c391b8f43b331ff8254034a13d2943").unwrap()
    }

    /// Alice's view of the conversation, then Bob's.
    fn both_sides() -> ((Keys, Keys), (Keys, Keys)) {
        (
            derive_chat_keys(&alice(), &bob().public_key()).unwrap(),
            derive_chat_keys(&bob(), &alice().public_key()).unwrap(),
        )
    }

    fn parties() -> Vec<PublicKey> {
        vec![alice().public_key(), bob().public_key()]
    }

    #[test]
    fn both_parties_derive_the_same_keys() {
        // Arrange / Act
        let ((a_conv, a_sign), (b_conv, b_sign)) = both_sides();

        // Assert
        assert_eq!(a_conv.public_key(), b_conv.public_key());
        assert_eq!(a_sign.public_key(), b_sign.public_key());
        // The two roles must not collide.
        assert_ne!(a_conv.public_key(), a_sign.public_key());
    }

    #[tokio::test]
    async fn alice_and_bob_exchange_a_message() {
        // Arrange
        let ((a_conv, a_sign), (b_conv, b_sign)) = both_sides();

        // Act
        let outer = mostro_wrap(&alice(), &a_conv, &a_sign, "hello bob", vec![])
            .await
            .unwrap();
        let inner = mostro_unwrap(
            &b_conv,
            Some(&b_sign.public_key()),
            Some(&parties()),
            &outer,
            Timestamp::now(),
        )
        .unwrap();

        // Assert
        assert_eq!(outer.kind, Kind::PrivateDirectMessage);
        assert_eq!(
            outer.pubkey,
            a_sign.public_key(),
            "outer is signed by K_sign"
        );
        assert_eq!(inner.content, "hello bob");
        assert_eq!(
            inner.pubkey,
            alice().public_key(),
            "inner identifies the sender"
        );
    }

    #[tokio::test]
    async fn the_published_event_never_carries_a_party_pubkey() {
        // Arrange
        let ((a_conv, a_sign), _) = both_sides();

        // Act
        let outer = mostro_wrap(&alice(), &a_conv, &a_sign, "hello bob", vec![])
            .await
            .unwrap();
        let published = outer.as_json();

        // Assert: everything an observer can read is a per-conversation key.
        assert_eq!(outer.pubkey, a_sign.public_key());
        assert!(
            !published.contains(&alice().public_key().to_hex()),
            "sender pubkey leaked into the published event"
        );
        assert!(
            !published.contains(&bob().public_key().to_hex()),
            "recipient pubkey leaked into the published event"
        );
        // The sender is only recoverable after decrypting with K_conv.
        let inner = mostro_unwrap(
            &a_conv,
            Some(&a_sign.public_key()),
            Some(&parties()),
            &outer,
            Timestamp::now(),
        )
        .unwrap();
        assert_eq!(inner.pubkey, alice().public_key());
    }

    #[tokio::test]
    async fn a_third_party_cannot_publish_into_the_conversation() {
        // Arrange: an outsider who has observed pub(K_conv) — it is public, in
        // the p tag — builds a well-formed event with their own key.
        let ((_, _), (b_conv, b_sign)) = both_sides();
        let outsider = Keys::generate();
        let forged = mostro_wrap(&outsider, &b_conv, &outsider, "spam", vec![])
            .await
            .unwrap();

        // Act
        let result = mostro_unwrap(
            &b_conv,
            Some(&b_sign.public_key()),
            Some(&parties()),
            &forged,
            Timestamp::now(),
        );

        // Assert: rejected on the author check, before any decryption. This is
        // the flood the gift-wrap scheme could not distinguish from real
        // traffic, and relays drop it too via the `authors` filter.
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn an_observer_holding_k_conv_cannot_sign_as_the_conversation() {
        // Arrange: this is the read-only dispute disclosure. K_sign is not
        // derivable from K_conv, so the best an observer can do is sign with
        // K_conv itself.
        let ((a_conv, a_sign), _) = both_sides();
        let solver_view = a_conv.clone();
        let attempt = mostro_wrap(&alice(), &solver_view, &solver_view, "forged", vec![])
            .await
            .unwrap();

        // Act
        let result = mostro_unwrap(
            &a_conv,
            Some(&a_sign.public_key()),
            Some(&parties()),
            &attempt,
            Timestamp::now(),
        );

        // Assert
        assert!(result.is_err(), "K_conv must not be able to author events");
    }

    #[tokio::test]
    async fn a_message_addressed_elsewhere_is_rejected() {
        // Arrange: a party sends a message whose p tag points somewhere else,
        // so it would stay out of the `#p` query a solver uses to rebuild the
        // transcript while the counterparty still sees it.
        let ((a_conv, a_sign), (b_conv, b_sign)) = both_sides();
        let elsewhere = Keys::generate();
        let inner = EventBuilder::text_note("off the record")
            .build(alice().public_key())
            .sign(&alice())
            .await
            .unwrap();
        let content = nip44::encrypt(
            a_conv.secret_key(),
            &a_conv.public_key(),
            inner.as_json(),
            nip44::Version::V2,
        )
        .unwrap();
        let outer = EventBuilder::new(Kind::PrivateDirectMessage, content)
            .tags(vec![Tag::public_key(elsewhere.public_key())])
            .sign_with_keys(&a_sign)
            .unwrap();

        // Act
        let result = mostro_unwrap(
            &b_conv,
            Some(&b_sign.public_key()),
            Some(&parties()),
            &outer,
            Timestamp::now(),
        );

        // Assert
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn an_event_dated_in_the_future_is_rejected() {
        // Arrange: both timestamps agree with each other, so only an absolute
        // bound catches this. Left unchecked it would poison a `since` cursor
        // and silence the conversation until that date.
        let ((a_conv, a_sign), (b_conv, b_sign)) = both_sides();
        let outer = mostro_wrap(&alice(), &a_conv, &a_sign, "from the future", vec![])
            .await
            .unwrap();

        // Act: evaluate it against a clock an hour behind the event.
        let an_hour_ago = Timestamp::from(outer.created_at.as_secs() - 3600);
        let result = mostro_unwrap(
            &b_conv,
            Some(&b_sign.public_key()),
            Some(&parties()),
            &outer,
            an_hour_ago,
        );

        // Assert
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn an_inner_event_from_a_stranger_is_rejected() {
        // Arrange: a party wraps someone else's signed note. The outer event is
        // legitimate, so only the allowed-signers check catches it.
        let ((a_conv, a_sign), (b_conv, b_sign)) = both_sides();
        let stranger = Keys::generate();
        let outer = mostro_wrap(&stranger, &a_conv, &a_sign, "not a party", vec![])
            .await
            .unwrap();

        // Act
        let result = mostro_unwrap(
            &b_conv,
            Some(&b_sign.public_key()),
            Some(&parties()),
            &outer,
            Timestamp::now(),
        );

        // Assert
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn callers_cannot_smuggle_a_second_p_tag() {
        // Arrange
        let ((a_conv, a_sign), _) = both_sides();
        let extra = vec![Tag::public_key(Keys::generate().public_key())];

        // Act
        let result = mostro_wrap(&alice(), &a_conv, &a_sign, "hello", extra).await;

        // Assert
        assert!(result.is_err());
    }
}
