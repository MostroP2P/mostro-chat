use clap::Parser;
use crossterm::{
    event::{self, Event as CrosstermEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use nostr_sdk::{
    Client, Event, EventBuilder, Keys, Kind, PublicKey, RelayPoolNotification, Tag,
    SecretKey, Timestamp,
};
use nostr_sdk::prelude::*;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};
use std::{
    io,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc::{self, Receiver, Sender};

// Relay URL
const RELAY_URL: &str = "wss://relay.mostro.network";

// We set N in seconds (600 seconds = 10 minutes)
const N_SECONDS: u64 = 600;
// Proof of work difficulty is important for the NIP-59 event
const POW_DIFFICULTY: u8 = 2;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Sender's private key (hex or bech32)
    #[arg(short = 's', long = "sender-secret", requires = "receiver_pubkey")]
    sender_secret: Option<String>,

    /// Receiver's public key (hex or bech32)
    #[arg(short = 'p', long = "receiver-pubkey", requires = "sender_secret")]
    receiver_pubkey: Option<String>,

    /// Shared secret key (hex)
    #[arg(short = 'k', long = "shared-key", conflicts_with_all = ["sender_secret", "receiver_pubkey"])]
    shared_key: Option<String>,
}

struct App {
    messages: Arc<Mutex<Vec<(Timestamp, PublicKey, String)>>>, // Store (timestamp, sender pubkey, message)
    input: String,
    tx: Option<Sender<String>>,  // Only used in participant mode
    sender_keys: Option<Keys>,   // Only used in participant mode
    shared_keys: Keys,
    shared_key_display: String,
    is_observer: bool,           // Flag to indicate observer mode (with -k)
    is_shared_key_visible: bool, // Flag to control visibility of the shared key
}

impl App {
    fn new(
        messages: Arc<Mutex<Vec<(Timestamp, PublicKey, String)>>>,
        tx: Option<Sender<String>>,
        sender_keys: Option<Keys>,
        shared_keys: Keys,
        is_observer: bool,
    ) -> Self {
        let shared_key_display = shared_keys.secret_key().to_secret_hex();
        Self {
            messages,
            input: String::new(),
            tx,
            sender_keys,
            shared_keys,
            shared_key_display,
            is_observer,
            is_shared_key_visible: false, // Initialize with shared key hidden
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Parse arguments using clap
    let args = Args::parse();

    let shared_keys: Keys;
    let mut sender_keys: Option<Keys> = None;
    let is_observer = args.shared_key.is_some();

    if let Some(shared_key_hex) = args.shared_key {
        // Observer mode: Use the provided shared key
        let shared_secret_key = SecretKey::from_str(&shared_key_hex).expect("Invalid shared key");
        shared_keys = Keys::new(shared_secret_key);
    } else {
        // Participant mode: Generate shared key from sender and receiver keys
        let sender_secret = args.sender_secret.expect("Sender secret is required");
        let receiver_pubkey_str = args.receiver_pubkey.expect("Receiver pubkey is required");

        sender_keys = Some(Keys::parse(&sender_secret).expect("Invalid sender's private key"));
        let receiver_pubkey = PublicKey::from_str(&receiver_pubkey_str).expect("Invalid recipient public key");

        let shared_key = nostr_sdk::util::generate_shared_key(
            sender_keys.as_ref().unwrap().secret_key(),
            &receiver_pubkey,
        ).expect("Error generating shared key");
        let shared_secret_key = SecretKey::from_slice(&shared_key).unwrap();
        shared_keys = Keys::new(shared_secret_key);
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

    // Create app and run Nostr client in background
    let app = App::new(messages.clone(), tx, sender_keys.clone(), shared_keys.clone(), is_observer);
    let nostr_handle = tokio::spawn(run_nostr(sender_keys, shared_keys, rx, messages.clone(), is_observer));

    let result = run_app(&mut terminal, app).await;

    // Clean up
    nostr_handle.abort();
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, mut app: App) -> io::Result<()> {
    loop {
        terminal.draw(|f| {
            let chunks = Layout::vertical([
                Constraint::Percentage(70), // Messages area
                Constraint::Percentage(15), // Shared key area
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
                .filter(|(timestamp, _, _)| now - timestamp.as_u64() <= N_SECONDS)
                .map(|(_, pubkey, msg)| {
                    if app.is_observer {
                        // In observer mode, always show the inner_event pubkey
                        format!("{}: {}", pubkey.to_string(), msg)
                    } else {
                        // In participant mode, show "You:" only if the message is from the sender
                        if Some(*pubkey) == app.sender_keys.as_ref().map(|k| k.public_key()) {
                            format!("You: {}", msg)
                        } else {
                            format!("{}: {}", pubkey.to_string(), msg)
                        }
                    }
                })
                .collect();

            // Display recent messages
            let lines: Vec<Line> = recent_messages
                .iter()
                .map(|msg| Line::from(Span::raw(msg)))
                .collect();
            let messages_widget = Paragraph::new(lines)
                .block(
                    Block::default()
                        .title_top(Line::from("Messages").alignment(Alignment::Left))
                        .title_top(Line::from(Span::styled("ESC to exit", Style::default().fg(Color::Green))).alignment(Alignment::Right))
                        .borders(Borders::ALL)
                );
            f.render_widget(messages_widget, chunks[0]);

            // Determine the text to display for the shared key
            let shared_key_text = if app.is_shared_key_visible {
                app.shared_key_display.as_str()
            } else {
                &"*".repeat(64)
            };

            // Display shared key with toggle label
            let shared_key_widget = Paragraph::new(shared_key_text)
                .style(Style::default().fg(Color::Cyan))
                .block(
                    Block::default()
                        .title("Shared Key")
                        // Add label "tab to display/hide" in the top-right corner
                        .title_top(Line::from(Span::styled("Tab to Display/Hide", Style::default().fg(Color::Green))).alignment(Alignment::Right))
                        .borders(Borders::ALL)
                );
            f.render_widget(shared_key_widget, chunks[1]);

            // Input field
            let input = Paragraph::new(app.input.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().title("Input").borders(Borders::ALL));
            f.render_widget(input, chunks[2]);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let CrosstermEvent::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Esc => break,
                    KeyCode::Char(c) => app.input.push(c),
                    KeyCode::Backspace => {
                        app.input.pop();
                    }
                    KeyCode::Enter => {
                        if !app.input.is_empty() {
                            let message = app.input.clone();
                            let now = Timestamp::now();
                            // Use the sender's public key (from sender_keys) when sending a message in participant mode
                            let sender_pubkey = app.sender_keys.as_ref().map(|k| k.public_key()).unwrap_or(app.shared_keys.public_key());
                            {
                                let mut messages = app.messages.lock().expect("Error locking messages");
                                messages.push((now, sender_pubkey, message.clone()));
                            }
                            if let Some(tx) = &app.tx {
                                if let Err(e) = tx.send(message).await {
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
                    }
                    // Toggle shared key visibility when Tab is pressed
                    KeyCode::Tab => {
                        app.is_shared_key_visible = !app.is_shared_key_visible;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

async fn run_nostr(
    sender: Option<Keys>,
    shared_keys: Keys,
    rx: Option<Receiver<String>>,
    messages: Arc<Mutex<Vec<(Timestamp, PublicKey, String)>>>,
    is_observer: bool,
) {
    // Initialize Nostr client
    let client = Client::new(Keys::generate());
    if let Err(e) = client.add_relay(RELAY_URL).await {
        eprintln!("Error adding relay: {}", e);
        return;
    }
    let _ = client.connect().await;

    // Subscribe to events directed to the shared key
    let filter = nostr_sdk::Filter::new()
        .kind(Kind::GiftWrap)
        .pubkey(shared_keys.public_key());
    if let Err(e) = client.subscribe(filter, None).await {
        eprintln!("Error subscribing: {}", e);
        return;
    }

    // Handle outgoing messages (only in participant mode)
    if !is_observer {
        let client_clone = client.clone();
        let receiver_clone = shared_keys.clone(); // Use shared_keys as receiver
        let sender = sender.expect("Sender keys are required in participant mode");
        if let Some(mut rx) = rx {
            tokio::spawn(async move {
                while let Some(message) = rx.recv().await {
                    if let Err(e) = send_message(&client_clone, &sender, receiver_clone.public_key(), &message).await {
                        eprintln!("Error sending message: {}", e);
                    }
                }
            });
        }
    }

    // Handle incoming messages
    let mut notifications = client.notifications();
    while let Ok(notification) = notifications.recv().await {
        if let RelayPoolNotification::Event { event, .. } = notification {
            if let Ok(inner_event) = mostro_unwrap(&shared_keys, *event).await {
                let message = inner_event.content.clone();
                let created_at = inner_event.created_at;
                let sender_pubkey = inner_event.pubkey;
                let mut messages = messages.lock().expect("Error locking messages");
                messages.push((created_at, sender_pubkey, message));
            }
        }
    }
}

async fn send_message(
    client: &Client,
    sender: &Keys,
    receiver: PublicKey,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let wrapped_event = mostro_wrap(sender, receiver, message, vec![]).await?;
    client.send_event(&wrapped_event).await?;
    Ok(())
}

/// Wraps a message in a non-standard and simplified NIP-59 event.
/// The inner event is signed with the sender's key and encrypted to the receiver's
/// public key using an ephemeral key.
///
/// # Arguments
/// - `sender`: The sender's keys for signing the inner event.
/// - `receiver`: The receiver's public key for encryption.
/// - `message`: The message to wrap.
/// - `extra_tags`: Additional tags to include in the wrapper event.
///
/// # Returns
/// A signed `Event` representing the NON STANDARD gift wrap.
pub async fn mostro_wrap(
    sender: &Keys,
    receiver: PublicKey,
    message: &str,
    extra_tags: Vec<Tag>,
) -> Result<Event, Box<dyn std::error::Error>> {
    let inner_event = EventBuilder::text_note(message)
        .build(sender.public_key())
        .sign(sender)
        .await?;
    let keys: Keys = Keys::generate();
    let encrypted_content: String = nip44::encrypt(
        keys.secret_key(),
        &receiver,
        inner_event.as_json(),
        nip44::Version::V2,
    )
    .unwrap();

    // Build tags for the wrapper event
    let mut tags = vec![Tag::public_key(receiver)];
    tags.extend(extra_tags);

    // Create and sign the gift wrap event
    let wrapped_event = EventBuilder::new(Kind::GiftWrap, encrypted_content)
        .pow(POW_DIFFICULTY)
        .tags(tags)
        .custom_created_at(Timestamp::tweaked(nip59::RANGE_RANDOM_TIMESTAMP_TWEAK))
        .sign_with_keys(&keys)?;
    Ok(wrapped_event)
}

/// Unwraps a non-standard NIP-59 event and retrieves the inner event.
/// The receiver uses their private key to decrypt the content.
///
/// # Arguments
/// - `receiver`: The receiver's keys for decryption.
/// - `event`: The wrapped event to unwrap.
///
/// # Returns
/// The decrypted inner `Event`.
pub async fn mostro_unwrap(
    receiver: &Keys,
    event: Event,
) -> Result<Event, Box<dyn std::error::Error>> {
    let decrypted_content = nip44::decrypt(receiver.secret_key(), &event.pubkey, &event.content)?;
    let inner_event = Event::from_json(&decrypted_content)?;

    // Verify the event before returning
    inner_event.verify()?;

    Ok(inner_event)
}