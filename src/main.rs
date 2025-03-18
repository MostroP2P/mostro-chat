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
    layout::{Constraint, Layout},
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
    #[arg(short = 's', long = "sender-secret")]
    sender_secret: String,

    /// Receiver's public key (hex or bech32)
    #[arg(short = 'p', long = "receiver-pubkey")]
    receiver_pubkey: String,
}

struct App {
    messages: Arc<Mutex<Vec<(Timestamp, String)>>>, // Store (timestamp, message)
    input: String,
    tx: Sender<String>,
    sender_keys: Keys,
    shared_keys: Keys,
}

impl App {
    fn new(
        messages: Arc<Mutex<Vec<(Timestamp, String)>>>,
        tx: Sender<String>,
        sender_keys: Keys,
        shared_keys: Keys,
    ) -> Self {
        Self {
            messages,
            input: String::new(),
            tx,
            sender_keys,
            shared_keys,
        }
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Parse arguments using clap
    let args = Args::parse();
    // Access the parsed values
    let sender_secret = args.sender_secret;
    let receiver_pubkey_str = args.receiver_pubkey;

    // Parse keys
    let sender_keys = Keys::parse(&sender_secret).expect("Invalid sender's private key");
    let receiver_pubkey =
        PublicKey::from_str(&receiver_pubkey_str).expect("Invalid recipient public key");

    // Generating shared key
    let shared_key = nostr_sdk::util::generate_shared_key(sender_keys.secret_key(), &receiver_pubkey)
        .expect("Error generating shared key");
    let shared_secret_key = SecretKey::from_slice(&shared_key).unwrap();
    let shared_keys = Keys::new(shared_secret_key);

    // Init terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // set channel and messages
    let (tx, rx) = mpsc::channel(100);
    let messages = Arc::new(Mutex::new(Vec::new()));

    // Create app and run Nostr client in background
    let app = App::new(messages.clone(), tx, sender_keys.clone(), shared_keys.clone());
    let nostr_handle = tokio::spawn(run_nostr(sender_keys, shared_keys, rx, messages.clone()));

    let result = run_app(&mut terminal, app).await;

    // clean up
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
                Constraint::Percentage(80), // messages area
                Constraint::Percentage(20), // input area
            ])
            .split(f.area());

            // Get the current time in seconds since the UNIX epoch
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Error getting current time")
                .as_secs();

            // Filtrar messages de los últimos N segundos
            let messages = app.messages.lock().expect("Error al bloquear messages");
            let recent_messages: Vec<String> = messages
                .iter()
                .filter(|(timestamp, _)| now - timestamp.as_u64() <= N_SECONDS)
                .map(|(_, msg)| msg.clone())
                .collect();

            // Mostrar messages recientes
            let lines: Vec<Line> = recent_messages
                .iter()
                .map(|msg| Line::from(Span::raw(msg)))
                .collect();
            let messages_widget = Paragraph::new(lines)
                .block(Block::default().title("messages").borders(Borders::ALL));
            f.render_widget(messages_widget, chunks[0]);

            // Campo de entrada
            let input = Paragraph::new(app.input.as_str())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().title("Input").borders(Borders::ALL));
            f.render_widget(input, chunks[1]);
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
                            let message = format!("You: {}", app.input);
                            let now = Timestamp::now(); // Timestamp for sent messages
                            {
                                let mut messages = app.messages.lock().expect("Error al bloquear messages");
                                messages.push((now, message));
                            }
                            if let Err(e) = app.tx.send(app.input.clone()).await {
                                let mut messages = app.messages.lock().expect("Error al bloquear messages");
                                messages.push((
                                    Timestamp::now(),
                                    format!("Error sending message: {}", e),
                                ));
                            }
                            app.input.clear();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

async fn run_nostr(
    sender_keys: Keys,
    shared_keys: Keys,
    mut rx: Receiver<String>,
    messages: Arc<Mutex<Vec<(Timestamp, String)>>>,
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
    // let subscription_id = SubscriptionId::generate();
    if let Err(e) = client.subscribe(filter, None).await {
        eprintln!("Error subscribing: {}", e);
        return;
    }

    // Handle outgoing messages
    let client_clone = client.clone();
    let sender_keys_clone = sender_keys.clone();
    let shared_keys_clone = shared_keys.clone();
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if let Err(e) = send_message(&client_clone, &sender_keys_clone, &shared_keys_clone, &message).await {
                eprintln!("Error sending message: {}", e);
            }
        }
    });

    // Handle incoming messages
    let mut notifications = client.notifications();
    while let Ok(notification) = notifications.recv().await {
        if let RelayPoolNotification::Event { event, .. } = notification {
            if let Ok(inner_event) = mostro_unwrap(&shared_keys, *event).await {
                if inner_event.pubkey != sender_keys.public_key() {
                    let message = format!("Counterpart: {}", inner_event.content);
                    let created_at = inner_event.created_at; // We use the created_at of the inner_event
                    let mut messages = messages.lock().expect("Error blocking messages");
                    messages.push((created_at, message));
                }
            }
        }
    }
}

async fn send_message(
    client: &Client,
    sender: &Keys,
    shared_keys: &Keys,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let wrapped_event = mostro_wrap(sender, shared_keys.public_key(), message, vec![]).await?;
    client.send_event(&wrapped_event).await?;
    Ok(())
}

/// Wraps a message in a non standard and simplified NIP-59 event.
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

/// Unwraps an non standard NIP-59 event and retrieves the inner event.
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
