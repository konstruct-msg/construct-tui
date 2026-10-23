//! Keys and pastes from the terminal, as a channel the run loop selects on.

use crossterm::event::{Event as CrosstermEvent, EventStream, KeyEvent};
use futures::StreamExt;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum Event {
    Key(KeyEvent),
    Paste(String),
}

pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<Event>,
}

impl EventHandler {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            let mut reader = EventStream::new();
            while let Some(Ok(evt)) = reader.next().await {
                let event = match evt {
                    CrosstermEvent::Key(key) => Event::Key(key),
                    CrosstermEvent::Paste(text) => Event::Paste(text),
                    _ => continue,
                };
                if tx.send(event).is_err() {
                    break;
                }
            }
        });

        Self { rx }
    }

    pub async fn next(&mut self) -> Option<Event> {
        self.rx.recv().await
    }
}
