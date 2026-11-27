// SPDX-License-Identifier: GPL-3.0-or-later
//! The terminal: raw mode and the alternate screen, restored on every exit
//! path, and the event loop that ties input, effects and the watcher together.

use std::ffi::OsString;
use std::io::{self, Stdout};
use std::panic::{self, PanicHookInfo};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::cursor::Show;
use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, Event as TerminalEvent, EventStream, KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures::StreamExt;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use remap_protocol::{ControlClient, Diagnostic};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::mpsc;

use crate::authority::Authority;
use crate::model::Model;
use crate::update::{self, Effect, Event};
use crate::view::view;
use crate::worker::{self, Backoff, Debouncer, VALIDATION_DEBOUNCE};

/// Stable code for a terminal the console cannot drive.
pub(crate) const TERMINAL_IO: &str = "console-terminal-io";
/// Stable code for a console that could not listen for stop signals.
pub(crate) const SIGNAL_SETUP: &str = "console-signal-setup";
/// Stable code for a console stopped by an internal fault.
pub(crate) const INTERNAL_ERROR: &str = "console-internal-error";

const EVENT_QUEUE: usize = 64;

type Hook = Box<dyn Fn(&PanicHookInfo<'_>) + Sync + Send + 'static>;

/// `NO_COLOR` set to anything but the empty string turns colour off.
pub(crate) fn color_enabled(no_color: Option<OsString>) -> bool {
    no_color.is_none_or(|value| value.is_empty())
}

fn terminal_error(phase: &str, error: &io::Error) -> Diagnostic {
    Diagnostic::new(
        TERMINAL_IO,
        format!("the console could not {phase} the terminal: {error}"),
        Some(
            "run remap console in an interactive terminal, or use 'remap list' and 'remap status'"
                .to_owned(),
        ),
        false,
    )
    .with_context("phase", phase)
}

/// SIGTERM and SIGHUP, turned into [`Event::Stop`] so the console quits
/// through the normal path and its guard restores the terminal.
struct StopSignals {
    terminate: Signal,
    hangup: Signal,
}

impl StopSignals {
    fn listen() -> Result<Self, Diagnostic> {
        let listen = |kind: SignalKind, name: &str| {
            signal(kind).map_err(|error| {
                Diagnostic::new(
                    SIGNAL_SETUP,
                    format!("the console could not listen for {name}: {error}"),
                    Some("use 'remap list' and 'remap status' instead".to_owned()),
                    false,
                )
                .with_context("signal", name)
            })
        };
        Ok(Self {
            terminate: listen(SignalKind::terminate(), "SIGTERM")?,
            hangup: listen(SignalKind::hangup(), "SIGHUP")?,
        })
    }

    /// Resolves when either signal arrives. Cancel-safe.
    async fn next(&mut self) -> Event {
        tokio::select! {
            _ = self.terminate.recv() => Event::Stop,
            _ = self.hangup.recv() => Event::Stop,
        }
    }
}

/// Best-effort restore; it must work even half-way through a failure.
fn restore_terminal() {
    let _raw = disable_raw_mode();
    let _screen = execute!(
        io::stdout(),
        DisableBracketedPaste,
        LeaveAlternateScreen,
        Show
    );
}

/// Raw mode and the alternate screen for as long as it lives.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self, Diagnostic> {
        enable_raw_mode().map_err(|error| terminal_error("prepare", &error))?;
        let guard = Self;
        execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste)
            .map_err(|error| terminal_error("prepare", &error))?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Restores the terminal before the previous panic hook prints, and puts
/// that hook back when dropped.
struct PanicGuard {
    previous: Option<Arc<Hook>>,
    fired: Arc<AtomicBool>,
}

impl PanicGuard {
    fn install() -> Self {
        let previous: Arc<Hook> = Arc::new(panic::take_hook());
        let fired = Arc::new(AtomicBool::new(false));
        let hook_previous = Arc::clone(&previous);
        let hook_fired = Arc::clone(&fired);
        panic::set_hook(Box::new(move |info| {
            hook_fired.store(true, Ordering::SeqCst);
            restore_terminal();
            hook_previous(info);
        }));
        Self {
            previous: Some(previous),
            fired,
        }
    }

    fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl Drop for PanicGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        drop(panic::take_hook());
        if let Some(previous) = self.previous.take()
            && let Ok(previous) = Arc::try_unwrap(previous)
        {
            panic::set_hook(previous);
        }
    }
}

pub(crate) async fn run(client: ControlClient) -> Result<(), Diagnostic> {
    let color = color_enabled(std::env::var_os("NO_COLOR"));
    let panic_guard = PanicGuard::install();
    let terminal_guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|error| terminal_error("start", &error))?;
    let result = event_loop(&mut terminal, Arc::new(client), color, &panic_guard).await;
    drop(terminal);
    drop(terminal_guard);
    drop(panic_guard);
    result
}

fn translate(event: TerminalEvent) -> Option<Event> {
    match event {
        TerminalEvent::Key(key) if key.kind != KeyEventKind::Release => Some(Event::Key(key)),
        TerminalEvent::Paste(text) => Some(Event::Paste(text)),
        TerminalEvent::Resize(width, height) => Some(Event::Resize { width, height }),
        _ => None,
    }
}

/// Sends validations through the debounce and everything else straight to
/// a worker task.
fn dispatch<A: Authority>(
    effects: Vec<Effect>,
    authority: &Arc<A>,
    events: &mpsc::Sender<Event>,
    debounce: &mut Debouncer,
) {
    for effect in effects {
        if matches!(effect, Effect::Validate { .. }) {
            debounce.hold(effect, VALIDATION_DEBOUNCE);
        } else {
            worker::spawn_effect(Arc::clone(authority), effect, events.clone());
        }
    }
}

async fn event_loop<A: Authority>(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    authority: Arc<A>,
    color: bool,
    panic_guard: &PanicGuard,
) -> Result<(), Diagnostic> {
    let size = terminal
        .size()
        .map_err(|error| terminal_error("measure", &error))?;
    let mut stops = StopSignals::listen()?;
    let (events, mut incoming) = mpsc::channel(EVENT_QUEUE);
    let watcher = tokio::spawn(worker::watch(
        Arc::clone(&authority),
        events.clone(),
        Backoff::standard(),
    ));
    let mut model = Model::new(color);
    let resize = Event::Resize {
        width: size.width,
        height: size.height,
    };
    let mut pending = update::update(&mut model, resize);
    pending.extend(update::start(&mut model));
    let mut input = EventStream::new();
    let mut debounce = Debouncer::default();
    let result = loop {
        dispatch(
            std::mem::take(&mut pending),
            &authority,
            &events,
            &mut debounce,
        );
        if model.should_quit() {
            break Ok(());
        }
        if panic_guard.fired() {
            break Err(internal_error());
        }
        if let Err(error) = terminal.draw(|frame| view(&model, frame)) {
            break Err(terminal_error("draw on", &error));
        }
        let event = tokio::select! {
            next = input.next() => match next {
                Some(Ok(event)) => translate(event),
                Some(Err(error)) => break Err(terminal_error("read from", &error)),
                None => break Err(terminal_error("read from", &io::Error::from(io::ErrorKind::UnexpectedEof))),
            },
            Some(event) = incoming.recv() => Some(event),
            stop = stops.next() => Some(stop),
            effect = debounce.ready() => {
                worker::spawn_effect(Arc::clone(&authority), effect, events.clone());
                None
            }
        };
        if let Some(event) = event {
            pending = update::update(&mut model, event);
        }
    };
    watcher.abort();
    result
}

fn internal_error() -> Diagnostic {
    Diagnostic::new(
        INTERNAL_ERROR,
        "the console stopped after an internal fault",
        Some(
            "the fault was printed above; run 'remap list' to check the registry, then report it"
                .to_owned(),
        ),
        false,
    )
}
