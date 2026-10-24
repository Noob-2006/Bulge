//! `bulge-remote`: talk to your bulge from another device (Linux, macOS,
//! Windows), from any network, through the relay — end-to-end encrypted.

use bulge_remote::cli::{CliError, usage};
use std::io::BufRead;

use bulge_remote::conversation::{self, Event};
use bulge_remote::device::{self, KnownHost};
use bulge_remote::link::PairLink;
use tokio::sync::mpsc;

const USAGE: &str = "\
bulge-remote — talk to your bulge from this device

USAGE:
    bulge-remote join <PAIRING-LINK> [--as <HOST-NAME>] [--name <DEVICE-NAME>]
        Pair with a bulge. The link comes from `bulge remote pair` on that
        computer (scan the QR code or copy the text; it works once, for 10 min).
    bulge-remote chat [HOST-NAME]
        Type messages for bulge; replies appear as they arrive. A lone /
        lists the commands (/new, /stop, /status, /undo, /help). Ctrl-D quits.
    bulge-remote hosts
    bulge-remote forget <HOST-NAME>
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(&args) {
        Ok(()) => 0,
        Err(error) => {
            error.report(USAGE);
            1
        }
    };
    std::process::exit(code);
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn default_device_name() -> String {
    std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")).ok().filter(|n| !n.is_empty()).unwrap_or_else(|| std::env::consts::OS.to_owned())
}

fn run(args: &[String]) -> Result<(), CliError> {
    let dir = bulge_remote::default_dir()?;
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    match args.first().map(String::as_str) {
        Some("join") => {
            let link = PairLink::decode(args.get(1).ok_or_else(|| usage("join needs the pairing link"))?)?;
            let host_name = flag(args, "--as").unwrap_or("bulge");
            let device_name = flag(args, "--name").map(str::to_owned).unwrap_or_else(default_device_name);
            let known = runtime.block_on(device::join(&dir, &link, host_name, &device_name))?;
            println!("paired with \"{}\" (listed there as \"{}\"); talk to it with: bulge-remote chat", known.name, known.device_name);
            Ok(())
        }
        Some("chat") => {
            let host = device::pick_host(&dir, args.get(1).map(String::as_str))?;
            Ok(runtime.block_on(chat(&dir, &host))?)
        }
        Some("hosts") => {
            for host in device::hosts(&dir)? {
                println!("{}  via {}  (this device is \"{}\" there)", host.name, host.relay, host.device_name);
            }
            Ok(())
        }
        Some("forget") => {
            let name = args.get(1).ok_or_else(|| usage("forget needs a host name"))?;
            println!("{}", if device::forget(&dir, name)? { "forgotten" } else { "no such host" });
            Ok(())
        }
        Some("-h" | "--help") => {
            print!("{USAGE}");
            Ok(())
        }
        _ => Err(usage("unknown command")),
    }
}

/// Read stdin lines on a thread (stdin has no portable async reader).
fn stdin_lines() -> mpsc::UnboundedReceiver<String> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

async fn chat(dir: &std::path::Path, host: &KnownHost) -> Result<(), String> {
    let mut input = stdin_lines();
    let mut conversation = conversation::start(dir.to_path_buf(), host.clone());
    let mut input_open = true;
    // Messages sent that have not had a reply yet (to know when to quit after Ctrl-D).
    let mut awaiting = 0usize;
    let mut announced_typing = false;
    let mut commands: Vec<bulge_remote::wire::CommandEntry> = Vec::new();
    loop {
        if !input_open && awaiting == 0 {
            return Ok(());
        }
        tokio::select! {
            line = input.recv(), if input_open => match line {
                Some(line) if line.trim().is_empty() => {}
                // A lone "/" lists the commands, like a command palette.
                Some(line) if line.trim() == "/" => {
                    for command in &commands {
                        eprintln!("  /{:<8} {}", command.name, command.summary);
                    }
                }
                Some(text) => {
                    conversation.send.send(text).map_err(|_| "the conversation stopped".to_string())?;
                    awaiting += 1;
                    announced_typing = false;
                }
                None => input_open = false,
            },
            event = conversation.events.recv() => match event {
                Some(Event::Connected { direct: false }) => eprintln!("— connected to {} (via relay) —", host.name),
                Some(Event::Connected { direct: true }) => eprintln!("— direct connection to {} —", host.name),
                Some(Event::NotSent(why)) => {
                    eprintln!("— {why} —");
                    awaiting = awaiting.saturating_sub(1);
                }
                Some(Event::Reply(text)) => {
                    println!("{text}\n");
                    awaiting = awaiting.saturating_sub(1);
                    announced_typing = false;
                }
                Some(Event::Commands(list)) => commands = list,
                Some(Event::Typing) => {
                    if !announced_typing {
                        eprintln!("（bulge 處理中…）");
                        announced_typing = true;
                    }
                }
                Some(Event::Disconnected(why)) => eprintln!("— disconnected ({why}) —"),
                Some(Event::Fatal(error)) => return Err(error),
                None => return Err("the conversation stopped".into()),
            },
        }
    }
}
