//! A tiny multi-call WASI program (the applet is argv[0]'s file name, like busybox / uutils
//! coreutils) for the `wasm` backend tests: file I/O, directories, stdio, exit codes, clocks,
//! busy loops and sandbox-escape attempts, all through Rust std on `wasm32-wasip1`.

use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let applet = args[0].rsplit('/').next().unwrap_or("").to_string();
    let rest = &args[1..];
    let code = match applet.as_str() {
        "say" => {
            println!("{}", rest.join(" "));
            0
        }
        "cat" => {
            let mut out = std::io::stdout();
            if rest.is_empty() {
                let mut b = Vec::new();
                std::io::stdin().read_to_end(&mut b).unwrap();
                out.write_all(&b).unwrap();
                0
            } else {
                let mut code = 0;
                for f in rest {
                    match std::fs::read(f) {
                        Ok(b) => out.write_all(&b).unwrap(),
                        Err(e) => {
                            eprintln!("cat: {f}: {e}");
                            code = 1;
                        }
                    }
                }
                code
            }
        }
        "put" => match std::fs::write(&rest[0], rest[1..].join(" ")) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("put: {}: {e}", rest[0]);
                1
            }
        },
        "ls" => {
            let dir = rest.first().map(String::as_str).unwrap_or(".");
            match std::fs::read_dir(dir) {
                Ok(rd) => {
                    let mut v: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
                    v.sort();
                    for n in v {
                        println!("{n}");
                    }
                    0
                }
                Err(e) => {
                    eprintln!("ls: {dir}: {e}");
                    2
                }
            }
        }
        "mkdir" => match std::fs::create_dir_all(&rest[0]) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("mkdir: {}: {e}", rest[0]);
                1
            }
        },
        "mv" => match std::fs::rename(&rest[rest.len() - 2], &rest[rest.len() - 1]) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("mv: {e}");
                1
            }
        },
        "rm" => {
            let mut code = 0;
            for f in rest.iter().filter(|a| !a.starts_with('-')) {
                if let Err(e) = std::fs::remove_file(f) {
                    eprintln!("rm: {f}: {e}");
                    code = 1;
                }
            }
            code
        }
        "wc" => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).unwrap();
            println!("{}", s.lines().count());
            0
        }
        "upper" => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).unwrap();
            print!("{}", s.to_uppercase());
            0
        }
        "env" => {
            let mut v: Vec<(String, String)> = std::env::vars().collect();
            v.sort();
            for (k, val) in v {
                println!("{k}={val}");
            }
            0
        }
        "fail" => {
            eprintln!("fail: on purpose");
            rest.first().and_then(|n| n.parse().ok()).unwrap_or(3)
        }
        "spin" => {
            let mut x: u64 = 0;
            loop {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                if x == 42 {
                    break;
                }
            }
            println!("{x}");
            0
        }
        "nap" => {
            let ms: u64 = rest.first().and_then(|n| n.parse().ok()).unwrap_or(100);
            let t = std::time::Instant::now();
            std::thread::sleep(std::time::Duration::from_millis(ms));
            println!("slept {}", t.elapsed().as_millis() >= ms as u128);
            0
        }
        "hog" => {
            let mut v: Vec<Vec<u8>> = Vec::new();
            for _ in 0..4096 {
                v.push(vec![1u8; 1 << 20]);
            }
            println!("allocated {}", v.len());
            0
        }
        // Every way out of the sandbox it can think of; prints what happened to each.
        "escape" => {
            for p in ["/etc/passwd", "../outside.txt", "/tmp/../../etc/hostname", "link-out/secret.txt"] {
                match std::fs::read_to_string(p) {
                    Ok(_) => println!("READ {p}"),
                    Err(_) => println!("denied {p}"),
                }
            }
            for p in ["/escape.txt", "../escape.txt"] {
                match std::fs::write(p, "x") {
                    Ok(()) => println!("WROTE {p}"),
                    Err(_) => println!("denied {p}"),
                }
            }
            0
        }
        "now" => {
            let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            // A HashMap's RandomState seeds itself through `random_get`.
            let m: std::collections::HashMap<u8, u8> = (0..4).map(|i| (i, i)).collect();
            println!("{} {}", t > 1_600_000_000, m.len());
            0
        }
        other => {
            eprintln!("wbox: unknown applet `{other}`");
            127
        }
    };
    std::process::exit(code);
}
