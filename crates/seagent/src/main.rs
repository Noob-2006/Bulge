//! The `seagent` binary. Everything lives in the library (`lib.rs`), so the iOS app can link the
//! same agent and run it in-process (`seagent::embed`, docs/cross-platform.md).

// musl's malloc serialises threads on one lock; the static (musl) release builds use mimalloc.
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    seagent::main()
}
