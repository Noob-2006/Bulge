//! Guest-side file tools. Pure logic lives in submodules; `handlers` wires
//! them to runtime commands.

pub mod edit;
pub mod handlers;
pub mod read;
pub mod truncate;
