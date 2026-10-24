//! Small JSON files holding keys and lists, private to the user (mode 600,
//! refused when others can read them; shared lists changed only under a
//! lock). The implementation is shared: [`bulge_util::fs`].

pub use bulge_util::fs::{check_private, create_private_dir, read_json as read, transact_json as transact, write_json as write};
