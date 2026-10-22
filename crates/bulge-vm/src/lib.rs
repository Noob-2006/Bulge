//! bulge-vm: supervision of the libkrun guest.
//!
//! Networking: the guest's virtio-net talks length-prefixed Ethernet frames
//! (QEMU stream framing). bulge sits between the VMM and passt and drops every
//! guest frame whose destination is the host itself, a private/special-use
//! range, or anything other than the small set of link-local control traffic
//! (DHCP, IPv6 neighbour discovery) and DNS to passt's forwarder.

pub mod net;
pub mod changes;
pub mod slots;
pub mod vm;
