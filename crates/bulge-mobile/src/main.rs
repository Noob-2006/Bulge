// Desktop entry (for development); on Android the library is the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    bulge_mobile_lib::run();
}
