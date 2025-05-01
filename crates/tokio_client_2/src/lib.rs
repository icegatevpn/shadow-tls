#[macro_use]
mod driver;
#[macro_use]
mod macros;
mod fs;
mod net;
mod buf;
mod io;
mod utils;
pub type BufResult<T, B> = (std::io::Result<T>, B);