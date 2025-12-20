
pub mod asm;
pub mod elf;
pub mod elfdef;
pub mod map;
pub mod processes;
pub mod auxiliary;
pub mod chunk;

pub fn init()
{
    env_logger::init();
}