pub mod context;
pub mod filter;
pub mod packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    Master,
    Slave,
}
