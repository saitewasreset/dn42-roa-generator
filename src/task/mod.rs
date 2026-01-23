pub mod roa;
pub mod dns;

pub trait Task: Send + Sync {
    fn name(&self) -> &str;
    fn run(&self) -> anyhow::Result<()>;
}