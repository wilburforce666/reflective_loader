
use std::path::PathBuf;
use clap::{Parser, Subcommand, Args};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Pack(PackArgs),
    
    Unpack(UnpackArgs),
    
    ListGpus,
    
    Run(RunArgs),
}

#[derive(Args, Debug)]
pub struct PackArgs {
    #[arg(short, long)]
    pub input: PathBuf,
    
    #[arg(short, long)]
    pub output: PathBuf,
    
    #[arg(long, default_value_t = 0)]
    pub gpu_device: usize,
    
    #[arg(long, default_value_t = 4096)]
    pub segment_size: usize,
    
    #[arg(long, default_value_t = 10)]
    pub iterations: usize,
    
    #[arg(long)]
    pub no_encryption: bool,
}

#[derive(Args, Debug)]
pub struct UnpackArgs {
    #[arg(short, long)]
    pub input: PathBuf,
    
    #[arg(short, long)]
    pub output: PathBuf,
    
    #[arg(long, default_value_t = 0)]
    pub gpu_device: usize,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    #[arg(short, long)]
    pub input: PathBuf,
    
    #[arg(long)]
    pub target: Option<PathBuf>,
    
    #[arg(long)]
    pub args: Option<String>,
    
    #[arg(long)]
    pub runpe: bool,
    
    #[arg(long)]
    pub no_auto_resume: bool,
}

pub fn parse_args() -> Cli {
    Cli::parse()
}
