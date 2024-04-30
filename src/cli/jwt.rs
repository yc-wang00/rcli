use crate::{process_jwt_sign, process_jwt_verify, CmdExector};
use anyhow::Ok;
use clap::Parser;
use enum_dispatch::enum_dispatch;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum JWTSubCommand {
    #[command(about = "Sign a JWT token")]
    Sign(JWTSignOpts),

    #[command(about = "Verify a JWT token")]
    Verify(JWTVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JWTSignOpts {
    #[arg(short, long)]
    pub sub: String,

    #[arg(short, long)]
    pub aud: String,

    #[arg(short, long)]
    pub exp: usize,
}

#[derive(Debug, Parser)]
pub struct JWTVerifyOpts {
    #[arg(short, long)]
    pub token: String,

    #[arg(short, long, default_value = "me")]
    pub valid_aud: String,
}

impl CmdExector for JWTSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let token = process_jwt_sign(self.sub, self.aud, self.exp)?;
        println!("{}", token);
        Ok(())
    }
}

impl CmdExector for JWTVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        process_jwt_verify(self.token, &self.valid_aud)?;
        Ok(())
    }
}
