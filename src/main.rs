use clap::Parser;
use rcli::{
    process_csv, process_decode, process_encode, process_genpass, process_http_serve,
    process_text_decrypt, process_text_encrypt, process_text_generate, process_text_sign,
    process_text_verify, Base64SubCommand, HttpSubCommand, Opts, SubCommand, TextSignFormat,
    TextSubCommand,
};
use std::fs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::Csv(csv_opts) => {
            let output = if let Some(output) = csv_opts.output {
                output
            } else {
                format!("output.{}", csv_opts.format)
            };
            process_csv(&csv_opts.input, output, csv_opts.format)?;
        }
        SubCommand::GenPass(genpass_opts) => {
            let password = process_genpass(
                genpass_opts.length,
                genpass_opts.uppercase,
                genpass_opts.lowercase,
                genpass_opts.number,
                genpass_opts.symbol,
            )?;
            println!("{}", password);
        }
        SubCommand::Base64(subcmd) => match subcmd {
            Base64SubCommand::Encode(opts) => {
                let encoded = process_encode(&opts.input, opts.format)?;
                println!("{}", encoded);
            }
            Base64SubCommand::Decode(opts) => {
                let decoded = process_decode(&opts.output, opts.format)?;

                // Assuming the input is a valid UTF-8 string
                let decoded = String::from_utf8(decoded)?;
                print!("{}", decoded)
            }
        },
        SubCommand::Text(subcmd) => match subcmd {
            TextSubCommand::Sign(opts) => {
                let signed = process_text_sign(&opts.input, &opts.key, opts.format)?;
                println!("{}", signed);
            }
            TextSubCommand::Verify(opts) => {
                let verified = process_text_verify(&opts.input, &opts.key, &opts.sig, opts.format)?;
                println!("{}", verified);
            }
            TextSubCommand::Generate(opts) => {
                let keys = process_text_generate(opts.format)?;

                match opts.format {
                    TextSignFormat::Blake3 => {
                        let name = opts.output_path.join("blake3.txt");
                        fs::write(name, &keys[0])?;
                    }
                    TextSignFormat::Ed25519 => {
                        let name_private = opts.output_path.join("ed25519.private");
                        let name_public = opts.output_path.join("ed25519.public");
                        fs::write(name_private, &keys[0])?;
                        fs::write(name_public, &keys[1])?;
                    }
                    TextSignFormat::ChaCha20Poly1305 => {
                        let name = opts.output_path.join("chacha20-poly1305.txt");
                        fs::write(name, &keys[0])?;
                    }
                }
            }
            TextSubCommand::Encrypt(opts) => {
                let encrypted_text = process_text_encrypt(&opts.input, &opts.key)?;
                // write to file
                let name = opts.output_path.join("encrypted.txt");
                fs::write(name, encrypted_text)?;
            }
            TextSubCommand::Decrypt(opts) => {
                let decrypted_text = process_text_decrypt(&opts.input, &opts.key)?;
                // write to file
                let name = opts.output_path.join("decrypted.txt");
                fs::write(name, decrypted_text)?;
            }
        },
        SubCommand::Http(http_opts) => match http_opts {
            HttpSubCommand::Serve(opts) => {
                process_http_serve(opts.dir, opts.port).await?;
            }
        },
    }
    Ok(())
}
