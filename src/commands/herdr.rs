use anyhow::{Context, Result};
use clap::Subcommand;
use std::process::Command;
use zeroclaw_config::schema::Config;

#[derive(Subcommand, Debug, Clone)]
pub enum HerdrCommands {
    /// Enable herdr integration (sets config + optionally runs herdr install)
    Enable {
        /// Also run `herdr integration install zeroclaw`
        #[arg(long, default_value = "true")]
        install: bool,
    },
    /// Disable herdr integration
    Disable,
    /// Show integration status
    Status,
    /// Run `herdr integration install zeroclaw` manually
    Integrate,
    /// Run `herdr integration uninstall zeroclaw`
    Uninstall,
}

pub async fn handle_herdr(cmd: HerdrCommands, config: &mut Config) -> Result<()> {
    match cmd {
        HerdrCommands::Enable { install } => {
            config.herdr.enabled = true;
            config.save().await?;
            println!("Herdr integration enabled.");
            if install {
                run_herdr_integration_install().await?;
            } else {
                println!("Run `zeroclaw herdr integrate` to install the herdr integration asset.");
            }
        }
        HerdrCommands::Disable => {
            config.herdr.enabled = false;
            config.save().await?;
            println!("Herdr integration disabled.");
        }
        HerdrCommands::Status => {
            run_herdr_integration_status().await?;
        }
        HerdrCommands::Integrate => {
            run_herdr_integration_install().await?;
        }
        HerdrCommands::Uninstall => {
            run_herdr_integration_uninstall().await?;
        }
    }
    Ok(())
}

async fn run_herdr_integration_install() -> Result<()> {
    let status = Command::new("herdr")
        .args(["integration", "install", "zeroclaw"])
        .status()
        .context("Failed to execute `herdr integration install zeroclaw`. Is herdr installed and in PATH?")?;

    if !status.success() {
        anyhow::bail!("`herdr integration install zeroclaw` failed with exit code: {:?}", status.code());
    }
    println!("Herdr integration 'zeroclaw' installed successfully.");
    Ok(())
}

async fn run_herdr_integration_uninstall() -> Result<()> {
    let status = Command::new("herdr")
        .args(["integration", "uninstall", "zeroclaw"])
        .status()
        .context("Failed to execute `herdr integration uninstall zeroclaw`")?;

    if !status.success() {
        anyhow::bail!("`herdr integration uninstall zeroclaw` failed with exit code: {:?}", status.code());
    }
    println!("Herdr integration 'zeroclaw' uninstalled successfully.");
    Ok(())
}

async fn run_herdr_integration_status() -> Result<()> {
    let output = Command::new("herdr")
        .args(["integration", "list", "--target", "zeroclaw"])
        .output()
        .context("Failed to execute `herdr integration list`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("`herdr integration list` failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);
    Ok(())
}