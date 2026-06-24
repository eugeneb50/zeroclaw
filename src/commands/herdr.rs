use anyhow::{Context, Result};
use clap::Subcommand;
use std::process::Command;
use zeroclaw_config::schema::Config;

#[cfg(feature = "agent-runtime")]
use zeroclaw_runtime::i18n::get_required_cli_string;

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
            Box::pin(config.save()).await?;
            println!("{}", herdr_enabled_message());
            if install {
                run_herdr_integration_install()?;
            } else {
                println!("{}", herdr_integrate_hint_message());
            }
        }
        HerdrCommands::Disable => {
            config.herdr.enabled = false;
            Box::pin(config.save()).await?;
            println!("{}", herdr_disabled_message());
        }
        HerdrCommands::Status => {
            run_herdr_integration_status()?;
        }
        HerdrCommands::Integrate => {
            run_herdr_integration_install()?;
        }
        HerdrCommands::Uninstall => {
            run_herdr_integration_uninstall()?;
        }
    }
    Ok(())
}

fn herdr_enabled_message() -> String {
    #[cfg(feature = "agent-runtime")]
    {
        get_required_cli_string("cli-herdr-enabled")
    }
    #[cfg(not(feature = "agent-runtime"))]
    {
        "Herdr integration enabled.".to_string()
    }
}

fn herdr_disabled_message() -> String {
    #[cfg(feature = "agent-runtime")]
    {
        get_required_cli_string("cli-herdr-disabled")
    }
    #[cfg(not(feature = "agent-runtime"))]
    {
        "Herdr integration disabled.".to_string()
    }
}

fn herdr_integrate_hint_message() -> String {
    #[cfg(feature = "agent-runtime")]
    {
        get_required_cli_string("cli-herdr-integrate-hint")
    }
    #[cfg(not(feature = "agent-runtime"))]
    {
        "Run `zeroclaw herdr integrate` to install the herdr integration asset.".to_string()
    }
}

fn run_herdr_integration_install() -> Result<()> {
    let status = Command::new("herdr")
        .args(["integration", "install", "zeroclaw"])
        .status()
        .context("Failed to execute `herdr integration install zeroclaw`. Is herdr installed and in PATH?")?;

    if !status.success() {
        anyhow::bail!(
            "`herdr integration install zeroclaw` failed with exit code: {:?}",
            status.code()
        );
    }
    println!("{}", herdr_installed_message());
    Ok(())
}

fn herdr_installed_message() -> String {
    #[cfg(feature = "agent-runtime")]
    {
        get_required_cli_string("cli-herdr-installed")
    }
    #[cfg(not(feature = "agent-runtime"))]
    {
        "Herdr integration 'zeroclaw' installed successfully.".to_string()
    }
}

fn run_herdr_integration_uninstall() -> Result<()> {
    let status = Command::new("herdr")
        .args(["integration", "uninstall", "zeroclaw"])
        .status()
        .context("Failed to execute `herdr integration uninstall zeroclaw`")?;

    if !status.success() {
        anyhow::bail!(
            "`herdr integration uninstall zeroclaw` failed with exit code: {:?}",
            status.code()
        );
    }
    println!("{}", herdr_uninstalled_message());
    Ok(())
}

fn herdr_uninstalled_message() -> String {
    #[cfg(feature = "agent-runtime")]
    {
        get_required_cli_string("cli-herdr-uninstalled")
    }
    #[cfg(not(feature = "agent-runtime"))]
    {
        "Herdr integration 'zeroclaw' uninstalled successfully.".to_string()
    }
}

fn run_herdr_integration_status() -> Result<()> {
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
