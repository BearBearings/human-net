use anyhow::Result;
use clap::ValueEnum;
use serde_json::Value;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

pub struct CommandOutput {
    pub message: String,
    pub payload: Value,
}

impl CommandOutput {
    pub fn new(message: impl Into<String>, payload: Value) -> Self {
        Self {
            message: message.into(),
            payload,
        }
    }

    pub fn render(&self, format: OutputFormat) -> Result<()> {
        match format {
            OutputFormat::Text => {
                println!("{}", self.message);
            }
            OutputFormat::Json => {
                let rendered = serde_json::to_string_pretty(&self.payload)?;
                println!("{rendered}");
            }
        }
        Ok(())
    }
}
