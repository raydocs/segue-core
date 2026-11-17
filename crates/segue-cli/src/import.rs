//! `segue import`: convert a Clash/mihomo YAML or sing-box JSON profile into
//! Segue's Xray-style JSON configuration.

use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use segue_config::import::{import_profile, ImportFormat};

use crate::CliError;

const HELP: &str = "usage: segue import <file|-> [--format clash|singbox] [-o <out.json>]

import converts a Clash/mihomo YAML or sing-box JSON profile into Segue's
Xray-style JSON configuration. It validates the result with the linked parser
and prints a warning for every source field it could not carry.
Use -o or --output to write the JSON to a file instead of stdout; - reads the
profile from stdin. Without --format the first non-space byte decides: `{` is
sing-box JSON, anything else is Clash YAML.
Exit status: 0 converted, 1 rejected profile, 2 usage or I/O failure.
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportCommand {
    Import {
        path: PathBuf,
        format: Option<ImportFormat>,
        output: Option<PathBuf>,
    },
    Help,
}

pub(super) fn parse_args(args: &[String]) -> Result<ImportCommand, CliError> {
    let invalid = || CliError::InvalidArguments(HELP.to_owned());
    if matches!(args, [flag] if flag == "--help" || flag == "-h") {
        return Ok(ImportCommand::Help);
    }
    let mut path = None;
    let mut format = None;
    let mut output = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--format" => {
                let value = iter.next().ok_or_else(invalid)?;
                if format.is_some() {
                    return Err(invalid());
                }
                format = Some(match value.as_str() {
                    "clash" => ImportFormat::Clash,
                    "singbox" | "sing-box" => ImportFormat::Singbox,
                    _ => return Err(invalid()),
                });
            }
            "-o" | "--output" => {
                let value = iter.next().ok_or_else(invalid)?;
                if output.is_some() {
                    return Err(invalid());
                }
                output = Some(PathBuf::from(value));
            }
            arg if arg.starts_with('-') && arg != "-" => return Err(invalid()),
            arg if path.is_none() => path = Some(PathBuf::from(arg)),
            _ => return Err(invalid()),
        }
    }
    Ok(ImportCommand::Import {
        path: path.ok_or_else(invalid)?,
        format,
        output,
    })
}

pub(super) fn run(command: ImportCommand) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let ImportCommand::Import {
        path,
        format,
        output,
    } = command
    else {
        out.write_all(HELP.as_bytes()).map_err(output_error)?;
        return Ok(());
    };

    let bytes = if path == Path::new("-") {
        let mut bytes = Vec::new();
        io::stdin()
            .lock()
            .read_to_end(&mut bytes)
            .map_err(|source| CliError::Output { source })?;
        bytes
    } else {
        fs::read(&path).map_err(|source| CliError::ReadConfig {
            path: path.clone(),
            source,
        })?
    };

    // `import_profile` already runs the linked parser over its output.
    let result = import_profile(&bytes, format)
        .map_err(|error| CliError::ImportFailed(format!("{}: {error}", path.display())))?;
    let json = serde_json::to_string_pretty(&result.config).map_err(|error| {
        CliError::ImportFailed(format!("serialize converted config: {error}"))
    })?;

    for warning in &result.warnings {
        eprintln!("warning: {}: {}", warning.path, warning.message);
    }

    match output {
        Some(output_path) => fs::write(&output_path, format!("{json}\n"))
            .map_err(|source| CliError::Output { source })?,
        None => {
            out.write_all(json.as_bytes()).map_err(output_error)?;
            out.write_all(b"\n").map_err(output_error)?;
            out.flush().map_err(output_error)?;
        }
    }
    Ok(())
}

fn output_error(source: io::Error) -> CliError {
    CliError::Output { source }
}
