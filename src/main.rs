use std::process::ExitCode;
use std::time::Duration;

use clipferry::clipboard::{
    ClipboardProbeOptions, PauseProbeOptions, run_clipboard_probe, run_pause_probe,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ClipFerry error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let Some(command) = arguments.next() else {
        println!("{}", clipferry::validation_banner());
        print_usage();
        return Ok(());
    };

    match command.as_str() {
        "clipboard-test" => {
            let mut lifetime = None;
            while let Some(argument) = arguments.next() {
                if argument != "--lifetime-seconds" {
                    return Err(format!("unknown argument: {argument}"));
                }
                let seconds = arguments
                    .next()
                    .ok_or_else(|| "--lifetime-seconds requires a value".to_owned())?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid lifetime: {error}"))?;
                lifetime = Some(Duration::from_secs(seconds));
            }
            run_clipboard_probe(ClipboardProbeOptions { lifetime })
                .map_err(|error| format!("{error} ({:#010X})", error.code().0.cast_unsigned()))
        }
        "clipboard-pause-test" => {
            let options = parse_pause_probe_options(arguments)?;
            run_pause_probe(options)
                .map_err(|error| format!("{error} ({:#010X})", error.code().0.cast_unsigned()))
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => Err(format!("unknown command: {command}")),
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  clipferry clipboard-test [--lifetime-seconds <seconds>]");
    println!(
        "  clipferry clipboard-pause-test [--size-mib <MiB>] [--chunk-kib <KiB>] [--delay-ms <ms>] [--async-mode] [--lifetime-seconds <seconds>]"
    );
}

fn parse_pause_probe_options(
    mut arguments: impl Iterator<Item = String>,
) -> Result<PauseProbeOptions, String> {
    let mut size_mib = 64_u64;
    let mut chunk_kib = 64_u64;
    let mut delay_ms = 8_u64;
    let mut lifetime = None;
    let mut async_mode = false;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--async-mode" => async_mode = true,
            "--size-mib" => size_mib = parse_value(&mut arguments, &argument)?,
            "--chunk-kib" => chunk_kib = parse_value(&mut arguments, &argument)?,
            "--delay-ms" => delay_ms = parse_value(&mut arguments, &argument)?,
            "--lifetime-seconds" => {
                lifetime = Some(Duration::from_secs(parse_value(&mut arguments, &argument)?));
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if size_mib == 0 || chunk_kib == 0 {
        return Err("--size-mib and --chunk-kib must be greater than zero".to_owned());
    }

    let size_bytes = size_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "--size-mib is too large".to_owned())?;
    let chunk_bytes = chunk_kib
        .checked_mul(1024)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| "--chunk-kib is too large".to_owned())?;
    Ok(PauseProbeOptions {
        size_bytes,
        chunk_bytes,
        chunk_delay: Duration::from_millis(delay_ms),
        lifetime,
        async_mode,
    })
}

fn parse_value(arguments: &mut impl Iterator<Item = String>, option: &str) -> Result<u64, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value"))?
        .parse::<u64>()
        .map_err(|error| format!("invalid value for {option}: {error}"))
}
