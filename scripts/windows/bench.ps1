$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location "$RootDir\rust-core"
cargo run --release --bin iod-bench
