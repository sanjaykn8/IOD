$ErrorActionPreference = "Stop"
$RootDir = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location "$RootDir\rust-core"
New-Item -ItemType Directory -Force -Path "$RootDir\examples\test-vectors" | Out-Null
cargo run --release --bin iod-vectors -- "$RootDir\examples\test-vectors"
