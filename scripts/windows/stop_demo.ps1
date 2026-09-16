$RootDir = (Resolve-Path "$PSScriptRoot\..\..").Path
$PidDir = "$RootDir\.demo-pids"

foreach ($name in @("rust", "python", "node")) {
    $pidFile = "$PidDir\$name.pid"
    if (Test-Path $pidFile) {
        $procId = Get-Content $pidFile
        try {
            Stop-Process -Id $procId -ErrorAction Stop
            Write-Host "Stopped $name (pid $procId)"
        } catch {
            Write-Host "$name (pid $procId) was not running"
        }
        Remove-Item $pidFile
    }
}
