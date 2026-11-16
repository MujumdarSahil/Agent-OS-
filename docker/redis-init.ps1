# Creates docker/.env.redis with random password (once) and prints the
# connection string for AGENTOS_REDIS_URI. Never commit docker/.env.redis.
$ErrorActionPreference = "Stop"
$envFile = Join-Path $PSScriptRoot ".env.redis"

if (-not (Test-Path $envFile)) {
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $password = ([Convert]::ToBase64String($bytes)) -replace '[+/=]', ''
    @(
        "AGENTOS_REDIS_PASSWORD=$password"
    ) | Set-Content -Encoding ascii $envFile
    Write-Host "Created $envFile"
}

$vals = @{}
Get-Content $envFile | ForEach-Object { $k, $v = $_ -split '=', 2; $vals[$k] = $v }
$port = if ($env:AGENTOS_REDIS_PORT) { $env:AGENTOS_REDIS_PORT } else { "6379" }
$uri = "redis://:$($vals.AGENTOS_REDIS_PASSWORD)@127.0.0.1:$port/0"
Write-Host "`nSet for this shell:`n  `$env:AGENTOS_REDIS_URI=`"$uri`""
