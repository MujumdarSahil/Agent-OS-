# Creates docker/.env.mongo with random root credentials (once) and prints the
# connection string for AGENTOS_MONGO_URI. Never commit docker/.env.mongo.
$ErrorActionPreference = "Stop"
$envFile = Join-Path $PSScriptRoot ".env.mongo"

if (-not (Test-Path $envFile)) {
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $password = ([Convert]::ToBase64String($bytes)) -replace '[+/=]', ''
    @(
        "MONGO_INITDB_ROOT_USERNAME=agentos"
        "MONGO_INITDB_ROOT_PASSWORD=$password"
    ) | Set-Content -Encoding ascii $envFile
    Write-Host "Created $envFile"
}

$vals = @{}
Get-Content $envFile | ForEach-Object { $k, $v = $_ -split '=', 2; $vals[$k] = $v }
$uri = "mongodb://$($vals.MONGO_INITDB_ROOT_USERNAME):$($vals.MONGO_INITDB_ROOT_PASSWORD)@127.0.0.1:27017/?replicaSet=rs0&authSource=admin"
Write-Host "`nSet for this shell:`n  `$env:AGENTOS_MONGO_URI=`"$uri`""
