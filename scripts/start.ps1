$ErrorActionPreference = "Stop"

$labRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $labRoot

function New-LabSecret {
    $bytes = New-Object byte[] 24
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    } finally {
        $generator.Dispose()
    }
    return ([Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_"))
}

if (-not (Test-Path -LiteralPath ".env")) {
    $existingVolume = docker volume ls --quiet --filter "name=^zero-trust-network-lab_keycloak-data$"
    if ($existingVolume) {
        throw ".env is missing but the persisted Keycloak volume still exists. Restore the original .env, or intentionally reset the lab with: docker volume rm zero-trust-network-lab_keycloak-data"
    }
    $adminPassword = New-LabSecret
    $alicePassword = New-LabSecret
    $bobPassword = New-LabSecret
    $generatedKeycloakPort = if ($env:ZT_KEYCLOAK_HOST_PORT) { $env:ZT_KEYCLOAK_HOST_PORT } else { "8080" }
    $generatedPepPort = if ($env:ZT_PEP_HOST_PORT) { $env:ZT_PEP_HOST_PORT } else { "8081" }
    @(
        "KEYCLOAK_ADMIN=admin"
        "KEYCLOAK_ADMIN_PASSWORD=$adminPassword"
        "ALICE_PASSWORD=$alicePassword"
        "BOB_PASSWORD=$bobPassword"
        "KEYCLOAK_HOST_PORT=$generatedKeycloakPort"
        "PEP_HOST_PORT=$generatedPepPort"
        "OIDC_ISSUER=http://localhost:$generatedKeycloakPort/realms/zero-trust"
        "OIDC_AUDIENCE=zero-trust-api"
    ) | Set-Content -LiteralPath ".env" -Encoding ASCII
    Write-Host "[INFO] Generated random local credentials in .env (gitignored)."
}

$labEnvironment = @{}
foreach ($line in Get-Content -LiteralPath ".env") {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
    $parts = $trimmed.Split("=", 2)
    if ($parts.Count -eq 2) { $labEnvironment[$parts[0]] = $parts[1] }
}
$keycloakPort = if ($labEnvironment.ContainsKey("KEYCLOAK_HOST_PORT")) { $labEnvironment["KEYCLOAK_HOST_PORT"] } else { "8080" }
$pepPort = if ($labEnvironment.ContainsKey("PEP_HOST_PORT")) { $labEnvironment["PEP_HOST_PORT"] } else { "8081" }

docker compose config --quiet
docker compose up --build -d

function Wait-LabEndpoint {
    param([string]$Name, [string]$Uri)
    Write-Host "Waiting for $Name..."
    # Keycloak's first Quarkus augmentation and realm import can be slow on Docker Desktop.
    for ($i = 0; $i -lt 300; $i++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 2 | Out-Null
            return
        } catch {
            Start-Sleep -Seconds 2
        }
    }
    throw "$Name did not become ready in time. Check: docker compose logs"
}

Wait-LabEndpoint -Name "Keycloak" -Uri "http://localhost:$keycloakPort/realms/zero-trust/.well-known/openid-configuration"
Wait-LabEndpoint -Name "PEP" -Uri "http://localhost:$pepPort/healthz"

Write-Host "The lab is ready."
Write-Host "Keycloak: http://localhost:$keycloakPort"
Write-Host "PEP:      http://localhost:$pepPort"
Write-Host "Tests:    ./scripts/test-access.ps1"
