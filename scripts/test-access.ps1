$ErrorActionPreference = "Stop"

$labRoot = Split-Path -Parent $PSScriptRoot
$envPath = Join-Path $labRoot ".env"
if (-not (Test-Path -LiteralPath $envPath)) {
    throw ".env is missing. Run ./scripts/start.ps1 first."
}

$labEnvironment = @{}
foreach ($line in Get-Content -LiteralPath $envPath) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
    $parts = $trimmed.Split("=", 2)
    if ($parts.Count -eq 2) { $labEnvironment[$parts[0]] = $parts[1] }
}
if (-not $labEnvironment.ContainsKey("ALICE_PASSWORD") -or -not $labEnvironment.ContainsKey("BOB_PASSWORD")) {
    throw ".env does not contain the generated lab user credentials."
}
$keycloakPort = if ($labEnvironment.ContainsKey("KEYCLOAK_HOST_PORT")) { $labEnvironment["KEYCLOAK_HOST_PORT"] } else { "8080" }
$pepPort = if ($labEnvironment.ContainsKey("PEP_HOST_PORT")) { $labEnvironment["PEP_HOST_PORT"] } else { "8081" }

function Get-LabToken {
    param(
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $body = @{
        grant_type = "password"
        client_id  = "zero-trust-cli"
        username   = $Username
        password   = $Password
    }
    $response = Invoke-RestMethod -Method Post `
        -Uri "http://localhost:$keycloakPort/realms/zero-trust/protocol/openid-connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body $body
    return $response.access_token
}

function Invoke-LabRequest {
    param(
        [string]$Token,
        [bool]$Managed = $true,
        [string]$Edr = "healthy",
        [int]$PatchAge = 3,
        [int]$Risk = 10,
        [string]$Method = "GET"
    )

    $headers = @{
        "X-Device-Managed" = $Managed.ToString().ToLowerInvariant()
        "X-EDR-Status" = $Edr
        "X-Patch-Age-Days" = $PatchAge.ToString()
        "X-Risk-Score" = $Risk.ToString()
    }
    if ($Token) {
        $headers["Authorization"] = "Bearer $Token"
    }

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Method $Method -Uri "http://localhost:$pepPort/project" -Headers $headers
        return [int]$response.StatusCode
    } catch {
        if ($null -ne $_.Exception.Response) {
            return [int]$_.Exception.Response.StatusCode
        }
        throw
    }
}

function Assert-Status {
    param([string]$Name, [int]$Expected, [int]$Actual)
    if ($Expected -eq $Actual) {
        Write-Host "[PASS] $Name -> HTTP $Actual" -ForegroundColor Green
        return $true
    }
    Write-Host "[FAIL] $Name -> expected $Expected, actual $Actual" -ForegroundColor Red
    return $false
}

$alice = Get-LabToken -Username "alice" -Password $labEnvironment["ALICE_PASSWORD"]
$bob = Get-LabToken -Username "bob" -Password $labEnvironment["BOB_PASSWORD"]

$results = @(
    (Assert-Status "T01 developer + compliant device" 200 (Invoke-LabRequest -Token $alice)),
    (Assert-Status "T02 unmanaged device" 403 (Invoke-LabRequest -Token $alice -Managed $false)),
    (Assert-Status "T03 employee without developer role" 403 (Invoke-LabRequest -Token $bob)),
    (Assert-Status "T04 missing token" 401 (Invoke-LabRequest -Token "")),
    (Assert-Status "T05 high-risk session" 403 (Invoke-LabRequest -Token $alice -Risk 80)),
    (Assert-Status "T06 stale patches" 403 (Invoke-LabRequest -Token $alice -PatchAge 45)),
    (Assert-Status "T07 POST method" 403 (Invoke-LabRequest -Token $alice -Method "POST"))
)

if ($results -contains $false) {
    exit 1
}

Write-Host "All zero-trust access tests passed." -ForegroundColor Cyan
