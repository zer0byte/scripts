# LoLDrivers feed (maintained by community)
$lolDriversUrl = "https://www.loldrivers.io/api/drivers.json"

# Download the JSON feed
try {
    $lolDrivers = Invoke-RestMethod -Uri $lolDriversUrl -UseBasicParsing
} catch {
    Write-Error "Could not fetch LoLDrivers feed. Check connectivity."
    exit
}

Write-Host "[*] Collected $($lolDrivers.Count) known vulnerable drivers from LoLDrivers.io"

# Get installed signed drivers
$drivers = Get-WmiObject Win32_PnPSignedDriver | 
           Select-Object DeviceName, DriverVersion, Manufacturer, InfName, DriverProviderName, DriverDate, DriverFileName

# Compare locally installed drivers with LoLDrivers DB
$results = foreach ($driver in $drivers) {
    foreach ($lol in $lolDrivers) {
        if ($driver.DriverFileName -and $lol.file_name -and ($driver.DriverFileName -ieq $lol.file_name)) {
            [PSCustomObject]@{
                Device       = $driver.DeviceName
                LocalVersion = $driver.DriverVersion
                Vendor       = $driver.Manufacturer
                Vulnerable   = $true
                KnownBadVer  = $lol.vulnerable_version
                FileName     = $driver.DriverFileName
                Reference    = $lol.source_url
            }
        }
    }
}

if ($results) {
    Write-Host "`n[!] Vulnerable drivers detected on this system:" -ForegroundColor Red
    $results | Format-Table -AutoSize
} else {
    Write-Host "`n[+] No known vulnerable drivers from LoLDrivers.io were detected locally." -ForegroundColor Green
}
