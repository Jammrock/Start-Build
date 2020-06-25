#requires -RunAsAdministrator
#requires -Version 5.1

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $bldPath = "C:\temp",

    [Parameter()]
    [switch]
    $driverOnly

)

function Get-WebFile
{
    param ( 
        [string]$URI,
        [string]$savePath,
        [string]$fileName
    )

    #Add-Log "Attempting to download: $dlUrl"

    # make sure we don't try to use an insecure SSL/TLS protocol when downloading files
    $secureProtocols = @() 
    $insecureProtocols = @( [System.Net.SecurityProtocolType]::SystemDefault, 
                            [System.Net.SecurityProtocolType]::Ssl3, 
                            [System.Net.SecurityProtocolType]::Tls, 
                            [System.Net.SecurityProtocolType]::Tls11) 
    foreach ($protocol in [System.Enum]::GetValues([System.Net.SecurityProtocolType])) 
    { 
        if ($insecureProtocols -notcontains $protocol) 
        { 
            $secureProtocols += $protocol 
        } 
    } 
    [System.Net.ServicePointManager]::SecurityProtocol = $secureProtocols

    try 
    {
        Invoke-WebRequest -Uri $URI -OutFile "$savePath\$fileName"
    } 
    catch 
    {
        Write-Error "Could not download $URI`: $($Error[0].ToString())"
        return $null
    }

    #Add-Log "Downloaded successfully to: $output"
    return "$savePath\$fileName"
}

Write-Host -ForegroundColor Green "Searching for supported Nvidia graphics cards."
# GeForce or Quadro
$gpu = Get-CimInstance win32_VideoController

if ($gpu.Name -match "GeForce")
{
    <# 
    METHOD 2 

    # quadro
    https://www.nvidia.com/Download/processDriver.aspx?psid=73&pfid=865&rpf=1&osid=57&lid=1&lang=en-us&ctk=0&dtid=1&dtcid=0

    #GeForce
    https://www.nvidia.com/Download/processDriver.aspx?psid=107&pfid=877&rpf=1&osid=57&lid=1&lang=en-us&ctk=0&dtid=1&dtcid=1
    #>

    Write-Host -ForegroundColor Green "Found: $(($gpu.Name | Where-Object { $_ -match "nvidia" }) -join ',')"
    Write-Host -ForegroundColor Green "Attempting to find the newest GeForce Game Ready driver."

    $dlUrl = "https://www.nvidia.com/Download/processDriver.aspx?psid=107&pfid=877&rpf=1&osid=57&lid=1&lang=en-us&ctk=0&dtid=1&dtcid=1"

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    $cookie = New-Object System.Net.Cookie

    $cookie.Name = "drvrSel"
    $cookie.Value = 'geforce|geforce rtx 20 series|geforce rtx 2080 ti|windows 10 64-bit|english (us)'
    $cookie.Domain = 'www.nvidia.com'

    $session.Cookies.Add($cookie)

    $test = Invoke-WebRequest -Uri $dlUrl -WebSession $session -UseBasicParsing
}
elseif ($gpu.Name -match "Quadro") 
{
    Write-Host -ForegroundColor Green "Found: $(($gpu.Name | Where-Object { $_ -match "nvidia" }) -join ',')"
    Write-Host -ForegroundColor Green "Attempting to find the newest Quadro driver."
    
    $dlUrl = "https://www.nvidia.com/Download/processDriver.aspx?psid=73&pfid=865&rpf=1&osid=57&lid=1&lang=en-us&ctk=0&dtid=1&dtcid=0"

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    $cookie = New-Object System.Net.Cookie

    $cookie.Name = "drvrSel"
    $cookie.Value = 'quadro|quadro series|quadro p620|optimal driver for enterprise (ode) / quadro studio|windows 10 64-bit|english (us)'
    $cookie.Domain = 'www.nvidia.com'

    $session.Cookies.Add($cookie)

    $test = Invoke-WebRequest -Uri $dlUrl -WebSession $session -UseBasicParsing
}
else 
{
    Write-Warning "Could not detect a supported Nvidia graphics card."
    return $null
}


# grab the exe link
$rootUri = "http://us.download.nvidia.com/"

$gfNextPage = Invoke-WebRequest -Uri "$($test.Content)" -UseBasicParsing

$drvUri = $gfNextPage.Links | Where-Object href -match "^.*windows.*\.exe.*$" | ForEach-Object { $_.href.Split('?')[-1].Split('&')[0].Split('=')[-1].TrimStart("/") }

$URI = "$rootUri$drvUri"

$gfFilename = $drvUri.Split('/')[-1]

Write-Host -ForegroundColor Green "Found a driver. Downloading $gfFilename. This may take a while."

# finally, download the file
$gfInstaller = Get-WebFile -URI $uri -savePath $bldPath -fileName $gfFilename


# make sure there is an installer file
if (-NOT (Test-Path $gfInstaller))
{
    Write-Error "Did not find a driver install file."
    return $null
}

Write-Host -ForegroundColor Green "Attempting to extract and install the driver."

# make sure 7-zip is installed
$7zPath = "$env:programfiles\7-zip\7z.exe"

if (-NOT (Test-Path $7zPath))
{
    winget install 7zip.7zip

    # make sure 7-zip is installed
    $7zPath = "$env:programfiles\7-zip\7z.exe"

    if (-NOT (Test-Path $7zPath))
    {
        Write-Host -ForegroundColor Green "Please manually install 7-zip before continuing. https://7-zip.org"
        Write-Host "Press any key to continue..."
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        # last chance
        if (-NOT (Test-Path $7zPath))
        {
            Write-Error "Failed to detect 7-zip. Cannot proceed. You can manually install the driver from:`n`n$gfInstaller"
        }
    }
}

# extract the file
$destPath = "$bldPath\$((Get-Item $gfInstaller).BaseName)"
& "$7zPath" x "$gfInstaller" -o"$destPath"

# run silent install
Push-Location $destPath
Write-Host -ForegroundColor Green "Starting Nvidia driver installation."
Write-Host -ForegroundColor Yellow "It is normal for the screen to flash (briefly go dark) multiple times during installation."

if ($driverOnly)
{
    Start-Process setup.exe -ArgumentList "-s Display.Driver  -clean -noreboot -noeula" -Wait
}
else 
{
    Start-Process setup.exe -ArgumentList "-s -clean -noreboot -noeula" -Wait    
}

Write-Host -ForegroundColor Green "Nvidia driver installation is complete."
Pop-Location

# clean up the installer files
Remove-Item "$gfInstaller" -Force
Remove-Item "$destPath" -Recurse -Force





    <#
        No good way to autodetect because Nvidia turned off all the RSS feeds. Needs more research.
    #>
    
    <#
        METHOD 1
    
    # find the latest game ready driver version by searching for game-ready link on the news page
    $gfgrdUrl = 'https://www.nvidia.com/en-us/geforce/news/'
    $gfPage = Invoke-WebRequest -Uri $gfgrdUrl -UseBasicParsing
    $gfArticleLink = ($gfPage.Links | Where-Object { $_.href -match "game-ready" })[0].href

    # open the top article to find the version number
    $gfNextPage = Invoke-WebRequest -Uri $gfArticleLink -UseBasicParsing
    $gfRawLine = $gfNextPage.RawContent.Split("`n") | Where-Object {$_-match "GeForce Game Ready \d{3}\.\d{2} WHQL" }

    $result = $gfRawLine -match "\d{3}\.\d{2}"

    if ($result)
    {
        $gfVer = $Matches.0
    }
    else 
    {
        # use last known driver version
        $gfVer = "446.14" 
    }

    $uri = "https://us.download.nvidia.com/Windows/$gfVer/$gfVer-desktop-win10-64bit-international-dch-whql.exe"
    $gfFilename = "$gfVer-desktop-win10-64bit-international-dch-whql.exe"

    $gfInstaller = Get-WebFile -URI $uri -savePath $bldPath -fileName $gfFilename

    #>
