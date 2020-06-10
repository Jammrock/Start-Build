# manages downloading and starting the build scripts

# downloads files from the interwebz
function Get-WebFile
{
    param ( 
        [string]$URI,
        [string]$savePath,
        [string]$fileName
    )

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

    # download time
    try 
    {
        Invoke-WebRequest -Uri $URI -OutFile "$savePath\$fileName" -EA Stop
    } 
    catch 
    {
        Write-Error "Could not download $URI`: $($Error[0].ToString())"
        return $null
    }

    #Add-Log "Downloaded successfully to: $output"
    return "$savePath\$fileName"
}

# navigate to the desktop
CD "$env:USERPROFILE\desktop"

# prompt for the settings.json location
$settingsFile = Read-Host "URL (gist, pastebin, etc. to the raw JSON file) or literal path to settings.json"

# URL to Start-Build.ps1
$URI = 'https://gist.githubusercontent.com/Jammrock/a51247baa21ac6e9355b20133efaa866/raw/3aef0529046451cd7f6fa8e1d9fe53d252d45e1e/Start-Build.ps1'

# download Start-Build.ps1
$script = Get-WebFile -URI $URI -savePath $PWD.Path -fileName "Start-Build.ps1"

# start the build process
if ($script)
{
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Unrestricted -file "$script" -settingsFile $settingsFile
}
else 
{
    Write-Error "Failed to download Start-Build.ps1 from $URI"
}
