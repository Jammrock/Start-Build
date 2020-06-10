#requires -RunAsAdministrator
#requires -Version 5.1

<#
    TO-DO

    - DONE: Update drivers via WU: Get-WindowsUpdate -WindowsUpdate -UpdateType Driver -AcceptAll -Verbose -IgnoreReboot
    - DONE: Add Environment variables: SYSTEM and User(?)
    - Download and install projects from GitHub
    - Download and install files from web sites...?
    - Autologon after reboots. (doesn't work on VMs?)
    - DONE: Help file
    - DONE: Set computername
    - DONE: Set timezone ... https://support.microsoft.com/en-us/help/973627/microsoft-time-zone-index-values ... Name of Time Zone

#>


<#
.SYNOPSIS
    Performs basic setup for a new Windows 10 installation.
.DESCRIPTION
    Performs basic setup for a new Windows 10 installation. Setup is performed in phases with auto-reboots between phases, as needed.

    A settings.json file is required. The settings file contains details about how the system should be setup.
.EXAMPLE
    .\Start-Build -settingsFile "C:\Temp\settings.json"
    
    Begins the build using a settings file in C:\Temp.
.NOTES
    Author: James "Jammrock" Kehr
    
.LINK
    More projects : https://github.com/jammrock
#>

param(
    <#
    Controls which phase of setup to execute first.

    1 - Configure the system (computername, timezone, env variables...)
    2 - Install Windows capabilities
    3 - Disable Windows features
    4 - Enable Windows features
    5 - Get drivers from Windows Update.
    6 - Download and install winget, then install apps through winget
    7 - Install PowerShell modules
    # - Any number not associated with a phase will trigger cleanup.

    #>
    [int]$Phase = 0,

    <#
    Path to settings.json. This can be either a local file, UNC path, or URL to the raw file in GitHub, Pastebin, etc.
    #>
    [string]$settingsFile = $null,

    <#
    Location where downloads and other script files will be created.
    #>
    [string]$bldPath = "C:\Temp"
)


    <#
    Turns off the autologon ability. The username and password must be manually entered after each reboot when autologon is disabled.
    #>
    #[switch]$noAutoLogon

## functions go here ##
#region FUNCTIONS
function Start-Reboot
{
    param(
        [int]$phase,
        [string]$settingsFile,
        [string]$bldPath,
        [switch]$noPhaseInc
    )

    # look for an old task and remove it
    $oldTaskName = 'Start-Rebuild-Phase-$phase'
    Unregister-ScheduledTask -TaskName $oldTaskName -Confirm:$false -EA SilentlyContinue | Out-Null

    if (-NOT $noPhaseInc)
    {
        # increment phase by 1. The COMMON region increments by 1 after WU so do not increment by more than 1
        $newPhase = $phase++
    }
    else 
    {
        $newPhase = $phase
    }

    ## create the logon task
    # launch PowerShell script from batch file, as they are more reliable with tasks
    $batchCMD = @"
@echo off
powershell -NoLogo -NoProfile -ExecutionPolicy Unrestricted -file "$scriptPath\Start-Build.ps1" -Phase $newPhase -settingsFile "$settingsFile" -bldPath "$bldPath"
"@

    # create the batch file
    $batchCMD | Out-File "$scriptPath\build.cmd" -Encoding ascii -Force

    $taskActionCmd = "cmd.exe"
    $taskArgument = "/c build.cmd"
    $taskName = 'Run-Start-Build-After-Reboot'
    $taskDescription = 'Restarts build script on reboot.'
    $taskAction = New-ScheduledTaskAction -WorkingDirectory "$scriptPath" -Execute $taskActionCmd -Argument $taskArgument
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME" # -RandomDelay ([TimeSpan]::FromMinutes(1)) 
    
    try 
    {
        # try to create the 
        $taskSplat = @{
            TaskName    = $taskName
            Action      = $taskAction
            Settings    = $taskSettings
            Trigger     = $taskTrigger
            Description = $taskDescription
            RunLevel    = "Highest"
            Force       = $true
            ErrorAction = "Stop"
        }
        
        Register-ScheduledTask @taskSplat
    } 
    catch 
    {
        Write-Error "Failed to create reboot task. Please manually reboot and rerun the script. Error: $_"
        exit
    }

    # reboot
    Restart-Computer -Force
}

function Get-NewestGitRelease
{
    param(
        [string]$URI,
        [string]$savePath,
        [string]$fileName
    )

    # list of extensions 
    $extension = $fileName.Split('.')[-1]

    # get the available releases
    try 
    {
        $rawReleases = Invoke-WebRequest $URI -UseBasicParsing -EA Stop    
    }
    catch 
    {
        Write-Error "Could not get GitHub releases. Error: $($error[0].ToString())"
        return $null
    }

    # process links
    [array]$rawDlLink = $rawReleases.Links.href | Where-Object { $_ -match $extension }

    $dlLink = @()
    foreach ($link in $rawDlLink)
    {
        [string]$version = $link | ForEach-Object { $_.Split('/') } | Where-Object { $_ -match "^v\d{1,2}.*$" } | ForEach-Object { $_.Split('-')[0].Trim('v') }
        [int]$major = $version.Split('.')[0]
        [int]$minor = $version.Split('.')[1]
        [int]$build = $version.Split('.')[2]

        $dlLink += [PSCustomObject]@{
            URI = "$gitURI$link"
            Version = $version
            Major = $major
            Minor = $minor
            Build = $build
        }
    }

    $dlURI = ($dlLink | Sort-Object -Property Major,Minor,Build -Descending)[0].URI

    try 
    {
        Invoke-WebRequest -Uri $dlURI -OutFile "$savePath\$fileName" -ErrorAction Stop
    }
    catch 
    {
        Write-Error "Failed to download $fileName. Please try manually: $dlURI"
        return $null
    }

    return "$savePath\$fileName"
}


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

function New-Phase
{
    param (
        $restart,
        $Phase,
        $bldPath,
        $settingsFile,
        [switch]$noPhaseInc
    )

    # if we already know to reboot, don't check
    if (-NOT $restart)
    {
        $restart = (Test-PendingReboot -SkipConfigurationManagerClientCheck).IsRebootPending
    }

    # reboot or increment phase            
    if ($restart)
    {
        if ($noPhaseInc)
        {
            Start-Reboot -phase $Phase -settingsFile $settingsFile -bldPath $bldPath -noPhaseInc
        }
        else 
        {
            Start-Reboot -phase $Phase -settingsFile $settingsFile -bldPath $bldPath
        }
    }
    else 
    {
        $phase++
    }

    return $Phase
}

function Reset-Path
{
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
}

#endregion FUNCTIONS

## code in this region runs on every execution ##
#region COMMON

Write-Host "Getting things ready."
$ProgressPreference = "SilentlyContinue"

# reboot when done?
$restart = $false

# location to download files and such
if (-NOT (Test-Path $bldPath)) { mkdir $bldPath -Force | Out-Null }

# setup scriptPath
if ($PSScriptRoot)
{
    $scriptPath = $script:scriptPath = $PSScriptRoot
}
else 
{
    $scriptPath = $script:scriptPath = $PWD.Path
}

#Write-Output "scriptPath: $scriptPath"

# convert the setup.json file to a variable
# start by trying to parse the settingsFile as a URI, which will determine if this is a URI or file.
try 
{
    $testURI = New-Object System.Uri $settingsFile -EA Stop    
} 
catch 
{
    Write-Verbose "settingsFile is not a URI."
}

# process the settings file
switch -regex ($testURI.Scheme)
{
    
    "https|http" 
    {
        $settingsPath = Get-WebFile -URI $settingsFile -savePath $scriptPath -fileName "settings.json"
    }
    
    "file"
    {
        if ((Test-Path $settingsFile))
        {
            if ($settingsFile -match "settings.json")
            {
                $settingsPath = $settingsFile
            }
            else 
            {
                $settingsPath = "$scriptPath\setup.json"
            }
        }
        else 
        {
            Write-Error "Copuld not find settings.json file."
            exit
        }
        
        
    }

    default
    {
        $settingsPath = "$scriptPath\setup.json"
    }

}

if ($settingsPath)
{
    #Write-Output "settingsPath: $settingsPath"
    $setup = Get-Content $settingsPath | ConvertFrom-Json
}
else 
{
    Write-Error "Copuld not find settings.json file."
    exit
}

if (-NOT $setup)
{
    Write-Error "Failed to find a settings file. Please make sure settings.json is in the same dir as the script, or the raw file (i.e. Gist, pastebin, etc.) is available."
    exit
}



# make sure PowerShellGet is version 2.2.4
$psgVer = (Get-Module -ListAvailable PowerShellGet).Version

$updatePSG = $false

if ($psgVer -is [array])
{
    $psgVer = $psgVer | Where-Object {$_.Major -ge 2 -and $_.Minor -ge 2 -and $_.Build -ge 4}
}

if ($psgVer.Major -lt 2)
{
    $updatePSG = $true
}
elseif (($psgVer.Major -eq 2 -and $psgVer.Minor -lt 2) -or ($psgVer.Major -eq 2 -and $psgVer.Minor -eq 2 -and $psgVer.Build -lt 4))
{
    $updatePSG = $true
}
elseif (-NOT $psgVer)
{
    $updatePSG = $true
}

if ($updatePSG)
{
    Write-Host "Updating PowerShellGet for PSGallery compatibility."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name PowerShellGet -MinimumVersion 2.2.4.1 -Force

    # restart the script in a new console or PowerShellGet will not work
    $argument = @"
    -noprofile -nologo -noexit -ExecutionPolicy Unrestricted -File .\Start-Build.ps1 -Phase $Phase -settingsFile "$settingsFile" -bldPath "$bldPath"
"@

    Write-Output "args: $argument"
    Start-Process powershell -WorkingDirectory $scriptPath -ArgumentList $argument -WindowStyle Normal

    Start-Sleep 2
    exit
}


# get the PendingReboot module   
$prFnd = Get-Module -ListAvailable PendingReboot

if (-NOT $prFnd)
{
    Install-Module -Name PendingReboot -Force
}

# run updates - always run updates 
Write-Output "Checking for Windows Updates."
$wuFnd = Get-Module -ListAvailable WindowsUpdateProvider -EA SilentlyContinue

if ($wuFnd)
{
    try 
    {
        $Updates = Start-WUScan -EA Stop
    }
    catch 
    {
        Write-Error "Could not scan for updates. $_"
    }

    if ($Updates)
    {
        Write-Host "Applying Windows Updates. The process may take a long time during the first run. Please be patient."
        Install-WUUpdates -Updates $Updates
    }

}
else 
{
    # try the public module
    Install-Module -Name PSWindowsUpdate -MinimumVersion 2.2.0 -Force
    Get-WindowsUpdate -AcceptAll -Verbose -WindowsUpdate -Install -IgnoreReboot
}

# check for pending reboot
# do not increment the phase here or phases may be skipped
$phase = New-Phase -restart $restart -Phase $Phase -bldPath $bldPath -settingsFile $settingsPath -noPhaseInc
    

#endregion COMMON

## control loop ##
## This is where the scripts loops through the phases.
while ($true)
{
    switch ($phase)
    {
        # Configure system.
        1
        {
            Write-Output "Configuring system."
            # change the computer name
            if ($setup.computerName)
            {
                Rename-Computer -NewName "$($setup.computerName)" -Force
            }

            if ($setup.timeZone)
            {
                Set-TimeZone -Id "$($setup.timeZone)"
            }

            if ($setup.userEnv)
            {
                # the user Environment path
                $uevPath = 'Registry::HKEY_CURRENT_USER\Environment'
                
                foreach ($uev in $setup.userEnv)
                {
                    # add or update the user environment variable
                    switch ($uev.name)
                    {
                        # path is appended
                        "path"
                        {
                            # append the use path
                            $oldPath = (Get-ItemProperty -Path $uevPath -Name PATH).path

                            $newPath = $oldPath, $uev.value -join ';'

                            try 
                            {
                                Set-ItemProperty -Path $uevPath -Name PATH -Value $newPath -ErrorAction Stop
                            }
                            catch 
                            {
                                Write-Error "Failed to update User Path: $_"
                            }
                            finally
                            {
                                Reset-Path
                            }
                        }

                        # default adds or overwrites the value
                        default
                        {
                            $uThere = Get-ItemProperty -Path $uevPath -Name $uev.name -EA SilentlyContinue

                            # overwrite an existing value
                            if ($uThere)
                            {
                                try 
                                {
                                    Set-ItemProperty -Path $uevPath -Name $uev.name -Value $uev.value -Force    
                                }
                                catch 
                                {
                                    Write-Error "Failed to change $($uev.name) user environment variable. $_"
                                }
                                
                            }
                            # else make a new one
                            else 
                            {
                                try 
                                {
                                    New-ItemProperty -Path $uevPath -Name $uev.name -Value $uev.value -Force
                                }
                                catch 
                                {
                                    Write-Error "Failed to add $($uev.name) to user environment. $_"
                                }
                            }
                        }
                    }
                }
            }

            if ($setup.systemEnv)
            {
                # the user Environment path
                $sevPath = 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment'
                
                foreach ($sev in $setup.systemEnv)
                {
                    # add or update the user environment variable
                    switch -Regex ($sev.name)
                    {
                        # path is appended
                        "^path$|^PATHEXT$|^PSModulePath$"
                        {
                            # which key are we messing with?
                            $sevKey = $sev.name
                            
                            # append the use path
                            $oldPath = (Get-ItemProperty -Path $sevPath -Name $sevKey)."$sevKey"

                            $newPath = $oldPath, $sev.value -join ';'

                            try 
                            {
                                Set-ItemProperty -Path $sevPath -Name $sevKey -Value $newPath -ErrorAction Stop
                            }
                            catch 
                            {
                                Write-Error "Failed to update User Path: $_"
                            }
                            finally
                            {
                                Reset-Path
                            }
                        }

                        # default adds or overwrites the value
                        default
                        {
                            $uThere = Get-ItemProperty -Path $sevPath -Name $sev.name -EA SilentlyContinue

                            # overwrite an existing value
                            if ($uThere)
                            {
                                try 
                                {
                                    Set-ItemProperty -Path $sevPath -Name $sev.name -Value $sev.value -Force    
                                }
                                catch 
                                {
                                    Write-Error "Failed to change $($sev.name) user environment variable. $_"
                                }
                                
                            }
                            # else make a new one
                            else 
                            {
                                try 
                                {
                                    New-ItemProperty -Path $sevPath -Name $sev.name -Value $sev.value -Force
                                }
                                catch 
                                {
                                    Write-Error "Failed to add $($sev.name) to user environment. $_"
                                }
                            }
                        }
                    }
                }
            }

            # check for pending reboot
            $phase = New-Phase -restart $restart -Phase $Phase -bldPath $bldPath -settingsFile $settingsPath

            break
        }
        
        # install Windows capabilities
        2
        {
            if ($setup.winCapabilities)
            {
                # install Windows capabilities
                $winCapabilities = Get-WindowsCapability -Online

                Write-Host "Installing Windows Capabilities."
                foreach ($capability in $setup.winCapabilities)
                {
                    [array]$package = $winCapabilities | Where-Object { $_.Name -match "$capability*" -and $_.State -eq "NotPresent" }

                    if ($package)
                    {
                        Write-Host "Installing $($package.Name | Out-String)"
                        $package | ForEach-Object { Add-WindowsCapability -Online -Name $_ }
                    }
                }
            }

            # check for pending reboot
            $phase = New-Phase -restart $restart -Phase $Phase -bldPath $bldPath -settingsFile $settingsPath

            break
        }

        # disable Windows features
        3
        {
            if ($setup.winFeaturesDisable)
            {
                # disable winFeaturesDisable
                Write-Host "Disabling Windows Optional Features."

                $winFeatures = Get-WindowsOptionalFeature -Online -EA SilentlyContinue
                $numFeats = $setup.winFeaturesDisable.Count
                $i = 1

                foreach ($feat in $setup.winFeaturesDisable)
                {
                    if ($feat -in $winFeatures.FeatureName)
                    {
                        Write-Host -ForegroundColor Green "[$i\$numFeats] Removing $feat."
                        $result = Disable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction SilentlyContinue
                    }
                    else 
                    {
                        Write-Host -ForegroundColor Yellow "[$i\$numFeats] Feature not found: $feat."
                    }

                    if ($result.RestartNeeded)
                    {
                        $restart = $true
                    }

                    $i++
                }
            }

            # check for pending reboot
            $phase = New-Phase -restart $restart -Phase $Phase -bldPath $bldPath -settingsFile $settingsPath

            break
        }

        # enable Windows features
        # features first in case someone wants to install a WSL Linux distro via winget later
        4
        {
            # enable winFeaturesEnable
            if ($setup.winFeaturesEnable)
            {
                # disable winFeaturesDisable
                Write-Host "Enabling Windows Optional Features."

                $winFeatures = Get-WindowsOptionalFeature -Online -EA SilentlyContinue
                $numFeats = $setup.winFeaturesEnable.Count
                $i = 1

                foreach ($feat in $setup.winFeaturesEnable)
                {
                    if ($feat -in $winFeatures.FeatureName)
                    {
                        Write-Host -ForegroundColor Green "[$i\$numFeats] Adding $feat."
                        $result = Enable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction SilentlyContinue
                    }
                    else 
                    {
                        Write-Host -ForegroundColor Yellow "[$i\$numFeats] Feature not found: $feat."
                    }

                    if ($result.RestartNeeded)
                    {
                        $restart = $true
                    }

                    $i++
                }
            }

            # check for pending reboot
            $phase = New-Phase -restart $restart -Phase $Phase -bldPath $bldPath -settingsFile $settingsPath

            break
        }

        # get drivers from Windows Update.
        5
        {
            Write-Output "Checking Windows Update for driver updates."
            Get-WindowsUpdate -WindowsUpdate -UpdateType Driver -AcceptAll -Verbose -IgnoreReboot
            
            #check for pending reboot
            $phase = New-Phase -restart $restart -Phase $Phase -bldPath $bldPath -settingsFile $settingsPath

            break
        }
        
        # download and install winget, then install apps through winget
        6
        {
            # automate removal of as many default Win10 apps as possible
            Write-Host "Removing default apps."
            $exclusions = 'Microsoft.VCLibs.140.00','Microsoft.WindowsStore','Microsoft.DesktopAppInstaller'
            Get-AppxPackage | Where-Object Name -notin $exclusions | Remove-AppPackage -Confirm:$false -EA SilentlyContinue | Out-Null
            Get-AppxPackage -AllUsers | Where-Object Name -notin $exclusions | Remove-AppPackage -Confirm:$false -EA SilentlyContinue | Out-Null

            # update store stuff
            #Get-AppxPackage -allusers Microsoft.WindowsStore | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}

            # install winget if it's not there
            $wingetFnd = Get-Command winget -ErrorAction SilentlyContinue

            if (-NOT $wingetFnd)
            {
                Write-Host "Installing winget."
                # install winget
                $gitURI = 'https://github.com'
                $releaseURI = "$gitURI/microsoft/winget-cli/releases"

                $wingetPath = Get-NewestGitRelease -URI $releaseURI -savePath $bldPath -fileName "winget.appxbundle"

                # install winget and dependencies
                if ($wingetPath)
                {
                    try 
                    {
                        Add-AppxPackage $wingetPath -InstallAllResources -EA Stop
                    }
                    catch
                    {
                        Write-Host -ForegroundColor Yellow "Need a little help!`nThe automated install of winget failed. Please click Update to proceed."
                        & $wingetPath
                        do
                        {
                            Start-Sleep 1
                            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
                    
                            # install winget if it's not there
                            $wingetFnd = Get-Command winget -ErrorAction SilentlyContinue
                        } until ($wingetFnd)
                    }
                    
                }

                # start phase 2
                #Start-Process powershell -ArgumentList "-Command { Start-Sleep 5; Push-Location $scriptPath; .\Start-Rebuild.ps -Phase2}"
                Reset-Path
                
                # install winget if it's not there
                $wingetFnd = Get-Command winget -ErrorAction SilentlyContinue
            }

            # install winget packages
            # https://github.com/microsoft/winget-pkgs/tree/master/manifests
            Write-Host "Installing apps through winget."
            $count = 1
            $total = $setup.wingetApps.Count
            $setup.wingetApps | Foreach-Object { 
                Write-Host -Fore Green "[$count/$total] Installing $_ ..."
                winget install --id $_ --exact
                $count++
            }

            # check for pending reboot
            $phase = New-Phase -restart $restart -Phase $Phase -bldPath $bldPath -settingsFile $settingsPath

            break
        }

        # install PowerShell modules
        7
        {
            # install PowerShell modules
            Write-Host "Installing PowerShell modules"
            $i = 1
            $tots = $setup.pwshModules.Count
            foreach ($module in $setup.pwshModules)
            {
                Write-Host -ForegroundColor Green "[$i\$tots] Installing $module`."
                Install-Module -Name $module -AcceptLicense -Force
                $i++
            }
            
            # check for pending reboot
            $phase = New-Phase -restart $restart -Phase $Phase -bldPath $bldPath -settingsFile $settingsPath

            break
        }

        # cleanup
        default
        {
            # cleanup 
            if ((Test-Path "$scriptPath\build.cmd"))
            {
                Remove-Item "$scriptPath\build.cmd" -Force
            }

            $taskName = 'Run-Start-Build-After-Reboot'
            $task = Get-ScheduledTask $taskName -EA SilentlyContinue
            if ($task)
            {
                $task | Unregister-ScheduledTask -Confirm:$false
            }


            # check for pending reboot
            $phase = New-Phase -restart $restart -Phase $Phase -bldPath $bldPath -settingsFile $settingsPath

            Write-Host "Work complete!"
            exit
        }
    }
}

