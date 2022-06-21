#requires -Version 5.1

<#
    TO-DO:

    - Add logging.
    - Use Github API to find the newest release rather than page parsing.


    The Graveyard (rejected ideas):

    - Out-of-scope: Download and install projects from GitHub
    - Out-of-scope: Download and install files from web sites...?


    What's not working:

    - AutoLogon is not consistent on Windows Hello capable devices. Needs more testing and tweaking.

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
    8 - Download and install supported graphics drivers
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

## classes go here ##
#region CLASSES

# there is a Windows system object called Version, so do not rename this to Version!
class PSVersion {
    [ValidateNotNullOrEmpty()][int]$Major
    [ValidateNotNullOrEmpty()][int]$Minor
    [int]$Build
    [int]$Revision

    PSVersion()
    {
        [int]$this.Major = -1
        [int]$this.Minor = -1
        [int]$this.Build = -1
        [int]$this.Revision = -1
    }

    PSVersion(
        $maj,
        $min
    )
    {
        [int]$this.Major = $maj
        [int]$this.Minor = $min
        [int]$this.Build = -1
        [int]$this.Revision = -1
    }

    PSVersion(
        $maj,
        $min,
        $bld
    )
    {
        [int]$this.Major = $maj
        [int]$this.Minor = $min
        [int]$this.Build = $bld
        [int]$this.Revision = -1
    }

    PSVersion(
        $maj,
        $min,
        $bld,
        $rev
    )
    {
        [int]$this.Major = $maj
        [int]$this.Minor = $min
        [int]$this.Build = $bld
        [int]$this.Revision = $rev
    }

    [string]GetVersion()
    {
        $str = ("{0}.{1}" -f $this.Major, $this.Minor)

        if ($this.Build -ne -1)
        {
            $str += ".$($this.Build)"
        }

        if ($this.Revision -ne -1)
        {
            $str += ".$($this.Revision)"
        }

        return $str
    }

    [string]ToList()
    {
        return ("Major`t`t: {0}`nMinor`t`t: {1}`nBuild`t`t: {2}`nRevision`t: {3}" -f $this.Major, $this.Minor, $this.Build, $this.Revision)
    }

    [string]ToString()
    {
        return $this.GetVersion()
    }
}

#endregion CLASSES


## variables/constansts for values that may change in the future ##
#region VARIABLES

# required minimum version of PowerShellGet
$psgMinVer = [PSVersion]::New(2,2,4,1)

# required minimum version of NuGet
$nugetMinVer = [PSVersion]::New(2,8,5,201)


# show progress bars
# Default: SilentlyContinue
# Change to Continue to see the progress bars.
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7
$ProgressPreference = "SilentlyContinue"

# reboot when done? Defaults to $false/no, unless a program/install requires it.
$restart = $false


<#
Moving this param to settings.json to make it easier to execute when using the GitHub instructions
Turns off the autologon ability. The username and password must be manually entered after each reboot when autologon is disabled.
#>
#[switch]$noAutoLogon
#endregion VARIABLES


## functions go here ##
#region FUNCTIONS

function Restart-ScriptAsAdmin
{
    param(
        $Phase,
        $settingsFile,
        $bldPath
    )

    Write-Host 'Attempting automatic elevation.'
    $newProcess = New-Object Diagnostics.ProcessStartInfo 'powershell.exe'
    $newProcess.Arguments = "-noprofile -nologo -ExecutionPolicy Unrestricted -File `"$($script:MyInvocation.MyCommand.Path)`" -Phase $Phase -settingsFile `"$settingsFile`" -bldPath `"$bldPath`""
    $newProcess.Verb = 'runas'
    $newProcess.WorkingDirectory = "$PSScriptRoot"
    [Diagnostics.Process]::Start($newProcess)

    # close the script
    exit
}

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
    Start-Sleep 5
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
        Invoke-WebRequest -Uri $URI -OutFile "$savePath\$fileName" -MaximumRedirection 5 -EA Stop
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


# tests whether the object contains valid data.
# - Major and Minor must exist.
# - Major, Minor, [optional] Build, and [optional] Revision must be integers

function Test-Version
{
    param( $obj )

    $valNames = "Major", "Minor", "Build", "Revision"

    foreach ($n in $valNames)
    {
        if (($obj."$n" -or $obj."$n" -eq 0))
        {
            # is int?
            if ($obj."$n" -isnot [int])
            {
                Write-Error "$n is not an integer."
                return $false
            }
        }
        else 
        {
            if ($n -eq "Major" -or $n -eq "Minor")
            {
                Write-Error "Object does not contain a $n version."
                return $false
            }
        }
    }

    return $true
}

<#

    Accepts two version objects. Each object must contain the following integer ([int])properties:

    - Major
    - Minor

    These two integer properties are optional

    - Build
    - Revision

    Other properties are acceptable within the object. The function only looks for these four values.

    The RequiredVer is the well known version. For example, if testing whether an update to PowerShellGet is needed, 
    and the minimum version needed is 2.2.4.1, then the version object containing 2.2.4.1 would be the RequiredVer.
    
    The Version class is provided to create a valid Compare-Version object.
    
    Example 1:
    Create a Version object for a module of version 2.2.4.1

    $RequiredVer = [Version]::New(2,2,4,1)

    Example 2:
    Create a Version object for a module of version 2.0

    $RequiredVer = [Version]::New(2,0)


    The BaseVer contains the existing version number(s), from a command like "Get-Module -ListAvailable PowerShellGet".

    An array of versions is accepted for BaseVer, but not for RequiredVer. The highest version found in BaseVer 
    is used to compare against RequiredVer.

    The return values of this function are:
    
    $True  - Indicates that RequiredVer is higher than the largest BaseVer value. I.E. indicates that an update is needed.
    $False - Indicates that RequiredVer is less than or euqal to the largest BaseVer value. I.E. indicates that an update is not needed.
    $null  - Indicates an error occurred during version validation.

#>
function Compare-Version
{
    param(
        $RequiredVer,
        [array]$BaseVer
    )

    # make sure RequredVer is valid
    if (-NOT (Test-Version $RequiredVer))
    {
        Write-Error "RequiredVer is invalid:`n$($RequiredVer | Format-List * | Out-String)"
        return $null
    }

    # make sure BaseVer is valid
    $BaseVer | ForEach-Object {
        if (-NOT (Test-Version $_))
        {
            Write-Error "A BaseVer is invalid:`n$($_ | Format-List * | Out-String)"
            return $null
        }
    }

    # find the highest version number for BaseVer
    $testVer = ($BaseVer | Sort-Object -Property Major, Minor, Build, Revision -Descending)[0]
    
    # perform the comparison
    $valNames = "Major", "Minor", "Build", "Revision"

    <#
        Looping through Major, Minor, Build and Revision version levels here. In that order.

        At each step we make a > and then < comparison at the version level.

        If at any point the RequiredVer > testVer/BaseVer, then an update is needed because the matching testVer is smaller than required.

        If at any point the RequiredVer < testVer/BaseVer, then an update is not needed because the matching testVer is larger than required.

        If the loop completes without a return then the versions match and no update is needed.
    #>
    foreach ($n in $valNames)
    {
        # if $RequiredVer."$n" > $testVer."$n" an update is needed and we're done
        if ($RequiredVer."$n" -gt $testVer."$n")
        {
            return $true
        
        } 
        # if $RequiredVer."$n" < $testVer."$n" an update is not needed and we're done
        elseif ($RequiredVer."$n" -lt $testVer."$n")
        {
            return $false
        }
    }

    # if we get to this point then major, minor, build, and revision were all equal and $false is returned
    return $false
}

#endregion FUNCTIONS


## code in this region runs on every execution ##
#region COMMON

Write-Host "Getting things ready."

# restart elevated if not running as admin
[bool]$elevated = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-NOT $elevated)
{
    Restart-ScriptAsAdmin -Phase $Phase -settingsFile "$settingsFile" -bldPath "$bldPath"
}

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
                $settingsPath = "$scriptPath\settings.json"
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
        $settingsPath = "$scriptPath\settings.json"
    }

}

if ($settingsPath)
{
    #Write-Output "settingsPath: $settingsPath"
    try 
    {
        $setup = Get-Content $settingsPath -EA Stop | ConvertFrom-Json -EA Stop    
    }
    catch 
    {
        Write-Error "Could not parse settings.json file."
        exit
    }
    
}
else 
{
    Write-Error "Could not find settings.json file."
    exit
}

if (-NOT $setup)
{
    Write-Error "Failed to find a settings file. Please make sure settings.json is in the same dir as the script, or the raw file (i.e. Gist, pastebin, etc.) is available."
    exit
}


## enable autoLogon, unless disabled
# has autologon already been setup?
$isALFnd = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue

$noAutoLogon = [bool]($setup.AutoLogon)

if (-NOT $noAutoLogon -and (-NOT $isALFnd -or $isALFnd.AutoAdminLogon -eq 0))
{
    # detect Hyper-V VM and prompt
    $compy = Get-ComputerInfo -Property CsModel, CsManufacturer, BiosCaption
    if ($compy.CsModel -match "virtual" -and $compy.CsManufacturer -match "Microsoft" -and $compy.BiosCaption -match "Hyper-V")
    {
        Write-Host -ForegroundColor Red "A Hyper-V virtual machine (VM) was detected.`n"
        Write-Host -ForegroundColor Yellow "WARNING! AutoLogon does not work with remote desktop or enhanced session.`n"
        Write-Host -ForegroundColor Yellow "Select View from the vmconnect menu and uncheck Enhanced Session to allow AutoLogon to work. Or relaunch the VM console and close the resolution prompt to disable it."

        Write-Host "Press any key to continue..."
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
    
    # disable Ctrl+Alt+Del
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DisableCAD" -Value 1 -Force

    # set passwordless mode to 0
    $isPasswordless = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device" -Name "DevicePasswordLessBuildVersion" -EA SilentlyContinue

    if (-NOT $isPasswordless)
    {
        New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device" -Force
    }
    
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device" -Name "DevicePasswordLessBuildVersion" -Value 0 -Force

    # download autologon
    $sysAL = Get-WebFile -URI "http://live.sysinternals.com/Autologon.exe" -savePath $bldPath -fileName "Autologon.exe"

    if ($sysAL)
    {
        Write-Host -ForegroundColor Yellow "By entering a username and password into the AutoLogon prompt you are agreeing to the Microsoft Sysinternals EULA.`n`nhttps://docs.microsoft.com/en-us/sysinternals/license-terms"

        Push-Location $bldPath
        #.\Autologon.exe
        Start-Process Autologon.exe -WorkingDirectory $bldPath -Wait
        Pop-Location
    }
}


# make sure PowerShellGet is version 2.2.4.1
$psgVer = (Get-Module -ListAvailable PowerShellGet).Version

$updatePSG = Compare-Version -RequiredVer $psgMinVer -BaseVer $psgVer

if ($updatePSG)
{
    Write-Host "Updating PowerShellGet for PSGallery compatibility."
    Install-PackageProvider -Name NuGet -MinimumVersion "$($nugetMinVer.GetVersion())" -Force
    Install-Module -Name PowerShellGet -MinimumVersion "$($psgMinVer.GetVersion())" -Force -AllowClobber

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
            $exclusions = 'Microsoft.VCLibs.140.00','Microsoft.WindowsStore','Microsoft.DesktopAppInstaller','Microsoft.UI.XAML.2.7','Microsoft.MicrosoftEdge','Microsoft.MicrosoftEdge.Stable','Microsoft.WindowsNotepad'
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
                        Write-Host "Error: $_"
                        $Error[0] > c:\winget.txt
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

        # install graphics drivers
        # we don't install anything else because the drivers on WU are good enough for everything else.
        8
        {
            # what GPU(s) are installed
            [array]$gpu = Get-CimInstance win32_VideoController

            [array]$gpuFnd = $gpu.Name | ForEach-Object { $_ -match "^NVIDIA.*$" }

            # while it's possible to have both AMD and Nvidia GPU's installed at the same time... I'm not going to support that
            if ($gpuFnd -contains $true)
            {
                # is the file local
                $isNvidiaFnd = Get-Item "$script:scriptPath\Install-BuildNvidia.ps1" -EA SilentlyContinue

                if (-NOT $isNvidiaFnd)
                {
                    
                    # download Install-BuildNvidia.ps1
                    $bldNvUri = 'https://git.io/Jfhbm'
                    $bldNv = Get-WebFile -URI $bldNvUri -savePath $bldPath -fileName "Install-BuildNvidia.ps1"
                }
                else 
                {
                    [string]$bldNv = $isNvidiaFnd.FullName
                }

                if ((Test-Path $bldNv))
                {
                    # install the drivers
                    Push-Location $bldPath

                    if ($setup.gpuDriverOnly -eq "True")
                    {
                        $argument = @"
-noprofile -nologo -ExecutionPolicy Unrestricted -File .\Install-BuildNvidia.ps1 -bldPath "$bldPath" -driverOnly
"@
                    }
                    else 
                    {
                        $argument = @"
-noprofile -nologo -ExecutionPolicy Unrestricted -File .\Install-BuildNvidia.ps1 -bldPath "$bldPath"
"@    
                    }

                    

                    Write-Output "args: $argument"
                    Start-Process powershell -WorkingDirectory $bldPath -ArgumentList $argument -WindowStyle Normal -Wait

                    Pop-Location
                }
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

            # rerun autologon to give the user an option to disable it as a security best practice.
            $isALFnd = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue

            if (-NOT $noAutoLogon -and (-NOT $isALFnd -or $isALFnd.AutoAdminLogon -eq 1))
            {
                $sysAL = Get-Item "$bldPath\Autologon.exe" -EA SilentlyContinue

                if ($sysAL)
                {
                    Write-Host -ForegroundColor Yellow "`n`n`n`n`nOne last prompt!`n`n"
                    Write-Host -ForegroundColor Green "Windows AutoLogon is still enabled. This should be disabled for security reasons, but this is completely up to you."
                    Write-Host -ForegroundColor Green "`nPress Disable in the AutoLogon program to resume normal logon. If your PC is secure, and you really want autologon, simply close the prompt."

                    Push-Location $bldPath
                    #.\Autologon.exe
                    Start-Process Autologon.exe -WorkingDirectory $bldPath -Wait
                    Pop-Location
                }
            }

            # check for pending reboot
            $phase = New-Phase -restart $restart -Phase $Phase -bldPath $bldPath -settingsFile $settingsPath

            Write-Host "Work complete!"
            exit
        }
    }
}

