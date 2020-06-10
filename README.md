# Start-Build
Performs basic setup for a new Windows 10 installation. Setup is performed in phases with auto-reboots between phases, as needed.

A settings.json file is required. The settings file contains details about how the system should be setup.

# settings.json

The [example-settings.json](https://raw.githubusercontent.com/Jammrock/Start-Build/master/example-settings.json) file can be used as a template for creating a custom build file.

The settings file can be on the local file system or a URL. The system needs Intranet/Internet access to reach a remote settings file. The URL should point to the RAW settings file. For example, you cannot use this URL as the settings are embedded within a web page.

https://github.com/Jammrock/Start-Build/blob/master/example-settings.json

You can use a URL like this one since the page content is the raw settings file content.

https://raw.githubusercontent.com/Jammrock/Start-Build/master/example-settings.json


### computerName

Sets the computer name, also known as the hostname, of the computer to the value of this setting.

### timeZone

Changes the time zone for the system clock. Use the appropriate value from the "Name of Time Zone" column in [Microsoft KB973627]( https://support.microsoft.com/en-us/help/973627/microsoft-time-zone-index-values) as the timeZone value.

Or use PowerShell:

`Get-TimeZone -ListAvailable`

### userEnv

Adds user environment variables to the logged on user running the script. Each addition must be formatted using the following template. Multiple variables should be separated by commas (,) per JSON file format rules.

`        
"userEnv": [
        {
            "name": "",
            "value": ""
        },
        {
            "name": "",
            "value": ""
        }
]
`

#### *name*

This is the variable name. Example: PATH

Entries to PATH (case insensitive) are appended to the existing path. All additions to PATH can be in a single entry or multiple entries.

All of ther variable names are added, or overwrites the existing value.

#### *value*

The variable value.

### systemEnv

Same concept as as userEnv, except variables are added to the system level environment variables. The same settings rules apply for name and value formatting.

In addition to entries being appended to PATH, entries for PATHEXT and PSModulePath are appended as well. All other entries add the variable or overwrites an existing variable.

### pwshModules

A list of PowerShell modules to install. This is only tested with [PSGallery](https://www.powershellgallery.com/) based modules. In theory, this would work with any package provider that PowerShellGet and NuGet can find.

### winCapabilities

This installs Optional Features, also known as features on demand (FOD). The optional features are primarily languages, RSAT tools, OpenSSH client/server, etc.

The feature name used for winCapabilities should be the feature name up to the tildas(\~). The build script does a wildcard search to complete the feature name. For example, use OpenSSH.Client instead of OpenSSH.Client\~\~\~\~0.0.1.0

The official list of FOD packages are [here](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod).

You can also get a list of FOD name using this command in PowerShell:

`Get-WindowsCapability -Online`

### winFeaturesEnable

This installs Windows Features; such as, Hyper-V, Windows Sandbox, Windows Subsystem for Linux (WSL), and so on. Feature names must be an exact match!

There is no official list of feature names that I am aware. The list of feature names can be retrieved via PowerShell from an existing system.

`Get-WindowsOptionalFeature -Online`

### winFeaturesDisable

Removes Windows Features. Basically does the opposite of winFeaturesEnable. This can be used for security hardening to make sure things like SMB1 and PowerShell 2 are not installed.

### wingetApps

This is where the most fun happens. [Winget](https://github.com/microsoft/winget-cli) is a new command line based application packet provider built by Microsoft, based on similar projects like AppGet.

There are hundreds of applications available through winget. You don't need winget to list the available packages either. Steps on how to use wingetApps are below.

1. Use the exact winget ID. 
   - This is required since there can be duplicates is package names, such as Microsoft.Edge and Microsoft.EdgeBeta.
2. The master list of packages is here:

https://github.com/microsoft/winget-pkgs/tree/master/manifests

3. Note that some manifests are under a vendor dir. For example, click on Microsoft in the list and there is a list of Microsoft manifests.
4. Select the yaml file of the package you want to installed.
5. Copy the full ID into wingetApps, keeping the JSON formatting of the example.


## Instructions

\<coming soon\>

1. Open an elevated PowerShell (Run as administrator).

2. Run this command:

`curl 'https://raw.githubusercontent.com/Jammrock/Start-Build/master/build.ps1' -UseBasicParsing | iex`

3. Enter the URL or path to settings.json.

4. Chill... except for the parts where you need to logon after reboots.
