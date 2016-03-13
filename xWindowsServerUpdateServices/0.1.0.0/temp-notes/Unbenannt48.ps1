# The Get-TargetResource cmdlet.
function Set-TargetResource
{
    [OutputType([Hashtable])]
    param
    (
        # Name that clients use to communicate with our WSUS Server
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$WsusFQDN,
            
        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server   
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]                         
        [string]$CertificateThumbPrint,

        # 
        [Uint32]$Port = $( if($CertificateThumbPrint) { 8350 } else { 8351 } ),

        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",

        [Parameter()]
        [ValidateNotNullOrEmpty()]                         
        [string]$ProxyServer,

        [Parameter()]
        [ValidateNotNullOrEmpty()]                         
        [integer]$ProxyPort,

        $ProxyCredential,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]                         
        [string]$ContentDirectoryPath
    )

    if ($Ensure -eq 'Absent')
    {

    }
    if ($Ensure -eq 'Present')
    {
        if (TestSystemRequirements @PSBoundParameters)
        {
            if($DisablePreFlightChecks -ne $true)
            {
                StartPreFlightChecks
            }
            
            Add-WindowsFeature -Name UpdateServices -Restart:$false -IncludeManagementTools:$true
            #Install-WindowsFeature -Name UpdateServices,Windows-Internal-Database

            $WsusToolsDir = "$env:ProgramFiles\Update Services\Tools"
            & "$WsusToolsDir\wsusutil.exe" postinstall CONTENT_DIR="$WsusContentDirectoryPath"

            if($ProxyServer)
            {
                & "$WsusToolsDir\wsusutil.exe" ConfigureSSLProxy $ProxyServer $ProxyPort –enable  
            }
            else
            {
                # explicitly disable proxy if not specified
                & "$WsusToolsDir\wsusutil.exe" ConfigureSSLProxy $ProxyServer $ProxyPort –enable
            }

            if($Certificate)
            {
                Write-Verbose 'Configuring IIS Certificate Binding'



                $VirtualRoots = @('ApiRemoting30', 'ClientWebService', 'DSSAuthWebService', 'ServerSyncWebService', 'SimpleAuthWebService')
                Write-Verbose "Starting Virtual Host Encryption for $virtual"

                foreach($VirtualRoot in $VirtualRoots)
                {
                    Write-Verbose "Enforcing SSL encryption on the following virtual root: $VirtualRoot"
                    Set-WebConfigurationProperty -Filter //security/access -name sslflags -Value "Ssl" -PSPath IIS:\ -Location "WSUS Administration/VirtualRoot"
                }

                Write-Verbose 'Configuring IIS Certificate Binding'
                & "$WsusToolsDir\wsusutil.exe" configuressl $WsusFQDN
            }

                





            }
            

        }
    
    }
}


Function TestSystemRequirements
{
    [CmdletBinding()]
    [OutputType([boolean])]
    param(
        [string] $ContentDirectoryPath,
        [string] $ProxyServer,
        [int]    $ProxyPort,
        [string] $CertificateThumbPrint,

        [Parameter(ValueFromRemainingArguments)] $UnboundParameters
    )
    
    # Run some checks to tell us if we're doing anything stupid

    #region WarnIfContentDirOnSystemDrive
    if (-not (Test-Path $ContentDirectoryPath)) 
    {
        Write-Verbose "WSUS Content directory [$ContentDirectoryPath] doesn't exist. Creating..."
        New-Item -ItemType Directory -Path $ContentDirectoryPath -Force -ErrorAction SilentlyContinue | Out-Null
    }

    Write-Verbose "Testing if `$ContentDirectoryPath points to the system drive $env:SystemDrive"
    if ((Resolve-Path $ContentDirectoryPath).Drive.ToString() -eq ($env:SystemDrive)[0])
    {
        Write-Warning "Please consider changing the ContentDirectoryPath to a location outside the OS drive..."
    }
    #endregion

    #region WarnIfServerIsDC
    Write-Verbose "Testing if computer is a Domain Controller"
    if ((Get-WindowsFeature -Name AD-Domain-Services | Where Installed).count -eq 1)
    {
        Write-Warning "The database server must not be configured on a domain controller."
        $IsCompliant = $false     
    }
    #endregion

    #region WarnIfServerisRDSHost
    Write-Verbose "Testing if computer is a Domain Controller"
    if ((Get-WindowsFeature -Name Remote-Desktop-Services | Where Installed).count -eq 1)
    {
        Write-Warning "Remote Desktop Services role must not be installed on the computer where the WSUS Server role is installed." 
        $IsCompliant = $false    
    }
    #endregion

    #region WarnIfProxyServerIncomplete
    if ($ProxyServer -xor $ProxyPort)
    {
        Write-Warning "If you require a proxy you must define ProxyServer and ProxyPort."
        $IsCompliant = $false
    }
    elseif($ProxyCredential)
    {
        Write-Verbose "ProxyCredential specified - accessing http://windowsupdate.microsoft.com through proxy..."
        $Response = Invoke-WebRequest -URI 'http://windowsupdate.microsoft.com' -Proxy "$ProxyServer`:$ProxyPort" -ProxyCredential $ProxyCredential -ErrorAction  SilentlyContinue
        if($Response) {}
    }
    #endregion


    if (-not ($IsCompliant))
    {
        throw "ERROR: Server does not meet the WSUS requirements"

    }
    else 
    {
        return $true
    }

}

Function StartPreFlightChecks
{
    # Outbound Connections
# https://technet.microsoft.com/en-us/library/hh852346.aspx
<#
http://windowsupdate.microsoft.com
http://*.windowsupdate.microsoft.com
https://*.windowsupdate.microsoft.com
http://*.update.microsoft.com
https://*.update.microsoft.com
http://*.windowsupdate.com
http://download.windowsupdate.com
http://download.microsoft.com
http://*.download.windowsupdate.com
http://wustat.windows.com
http://ntservicepack.microsoft.com
http://go.microsoft.com
#>
}


# Get-Volume | ? { $_.DriveType -eq "Fixed" -and -not($_.FileSystem)}            
# Add-WindowsFeature -Name UpdateServices  -Restart:$false -IncludeManagementTools:$true
# http://blogs.technet.com/b/sus/archive/2012/03/20/installing-wsus-on-windows-server-8-beta-using-powershell.aspx            
#& 'C:\Program Files\Update Services\Tools\WsusUtil.exe' --% postinstall CONTENT_DIR=D:\WSUS.Content 
# get-wsusserver muss nach postinstall erfolgen
Function Get-TargetResource2
{
    $webSite = Get-Website -Name $EndpointName

    if ($webSite)
    {
            $Ensure = 'Present'
            $AcceptSelfSignedCertificates = $false
                
            # Get Full Path for Web.config file    
            $webConfigFullPath = Join-Path $website.physicalPath "web.config"

            # Get module and configuration path
            $modulePath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ModulePath"
            $ConfigurationPath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ConfigurationPath"
            $RegistrationKeyPath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "RegistrationKeyPath"

            $UrlPrefix = $website.bindings.Collection[0].protocol + "://"

            $fqdn = $env:COMPUTERNAME
            if ($env:USERDNSDOMAIN)
            {
                $fqdn = $env:COMPUTERNAME + "." + $env:USERDNSDOMAIN
            }

            $iisPort = $website.bindings.Collection[0].bindingInformation.Split(":")[1]
                        
            $svcFileName = (Get-ChildItem -Path $website.physicalPath -Filter "*.svc").Name

            $serverUrl = $UrlPrefix + $fqdn + ":" + $iisPort + "/" + $svcFileName

            $webBinding = Get-WebBinding -Name $EndpointName

            # This is the 64 bit module
            $certNativeModule = Get-WebConfigModulesSetting -WebConfigFullPath $webConfigFullPath -ModuleName "IISSelfSignedCertModule" 
            if($certNativeModule)
            {
                $AcceptSelfSignedCertificates = $true
            }           

            # This is the 32 bit module
            $certNativeModule = Get-WebConfigModulesSetting -WebConfigFullPath $webConfigFullPath -ModuleName "IISSelfSignedCertModule(32bit)" 
            if($certNativeModule)
            {
                $AcceptSelfSignedCertificates = $true
            }           
        }
    else
    {
        $Ensure = 'Absent'
    }

    @{
        EndpointName                    = $EndpointName
        CertificateThumbPrint           = if($CertificateThumbPrint -eq 'AllowUnencryptedTraffic'){$CertificateThumbPrint} else {(Get-WebBinding -Name $EndpointName).CertificateHash}
        Port                            = $iisPort
        PhysicalPath                    = $website.physicalPath
        State                           = $webSite.state
        ModulePath                      = $modulePath
        ConfigurationPath               = $ConfigurationPath
        DSCServerUrl                    = $serverUrl
        Ensure                          = $Ensure
        RegistrationKeyPath             = $RegistrationKeyPath
        AcceptSelfSignedCertificates    = $AcceptSelfSignedCertificates
    }
}


function Set-TargetResourceRef
{
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName,

        # Port number of the DSC Pull Server IIS Endpoint
        [Uint32]$Port = $( if ($IsComplianceServer) { 7070 } else { 8080 } ),

        # Physical path for the IIS Endpoint on the machine (usually under inetpub)                            
        [string]$PhysicalPath = "$env:SystemDrive\inetpub\$EndpointName",

        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]                            
        [string]$CertificateThumbPrint,

        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",
    
        # Location on the disk where the Modules are stored            
        [string]$ModulePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules",

        # Location on the disk where the Configuration is stored                    
        [string]$ConfigurationPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration",

        # Is the endpoint for a DSC Compliance Server
        [boolean]$IsComplianceServer,

        # Location on the disk where the RegistrationKeys file is stored                    
        [string]$RegistrationKeyPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService",

        # Add the IISSelfSignedCertModule native module to prevent self-signed certs being rejected.
        [boolean]$AcceptSelfSignedCertificates
    )

    # Initialize with default values     
    $script:appCmd = "$env:windir\system32\inetsrv\appcmd.exe"
   
    $pathPullServer = "$pshome\modules\PSDesiredStateConfiguration\PullServer"
    $rootDataPath ="$env:PROGRAMFILES\WindowsPowerShell\DscService"
    $jet4provider = "System.Data.OleDb"
    $jet4database = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=$env:PROGRAMFILES\WindowsPowerShell\DscService\Devices.mdb;"
    $eseprovider = "ESENT";
    $esedatabase = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Devices.edb";

    $culture = Get-Culture
    $language = $culture.TwoLetterISOLanguageName
    # the two letter iso languagename is not actually implemented in the source path, it's always 'en'
    if (-not (Test-Path $pathPullServer\$language\Microsoft.Powershell.DesiredStateConfiguration.Service.Resources.dll)) {
        $language = 'en'
    }

    $os = [System.Environment]::OSVersion.Version
    $IsBlue = $false;
    if($os.Major -eq 6 -and $os.Minor -eq 3)
    {
        $IsBlue = $true;
    }

    # Use Pull Server values for defaults
    $webConfigFileName = "$pathPullServer\PSDSCPullServer.config"
    $svcFileName = "$pathPullServer\PSDSCPullServer.svc"
    $pswsMofFileName = "$pathPullServer\PSDSCPullServer.mof"
    $pswsDispatchFileName = "$pathPullServer\PSDSCPullServer.xml"

    # Update only if Compliance Server install is requested
    if ($IsComplianceServer)
    {
        $webConfigFileName = "$pathPullServer\PSDSCComplianceServer.config"
        $svcFileName = "$pathPullServer\PSDSCComplianceServer.svc"
        $pswsMofFileName = "$pathPullServer\PSDSCComplianceServer.mof"
        $pswsDispatchFileName = "$pathPullServer\PSDSCComplianceServer.xml"
    }

    # check for the existance of Windows authentication, this is needed for the Compliance Server    
    if(($Ensure -eq "Present"))
    {
        Write-Verbose "Check IIS Windows Authentication"
        # only important if Present, Get-WindowsFeature works under 2008 R2 and newer
        if ((Get-WindowsFeature -name Web-Windows-Auth | Where Installed).count -eq 0)
        {
            # enable the feature     
            # Checking for Windows Server 2008 R2:
            if([Environment]::OSVersion.Version.ToString().StartsWith("6.1."))
            {
                Add-WindowsFeature -Name Web-Windows-Auth
            }
            else
            {
                Install-WindowsFeature -Name Web-Windows-Auth
            }                       
        }      
    }

    # ============ Absent block to remove existing site =========
    if(($Ensure -eq "Absent"))
    {
         $website = Get-Website -Name $EndpointName
         if($website -ne $null)
         {
            # there is a web site, but there shouldn't be one
            Write-Verbose "Removing web site $EndpointName"
            PSWSIISEndpoint\Remove-PSWSEndpoint -SiteName $EndpointName
         }

         # we are done here, all stuff below is for 'Present'
         return 
    }
    # ===========================================================

                
    Write-Verbose "Create the IIS endpoint"    
    PSWSIISEndpoint\New-PSWSEndpoint -site $EndpointName `
                     -path $PhysicalPath `
                     -cfgfile $webConfigFileName `
                     -port $Port `
                     -applicationPoolIdentityType LocalSystem `
                     -app $EndpointName `
                     -svc $svcFileName `
                     -mof $pswsMofFileName `
                     -dispatch $pswsDispatchFileName `
                     -asax "$pathPullServer\Global.asax" `
                     -dependentBinaries  "$pathPullServer\Microsoft.Powershell.DesiredStateConfiguration.Service.dll" `
                     -language $language `
                     -dependentMUIFiles  "$pathPullServer\$language\Microsoft.Powershell.DesiredStateConfiguration.Service.Resources.dll" `
                     -certificateThumbPrint $CertificateThumbPrint `
                     -EnableFirewallException $true -Verbose

    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "anonymous"
    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "basic"
    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "windows"
        

    if ($IsBlue)
    {
        Write-Verbose "Set values into the web.config that define the repository for BLUE OS"
        #PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $eseprovider
        #PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr"-value $esedatabase
        #ESE database is not present in current build
        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $jet4provider
        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr" -value $jet4database
        Set-BindingRedirectSettingInWebConfig -path $PhysicalPath
    }
    else
    {
        Write-Verbose "Set values into the web.config that define the repository for non-BLUE Downlevel OS"
        $repository = Join-Path "$rootDataPath" "Devices.mdb"
        Copy-Item "$pathPullServer\Devices.mdb" $repository -Force

        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $jet4provider
        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr" -value $jet4database
    }

    if ($IsComplianceServer)
    {    
        Write-Verbose "Compliance Server: Set values into the web.config that indicate this is the admin endpoint"
        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "AdminEndPoint" -value "true"
    }
    else
    {
        Write-Verbose "Pull Server: Set values into the web.config that indicate the location of repository, configuration, modules"

        # Create the application data directory calculated above        
        $null = New-Item -path $rootDataPath -itemType "directory" -Force
                
        $repository = Join-Path $rootDataPath "Devices.mdb"
        Copy-Item "$pathPullServer\Devices.mdb" $repository -Force

        $null = New-Item -path "$ConfigurationPath" -itemType "directory" -Force

        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "ConfigurationPath" -value $ConfigurationPath

        $null = New-Item -path "$ModulePath" -itemType "directory" -Force

        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "ModulePath" -value $ModulePath

        $null = New-Item -path "$RegistrationKeyPath" -itemType "directory" -Force

        PSWSIISEndpoint\Set-AppSettingsInWebconfig -path $PhysicalPath -key "RegistrationKeyPath" -value $RegistrationKeyPath

        if($AcceptSelfSignedCertificates)
        {
            Copy-Item "$pathPullServer\IISSelfSignedCertModule.dll" $env:windir\System32\inetsrv -Force
            Copy-Item "$env:windir\SysWOW64\WindowsPowerShell\v1.0\Modules\PSDesiredStateConfiguration\PullServer\IISSelfSignedCertModule.dll" $env:windir\SysWOW64\inetsrv -Force

            & $script:appCmd install module /name:"IISSelfSignedCertModule(32bit)" /image:$env:windir\SysWOW64\inetsrv\IISSelfSignedCertModule.dll /add:false /lock:false
            & $script:appCmd add module /name:"IISSelfSignedCertModule(32bit)"  /app.name:"PSDSCPullServer/"
        }
        else
        {
            if($AcceptSelfSignedCertificates -and ($AcceptSelfSignedCertificates -eq $false))
            {
                & $script:appCmd delete module /name:"IISSelfSignedCertModule(32bit)"  /app.name:"PSDSCPullServer/"
            }
        }
    }
}

# xWsusService

Function xWsusConfiguration
{
    param
    (
        #[boolean]SynchronizeAutomatically
        #[...]SynchronizeAutomaticallyTimeOfDay
        #[integer]NumberOfSynchronizationsPerDay = 1
        #EnabledUpdateLanguages (All, en, de, etc.) #https://msdn.microsoft.com/en-us/library/microsoft.updateservices.administration.iupdateserverconfiguration.supportedupdatelanguages(v=vs.85).aspx
    )
}


# RemoteSQLServerInstance

# 
# RunAsCredential
# PsDscRunAsCredential


