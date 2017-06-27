Import-Module WebAdministration

<#
    .SUMMARY
        DSC Resource to configure the IIS Web Management Service

    .DESCRIPTION
        A DSC Resource for configuring the IIS Web Management Service. 
#>
[DscResource()]
class cWebManagementService
{
    [DscProperty(Key)]
    [int]$EnableRemoteManagement = $null

    [DscProperty()]
    [string]$CertificateSubjectName = $null

    hidden static [string]$WMSvcRegistryRoot = 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server'
    hidden static [string]$WMSvcRegistryCertificateKey = 'SslCertificateHash'
    hidden static [string]$WMSvcEnableRemoteManagementKey = 'EnableRemoteManagement'

    hidden static [string]$MachineCertificateRoot = 'cert:\LocalMachine\My'
    hidden static [string]$SSLBindingPath = 'IIS:\SslBindings'

    hidden $RestartWebManagementService = $false

    <#
        .SYNOPSIS
            DSC Resource Get() - Populates as many fields as possible from querying the system
    #>
    [cWebManagementService] Get()
    {
        $this.GetCertificate()
        $this.GetEnableRemoteManagement()
        return $this
    }

    <#
        .SYNOPSIS
            DSC Resource Set() - Sets the values that are not null in the DSC resource properties
    #>
    [void] Set()
    {
        $this.RestartWebManagementService = $false

        if($null -ne $this.CertificateSubjectName) {
            $this.SetCertificate()
        }

        if($null -ne $this.EnableRemoteManagement) {
            $this.SetEnableRemoteManagement()
        }

        if ($this.RestartWebManagementService -eq $true) {
            Restart-Service 'WMSvc'
        }
    }

    <#
        .SYNOPSIS
            DSC Test verifies that all non-null resource properties are set as configured
    #>
    [bool] Test()
    {
        Write-Verbose '[cWebManagementService]Test()'
        if(
            ($null -ne $this.CertificateSubjectName) -and
            (-not $this.TestCertificateSubject())
        ) {
            return $false
        }

        if(
            ($null -ne $this.EnableRemoteManagement) -and 
            (-not $this.TestEnableRemoteManagement())
        ) {
            return $false
        }

        return $true
    }

    <#
        .SYNOPSIS
            Populated the DSC resource property EnableRemoteManagement

        .DESCRIPTION
            This function reads the registry key for configuring the remote management for Web Management Service
    #>
    hidden [void] GetEnableRemoteManagement()
    {
        Write-Verbose -Message '[cWebManagementService]::GetEnableRemoteManagement()'
        $this.EnableRemoteManagement = [cWebManagementService]::GetEnableRemoteManagementRegistryKey()
    }

    <#
        .SYNOPSIS
            Compares the current state of Web Management Service remote management to the configured setting

        .DESCRIPTION
            Reads the Web Management Service registry key and compares it to the configured value
    #>
    hidden [bool] TestEnableRemoteManagement()
    {
        Write-Verbose -Message '[cWebManagementService]::TestEnableRemoteManagement()'
        if (-not [cWebManagementService]::GetEnableRemoteManagementKeyPresent()) {
            Write-Verbose -Message (([cWebManagementService]::WMSvcEnableRemoteManagementKey) + ' not present')
            return $false
        }

        $currentValue = [cWebManagementService]::GetEnableRemoteManagementRegistryKey()
        Write-Verbose -Message (([cWebManagementService]::WMSvcEnableRemoteManagementKey) + ' = ' + $currentValue.ToString())
        Write-Verbose -Message ('DSC Resource Property EnableRemoteManagement = ' + $this.EnableRemoteManagement)

        return $currentValue -eq $this.EnableRemoteManagement
    }

    <#
        .SYNOPSIS
            Sets the Web Management Service Remote Management registry key
    #>
    hidden [void] SetEnableRemoteManagement()
    {
        [cWebManagementService]::SetEnableRemoteManagementRegistryKey($this.EnableRemoteManagement)
        $this.RestartWebManagementService = $true
    }

    <#
        .SYNOPSIS
            Gets the current Web Management Service certificate and sets the resource property CertificateSubjectName
    #>
    hidden [void] GetCertificate()
    {
        Write-Verbose -Message "GetCertificate()"
        [X509Certificate]$certificate = [cWebManagementService]::GetWMSvcCertificate()
        if($null -eq $certificate) {
            Write-Verbose -Message ('No certificate was properly configured and bound to the WMSvc service')
        } else {
            $this.CertificateSubjectName = $certificate.Subject
        }
    }

    <#
        .SYNOPSIS
            Configures the Web Management Service to use the certificate corresponding the subject name provided in the properties

        .DESCRIPTION
            This code doesn't just configure the certificate by forcing the binding as is popular on many
            web sites. Instead, it also attempts to properly configure the registry keys for WMSvc. It also
            aligns the system bindings for 'net http sslcerts' and the 'IIS:/sslcert' file system.
    #>
    hidden [void] SetCertificate()
    {
        # Don't bother configuring anything if there's nothing to configure
        if ($this.TestCertificateSubject()) {
            return
        }

        # Get the machine certificate object which corresponds to the property provided subject name
        [X509Certificate]$replacementCertificate = (Get-ChildItem -Path ([cWebManagementService]::MachineCertificateRoot)) |
            Where-Object { ($_.Subject).ToLower() -eq ($this.CompleteCertificateSubjectName().ToLower()) }

        # If the certificate is $null then we can't assign it.
        if ($null -eq $replacementCertificate) {
            Write-Error ('SetCertificate() - Could not find a machine certificate with the subject name [' + $this.CertificateSubjectName + ']')
            return
        }

        # Get the IIS:\sslcerts binding for tge certificate based on the configured IP and port in the WMSvc registry settings
        [string] $WMSvcBindingPath = (Join-Path -Path ([cWebManagementService]::SSLBindingPath) -ChildPath ([cWebManagementService]::GetWMSvcBinding('!')))
        
        # Get the existing binding for the WMSvc service and delete it if it already exists
        $existingBinding = Get-Item -Path $WMSvcBindingPath
        if ($null -eq $existingBinding) {
            Write-Information ("There doesn't appear to be an existing certificate binding registered for WMSvc")
        } else {
            # TODO : Verify that existing binding didn't return a list
            Remove-Item -Path $WMSvcbindingPath
            Write-Verbose -Message 'Removed existing certificate binding for WMSvc'
        }

        # Configure the Web Manager Service registry with the new certificate thumbprint
        [cWebManagementService]::SetWMSvcThumbprint($replacementCertificate.Thumbprint)

        # Create a new SSL binding for the replacement certificate to the IP and port for Web Management Service
        $replacementCertificate | New-Item -Path $WMSvcBindingPath
        Write-Verbose -Message 'Registered desired certificate to SSL binding for WMSvc'

        # Flag that the service should be restarted when all set operations are complete
        $this.RestartWebManagementService = $true
    }

    <#
        .SYNOPSIS
            Perform as thorough of a check as possible regarding certificate binding, registry and SSL settings for Web Management Service
        
        .DESCRIPTION
            Performs checks that should compensate for all manors of 'careless mistakes' with regard to common mistakes when configuring certificates.
            As more mistakes are discovered, more rules will be checked. This is not just checking for consistancy between DSC values and 
            configured settings. It is also intended to compensate for extreme cases of configuration drift.
    #>
    hidden [bool] TestCertificateSubject() 
    {
        Write-Verbose -Message '[cWebManagementService]::TestCertificateSubject()'

        # Check the Windows Registry for the Web Management Service certificate settings. If the thumbprint configured is no present or
        # valid, then return false
        [string]$wmsvcRegisteredThumbprint = [cWebManagementService]::GetWMSvcThumbprint()
        Write-Verbose -Message ('WMSvc is currently associated to certificate with thumbprint [' + $wmsvcRegisteredThumbprint + '] as per the Windows registry at [' + [cWebManagementService]::WMSvcRegistryRoot + ']')
        if (-not ([cWebManagementService]::ValidateThumbprint($wmsvcRegisteredThumbprint))) {
            Write-Verbose -Message ('There is no certificate thumbprint registered in the WMSvc registry : ' + [cWebManagementService]::WMSVCRegistryRoot)
            return $false
        }

        # Get handle to the certificate signified by thumbprint provided above. If the listed thumbprint does not correspond to a
        # certificate in the local machine certificate store, then return false
        Write-Verbose -Message ('Getting certificate [' + $wmsvcRegisteredThumbprint + ']')
        [X509Certificate]$wmsvrRegistered = [cWebManagementService]::GetCertificate($wmsvcRegisteredThumbprint)
        if ($null -eq $wmsvrRegistered) {
            Write-Verbose -Message ('The WMSvc certificate thumbprint [' + $wmsvcRegisteredThumbprint + '] found in the registry does not exist in the local machine certificate store')
            return $false
        }

        # Run 'net http show sslcert' and find the thumbprint bound to the IP and port configured for Web Management Service in the Windows
        # registry. If the binding isn't present, the thumbprint is null or invalid, then return false.
        [string]$actualCertificateThumbprint = [cWebManagementService]::GetWMSvcActiveThumbprint()
        Write-Verbose -Message ('''netsh http show sslcert'' shows that the certificate registered to the IP and Port for WMsvc is [' + $actualCertificateThumbprint + ']')
        if (-not ([cWebManagementService]::ValidateThumbprint($actualCertificateThumbprint))) {
            Write-Verbose -Message ("There doesn't appear to be a binding registered for the WMSvc service (as per netsh http show sslcert)")
            return $false
        }

        # Get the certificate corresponding to the thumbprint above from the local machine certificate store. If it's not present
        # return false.
        Write-Verbose -Message ('Getting certificate [' + $actualCertificateThumbprint + ']')
        [X509Certificate]$actualCertificate = [cWebManagementService]::GetCertificate($actualCertificateThumbprint)
        if ($null -eq $actualCertificate) {
            Write-Verbose -Message ("Although there is a binding for WMSvc found in 'netsh http show sslcert', the certificate is not found in the local machine certificate store")
            return $false
        }

        # If the thumbprints configured in the regitry settings for the Web Management Service and from 'net http show sslcert' do not
        # match, then return false.
        if ($wmsvcRegisteredThumbprint -ne $actualCertificateThumbprint) {
            Write-Verbose -Message ("The registry entry for WMSvc references the certificate with the thumbprint [" + $wmsvcRegisteredThumbprint + "] but 'netsh http show sslcert' references a certificate with the thumbprint [" + $actualCertificateThumbprint + "]")
            return $false
        }

        # If the certificate bound to the Web Management Service does not have the same subject as requested by the DSC resource properties, 
        # then return false.
        if (($actualCertificate.Subject.ToLower()) -ne ($this.CompleteCertificateSubjectName().ToLower())) {
            Write-Verbose -Message ("Operational certificate subject [" + $actualCertificate.Subject + "] does not match desired certificate subject [" + $this.CertificateSubjectName + "]")
            return $false
        }

        # TODO : Handle HKLM:\SOFTWARE\Microsoft\WebManagement\Server\SelfSignedSslCertificateHash?

        return $true
    }

    <#
        .SYNOPSIS
            Returns the $this.CertificateSubjectName with a preceeding 'CN=' if not present
    #>
    hidden [string] CompleteCertificateSubjectName()
    {
        # TODO : Add certificate subject name validation

        if($this.CertificateSubjectName.ToLower().StartsWith('cn=')) {
            return $this.CertificateSubjectName
        }
        return 'CN=' + $this.CertificateSubjectName
    }

    <#
        .SYNOPSIS
            Returns true if the input string is at least 32 characters and hexadecimal
    #>
    hidden static [bool] ValidateThumbprint([string]$Thumbprint)
    {
        return (
            ($null -ne $Thumbprint) -and
            ($Thumbprint -ne '') -and
            ($Thumbprint.Length -ge 32) -and
            (-not ($Thumbprint -match '[^A-Fa-f0-9]'))
            )
    }

    <#
        .SYNOPSIS
            Returns the certificate for the given thumbprint if it is present, otherwise return $null
    #>
    hidden static [X509Certificate]GetCertificate([string]$Thumbprint)
    {
        Write-Verbose -Message ('GetCertificate(' + $Thumbprint + ') - ' + (Join-Path -Path ([cWebManagementService]::MachineCertificateRoot) -ChildPath $Thumbprint))
        return Get-ChildItem -Path (Join-Path -Path ([cWebManagementService]::MachineCertificateRoot) -ChildPath $Thumbprint) -ErrorAction SilentlyContinue
    }

    <#
        .SYNOPSIS
            Returns the X.509 Certificate from the local machine store for the certificate configured in the registry for the WMSvc
    #>
    hidden static [X509Certificate]GetWMSvcCertificate()
    {
        [string]$CertificateThumbprint = [cWebManagementService]::GetWMSvcThumbprint()
        if ([cWebManagementService]::IsNullOrEmpty($CertificateThumbprint)) {
            return $null
        }

        return [cWebManagementService]::GetCertificate($CertificateThumbprint)
    }

    <#
        .SYNOPSIS 
            Returns the certificate thumbprint which is associated in the registry for WMSvc
    #>
    hidden static [string] GetWMSvcThumbprint()
    {
        [byte[]]$certificateHashPropertyValue = $null
        try {
            $certificateHashPropertyValue = Get-ItemPropertyValue -Path ([cWebManagementService]::WMSVCRegistryRoot) -Name 'SslCertificateHash'
        } catch {
            Write-Verbose -Message ('Exception caught ' + $_.Exception.Message)
            return $null
        }

        return [cWebManagementService]::BytesToHexString($certificateHashPropertyValue)
    }

    <#
        .SYNOPSIS
            Converts a thumbprint from a hex string to a byte array and then sets the registry key for the Web Service Manager
    #>
    hidden static [void] SetWMSvcThumbprint([string]$Thumbprint)
    {
        [byte[]] $byteArrayThumbprint = [cWebManagementService]::ToByteArray($Thumbprint)
        [cWebManagementService]::SetWMSvcThumbprint($byteArrayThumbprint)
    }

    <#
        .SYNOPSIS
            Sets the Web Service Manager registry key for the certificate thumbprint

        .NOTES
            If for some reason the key has been changed from a byte array to something else
            this function will delete the existing key and create a new one.

            This code is not intended to generate the original key and if there's no key 
            present at the start of the call, then it will likely raise and exception
    #>
    hidden static [void] SetWMSvcThumbprint([byte[]]$Thumbprint)
    {
        $previousValue = Get-ItemPropertyValue `
            -Path ([cWebManagementService]::WMSvcRegistryRoot) `
            -Name ([cWebManagementService]::WMSvcRegistryCertificateKey)

        if ($null -eq $previousValue) {
            # In case this function is being called when there isn't already a registry key,
            # simply return. This is not a proper case to encounter since the key should
            # be present if Web Management Service is present. If it's not present, then
            # this function likely should not have been called.
            return
        } elseif ($previousValue.GetType() -eq $Thumbprint) {
            Set-ItemProperty `
                -Path ([cWebManagementService]::WMSvcRegistryRoot) `
                -Name ([cWebManagementService]::WMSvcRegistryCertificateKey) `
                -Value $Thumbprint `
        } else {
            Remove-ItemProperty `
                -Path ([cWebManagementService]::WMSvcRegistryRoot) `
                -Name ([cWebManagementService]::WMSvcRegistryCertificateKey)

            New-ItemProperty `
                -Path ([cWebManagementService]::WMSvcRegistryRoot) `
                -Name ([cWebManagementService]::WMSvcRegistryCertificateKey) `
                -Value $Thumbprint
        }
    }

    <#
        .SYNOPSIS
            Call 'netsh http show sslcert' and return the active certificate thumbprint for the Web Management Service
    #>
    hidden static [string] GetWMSvcActiveThumbprint()
    {
        # Read the registry and assemble the IP address and port configured for the Web Management Service as a string
        # compatible with the output format of 'netsh'
        [string] $ipPortBinding = [cWebManagementService]::GetWMSvcBinding(':')

        # Return $null if the registry keys are empty or not suitable for looking up the binding information
        if([cWebManagementService]::IsNullOrEmpty($ipPortBinding)) {
            Write-Verbose -Message 'Could not obtain the registry settings for IP Address and port for binding the Web Management Service'
            return $null
        }

        # Execute 'netsh' to get the ssl certificae for the binding resolved above reference.
        # Limit the returned information to strictly the line of text containing the configuration of
        # the certificate hash.
        #   TODO : Use process object with credentials?
        [string]$output = 
            (netsh http show sslcert ipport=$ipPortBinding | 
                Where-Object { $_ -like '*Certificate Hash*' })

        # If the output of 'netsh' is empty or null, the return as there is nothing more to do here.
        if([cWebManagementService]::IsNullOrEmpty($output)) {
            Write-Verbose -Message ('No value returned for binding ' + $ipPortBinding + " from 'netsh http show sslcert")
            return $null
        }

        # Break the line which is formated as 'name : value' into parts using ' : ' as the split reference
        [string[]] $parts = [regex]::Split($output, '[ \t]+\:[ \t]+')
        if ($parts.Count -ne 2) {
            Write-Warning -Message ('Encountered line with more or less than 2 parts`n' + $output)
            return $null
        }

        # Trim the result of the second part and use this as the thumbprint
        [string]$Thumbprint = $parts[1].Trim()    

        # Validate the formation of the thumbprint before returning it
        if (-not ([cWebManagementService]::ValidateThumbprint($Thumbprint))) {
            Write-Verbose -Message ('Thumbprint returned from netsh [' + $Thumbprint + '] is invalid')
            return $null
        }

        return $Thumbprint
    }

    <#
        .SYNOPSIS
            Helper function : Return true if the given string is null or empty
    #>
    hidden static [bool] IsNullOrEmpty([string]$input)
    {
        return ($null -eq $input) -or ($input.Trim() -eq '')
    }

    <#
        .SYNOPSIS
            Convert an array of bytes into a hexidecimal string
    #>
    hidden static [string] BytesToHexString([byte[]]$input)
    {
        [string]$result = ''
        foreach($value in $input) {
            $result += '{0:X2}' -f $value
        }
        return $result
    }

    <#
        .SYNOPSIS
            Convert a hexidecimal numeric string into a byte array
    #>
    hidden static [byte[]] ToByteArray([string]$input)
    {
        if (-not [cWebManagementService]::ValidateThumbprint($input)) {
            throw [System.ArgumentException]::new('Invalid thumbprint format', '$input')
        }

        [byte[]]$result = @([Convert]::ToByte([System.Convert]::ToInt32($input.substring(0,2), 16)))
        for($i=2; $i -lt $input.Length; $i+=2) {
            $part = $input.substring($i,2)
            $result += [Convert]::ToByte($part, 16)
        }

        return $result
    }

    <#
        .SYNOPSIS
            Using the Web Management Service registry settings, return a string to represent the IP address and port binding 

        .NOTES
            <li>So far there has been nothing done to test against IPv6</li>
            <li>If the IP address value is *, then only IPv4 0.0.0.0 is returned. It may be better to return a list
            of IPv4 and IPv6 addresses included.</li>
    #>
    hidden static [string] GetWMSvcBinding([string]$Separator)
    {
        [string]$ipAddress = Get-ItemPropertyValue -Path ([cWebManagementService]::WMSvcRegistryRoot) -Name 'IPAddress'
        [int]$port = Get-ItemPropertyValue -Path([cWebManagementService]::WMSvcRegistryRoot) -Name 'Port'

        if ($ipAddress -eq '*') {
            $ipAddress = '0.0.0.0'
        }

        return ($ipAddress + $Separator + $port.ToString())
    }

    <#
        .SYNOPSIS
            Reads the Web Manager Service Remote Management registry key and returns 1 for true and 0 for false
    #>
    hidden static [int] GetEnableRemoteManagementRegistryKey()
    {
        [int]$value = Get-ItemPropertyValue -Path ([cWebManagementService]::WMSvcRegistryRoot) -Name ([cWebManagementService]::WMSvcEnableRemoteManagementKey)
        if ($null -eq $value) {
            Write-Verbose -Message ("The Enable Remote Management key in the registry for WMSvc is not present. Is the service installed?")
            return $false
        }
        return ($value)
    }

    <#
        .SYNOPSIS
            Returns true if the Remote Management key for Web Management Server is present in the registry
    #>
    hidden static [bool] GetEnableRemoteManagementKeyPresent()
    {
        $property = Get-ItemProperty -Path ([cWebManagementService]::WMSvcRegistryRoot) -Name ([cWebManagementService]::WMSvcEnableRemoteManagementKey)
        return ($null -ne $property)
    }

    <#
        .SYNOPSIS
            Sets the remote management key for the Web Management Server
    #>
    hidden static [void] SetEnableRemoteManagementRegistryKey([int]$Enabled)
    {
        # If the key is not present, then report it. This is probably something dangerous a the set item property below will likely raise
        # and exception if the feature is not yet installed.
        if (-not [cWebManagementService]::GetEnableRemoteManagementKeyPresent()) {
            # Throw?
            Write-Verbose -Message ('The Enable Remote Management key in the registry does not appear to be present. Is the feature installed?')
        }

        Set-ItemProperty -Path ([cWebManagementService]::WMSvcRegistryRoot) -Name ([cWebManagementService]::WMSvcEnableRemoteManagementKey) -Value $Enabled
    }
}
