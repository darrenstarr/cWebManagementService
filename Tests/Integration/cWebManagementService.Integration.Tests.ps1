#requires -Version 5.0 -Modules Pester

$script:DSCModuleName = 'cWebManagementService'
$script:DSCResourceName = 'cWebManagementService'

#region Header

$ModuleRoot = Split-Path -Path $Script:MyInvocation.MyCommand.Path -Parent | Split-Path -Parent | Split-Path -Parent

if (
    (-not (Test-Path -Path (Join-Path -Path $script:ModuleRoot -ChildPath 'DSCResource.Tests') -PathType Container)) -or
    (-not (Test-Path -Path (Join-Path -Path $script:ModuleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -PathType Leaf))
)
{
    (& git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests'))) 2> $null
}
else
{
    & git @('-C', (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests'), 'pull')
}

Import-Module -Name (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force

$TestEnvironment = Initialize-TestEnvironment -DSCModuleName $script:DSCModuleName -DSCResourceName $script:DSCResourceName -TestType Integration

#endregion

# Begin Testing
try
{
    #region Integration Tests

    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName).Config.ps1"
    . $ConfigFile

    Describe "$($script:DSCResourceName)_Integration - Ensure is set to Enabled" {
        BeforeAll {
            $certUtilResult       = & "$env:SystemRoot\system32\certutil.exe" @('-dump')
            $caServerFQDN         = ([regex]::matches($certUtilResult,'Server:[ \t]+`([A-Za-z0-9._-]+)''','IgnoreCase')).Groups[1].Value
            $caRootName           = ([regex]::matches($certUtilResult,'Name:[ \t]+`([\sA-Za-z0-9._-]+)''','IgnoreCase')).Groups[1].Value
            $keyLength            = 1024
            $exportable           = $true
            $providerName         = '"Microsoft RSA SChannel Cryptographic Provider"'
            $oid                  = '1.3.6.1.5.5.7.3.1'
            $keyUsage             = '0xa0'
            $certificateTemplate  = 'WebServer'
            $subject              = "$($script:DSCResourceName)_Test"
            $dns1                 = 'foofoo.com'
            $subjectAltName       = "dns=$dns1&"
            $friendlyName         = "$($script:DSCResourceName) Integration Test"       

            $wmsvcOriginalThumbprint = $null
            $wmsvcAddress = $null
            $wmsvcPort = $null
            try {
                $wmsvcAddress = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server' -Name 'IPAddress'
                if($wmsvcAddress -eq '*') {
                    $wmsvcAddress = '0.0.0.0'
                }
                $wmsvcPort = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server' -Name 'Port'
                $wmsvcBinding = '{0}:{1}' -f $wmsvcAddress,$wmsvcPort
                $netshResult = (& 'netsh' @('http','show','sslcert', ('ipport={0}' -f $wmsvcBinding))).Trim()
                if($netshResult -ne '')
                {
                    $wmsvcOriginalThumbprint = ([regex]::matches($netshResult,'Certificate Hash[ \t]+:[ \t]+([A-Fa-f0-9]+)','IgnoreCase')).Groups[1].Value
                }
            } catch {
                # Nothing to do here
            }

            $configData = @{
                AllNodes = @(
                    @{
                        NodeName                    = 'localhost'
                        Subject                     = $subject
                        CAServerFQDN                = $caServerFQDN
                        CARootName                  = $caRootName
                        KeyLength                   = $keyLength
                        Exportable                  = $exportable
                        ProviderName                = $providerName
                        OID                         = $oid
                        KeyUsage                    = $keyUsage
                        CertificateTemplate         = $certificateTemplate
                        SubjectAltName              = $subjectAltName
                        FriendlyName                = $friendlyName
                        PsDscAllowDomainUser        = $true
                        PsDscAllowPlainTextPassword = $true
                    }
                )
            }
        }

        Context 'WebServer certificate does not exist' {
            #region DEFAULT TESTS
            It 'Should compile and apply the MOF without throwing' {
                {
                    Write-Host "$configData"
                    Write-Host "$($script:DSCResourceName)_Config"
                    & "$($script:DSCResourceName)_Config" `
                        -OutputPath $TestDrive `
                        -ConfigurationData $configData `
                        -ComputerName localhost

                    Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force
                } | Should Not Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not Throw
            }
            #endregion
        }

        AfterAll {
            # Cleanup
            $CertificateNew = Get-Childitem -Path Cert:\LocalMachine\My |
                Where-Object -FilterScript {
                    $_.Subject -eq "CN=$($subject)" -and `
                    $_.Issuer.split(',')[0] -eq "CN=$($caRootName)"
                }

            Remove-Item `
                -Path $CertificateNew.PSPath `
                -Force `
                -ErrorAction SilentlyContinue

            if(($null -ne $wmsvcOriginalThumbprint) -and ($wmsvcOriginalThumbprint -ne '')) {
                $testBinding = Get-Item -Path ('IIS:\SslBindings\{0}!{1}' -f $wmsvcAddress,$wmsvcPort)
                if($null -ne $testBinding) {
                    $testBinding | Remove-Item -Force
                }

                $originalCertificate = Get-ChildItem -Path ('Cert:\LocalMachine\My\{0}' -f ($wmsvcOriginalThumbprint.ToUpper()))
                if($null -ne $originalCertificate) {
                    $originalCertificate | New-Item -Path ('IIS:\SslBindings\{0}!{1}' -f $wmsvcAddress,$wmsvcPort)
                }
            }
        }
    }
    #endregion
}
finally
{
    #region Footer

    Restore-TestEnvironment -TestEnvironment $TestEnvironment

    #endregion
}
