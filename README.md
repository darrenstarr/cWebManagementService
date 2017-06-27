# cWebManagementService
cWebManagementService is a Powershell DSC Resource for configuring the Internet Information Server Web Management Service. It consists of two primary functions, enabling the service and assigning a certificate to the service.

## Implementation details
### Class based
As this resource is 'class based' it requires Powershell v5.0 or later. It has only been tested on Powershell 5.1 and later. This also means that due to current limitations in class based resources, the resource doesn't reside well in DSCResources and therefore will generate pester warnings regarding the folder confusion. Moving the PSM1 to a DSCResource folder and then changing the root module in the PSD1 file does not seem to alleviate this.

### Integration testing
The resource includes integration tests which verify with pester

### Unit testing
At this time, the resource does not contain any unit tests.

### netsh and WebAdministration vs. WMI
When writing this resource, I was not quite ready to experiment with using WMI directly for listing and configuring DSC. This is on my TODO, but not in the near future as using netsh and the IIS:\ directory appears to work well enough at this time. It would of course be optimal to reduce dependence on the non-Powershell tools where possible.

## Example
```
<#
    .EXAMPLE
    Request and Accept a certificate from an Active Directory Root Certificate Authority. Then assign it to
    the IIS Web Management Service
#>
configuration Example
{
    param
    (
        [Parameter()]
        [string[]]
        $NodeName = 'localhost',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [PSCredential]
        $Credential
    )

    Import-DscResource -ModuleName xCertificate
    Node 'localhost'
    {
        xCertReq SSLCert
        {
            CARootName                = 'test-dc01-ca'
            CAServerFQDN              = 'dc01.test.pha'
            Subject                   = 'foodomain.test.net'
            KeyLength                 = '1024'
            Exportable                = $true
            ProviderName              = '"Microsoft RSA SChannel Cryptographic Provider"'
            OID                       = '1.3.6.1.5.5.7.3.1'
            KeyUsage                  = '0xa0'
            CertificateTemplate       = 'WebServer'
            AutoRenew                 = $true
            Credential                = $Credential
        }

        cWebManagementService WebManager {
            CertificateSubjectName = $Node.Subject
            EnableRemoteManagement = 1
            DependsOn = @('[xCertReq]SSLCert')
        }

    }
}
```
(C) Copyright 2017 Conscia Norway AS

Author Darren R. Starr
