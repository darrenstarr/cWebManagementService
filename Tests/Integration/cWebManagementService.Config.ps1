Configuration cWebManagementService_Config {
    param(
        [string[]]$ComputerName="localhost"
    )
    
    Import-DscResource -ModuleName cWebManagementService
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xCertificate

    node $ComputerName {
        WindowsFeature IIS {
            Ensure          = "Present"
            Name            = "Web-Server"
        }

        WindowsFeature Management {
            Name = 'Web-Mgmt-Service'
            Ensure = 'Present'
            DependsOn = @('[WindowsFeature]IIS')
        }

        xCertReq ManagementSSLCert
            {
                Subject             = $Node.Subject
                CAServerFQDN        = $Node.CAServerFQDN
                CARootName          = $Node.CARootName
                KeyLength           = $Node.KeyLength
                Exportable          = $Node.Exportable
                ProviderName        = $Node.ProviderName
                OID                 = $Node.OID
                KeyUsage            = $Node.KeyUsage
                CertificateTemplate = $Node.CertificateTemplate
                SubjectAltName      = $Node.SubjectAltName
            } 

        cWebManagementService WebManager {
            CertificateSubjectName = $Node.Subject
            EnableRemoteManagement = 1
            DependsOn = @('[xCertReq]ManagementSSLCert')
        }
    }
}
