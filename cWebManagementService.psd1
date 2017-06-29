@{
    # Script module or binary module file associated with this manifest.
    RootModule = '.\cWebManagementService.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.1'

    # ID used to uniquely identify this module
    GUID = 'fc4ac4ad-5bbe-422b-bcea-2ca77b14fccf'

    # Author of this module
    Author = 'Darren R. Starr'

    # Company or vendor of this module
    CompanyName = 'Conscia AS Norway'

    # Copyright statement for this module
    Copyright = '(c) 2017 Conscia AS Norway. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'DSC Resource to manage the Web Management Services'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.0'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @('WebAdministration', 'xCertificate')

    # DSC resources to export from this module
    DscResourcesToExport = 'cWebManagementService'

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('webmanagementservice','dsc')

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/darrenstarr/cWebManagementService/blob/master/LICENSE'


            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/darrenstarr/cWebManagementService'

            # ReleaseNotes of this module
            ReleaseNotes = 'Initial release'

            ExternalModuleDependencies = @('WebAdministration')

        } # End of PSData hashtable

    } # End of PrivateData hashtable
}

