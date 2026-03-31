@{
    RootModule        = 'PSWorkbench.psm1'
    ModuleVersion     = '0.0.1'
    GUID              = '1f0e620b-7e34-47c5-86ae-f21eb3f7253b'
    Author            = 'Dan Metzler'
    CompanyName       = 'Community'
    Copyright         = ''
    Description       = 'PowerShell utility module containing reusable, high-performance functions for Active Directory operations and sysadmin tasks.'
    PowerShellVersion = '5.1'

    PrivateData       = @{
        PSData = @{
            Tags         = @('ActiveDirectory', 'AD', 'Utilities', 'SysAdmin')
            LicenseUri   = 'https://github.com/dan-metzler/PSWorkbench/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/dan-metzler/PSWorkbench'
            ReleaseNotes = ''
        }
    }

    FunctionsToExport = @(
        'Get-ADBulkUserHashtable'
        'Resolve-ADGroupMember'
        'Update-GenericList'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
