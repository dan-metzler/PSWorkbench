function Resolve-ADGroupMember {
    <#
    .SYNOPSIS
        Retrieves Active Directory group members with cross-domain resolution capabilities to handle complex multi-domain environments.

    .DESCRIPTION
        This function addresses common challenges in multi-domain Active Directory environments by retrieving group members
        and automatically handling cross-domain member resolution. It queries the specified Active Directory groups for
        their membership details, attempts to resolve each member object in the local domain first, and falls back to
        global catalog queries when members exist in different domains. The function provides robust error handling for
        orphaned or inaccessible member references and returns detailed member object information for analysis and reporting.

    .PARAMETER Identity
        Array of Active Directory group identities (names, distinguished names, or SIDs) for which to retrieve membership
        information. Supports pipeline input and processes multiple groups efficiently with cross-domain member resolution.

    .EXAMPLE
        Resolve-ADGroupMember -Identity "Domain-SecurityGroup-Name"

        Retrieves all members of the specified security group, resolving members across domains as needed.

    .EXAMPLE
        "Group1", "Group2", "Group3" | Resolve-ADGroupMember

        Uses pipeline input to process multiple groups and return comprehensive member information with cross-domain resolution.

    .NOTES
        Author: https://github.com/dan-metzler
        PowerShellVersion: PowerShell 5.1 or Later Recommended.
        Features: Cross-domain resolution, Global catalog queries, Pipeline support, Error handling, Multi-group processing
    #>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [string[]]$Identity,

        # Active Directory global catalog server for cross-domain member resolution when local queries fail
        [Parameter(Mandatory)]
        [string]$ADGlobalCatalog
    )

    foreach ($GroupIdentity in $Identity) {
        $Group = $null
        $Group = Get-ADGroup -Identity $GroupIdentity -Properties Member
        if (-not $Group) {
            continue
        }
        Foreach ($Member in $Group.Member) {
            try {
                Get-ADObject $Member
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                Get-ADObject $Member -Server $ADGlobalCatalog
            }
            catch {
                Write-Error "Error finding $Member in Root Global Domains"
            }
        }
    }
}