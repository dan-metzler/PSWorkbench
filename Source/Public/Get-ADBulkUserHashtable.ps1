function Get-ADBulkUserHashtable {
    <#
    .SYNOPSIS
        Retrieves Active Directory user information for multiple users from primary and backup domains

    .DESCRIPTION
        Searches for multiple AD users simultaneously using an optimized LDAP filter with flexible search criteria. If users are not found in the default domain,
        performs a secondary search against a specified global catalog server. Returns user details in a hashtable for efficient lookups.
        Uses verbose output to report users not found in either domain.

    .PARAMETER UserList
        Array of user identifiers to search for in Active Directory. The identifier type is determined by the SearchBy parameter.

    .PARAMETER SearchBy
        Specifies which AD attribute to use for user lookups. Use 'Auto' (default) to detect per-value based on format:
        values containing '@' resolve to UserPrincipalName, 'CN=' prefix to DistinguishedName, all-digits to EmployeeID,
        whitespace to DisplayName, and everything else to SamAccountName. Mixed input lists are fully supported in Auto mode.
        Note: EmployeeID and Mail are not in the default Get-ADUser property set - include them via -Properties if needed.

    .PARAMETER ADGlobalCatalog
        Global catalog server and port for backup domain searches when users are not found in the default domain.

    .PARAMETER Properties
        Optional array of additional AD properties to retrieve for each user

    .EXAMPLE
        Get-ADBulkUserHashtable -UserList 'user1', 'user2', 'user3'
        Searches for three users using Auto detection (all resolve to SamAccountName)

    .EXAMPLE
        Get-ADBulkUserHashtable -UserList 'user1@company.com', 'jdoe', 'CN=Jane Smith,OU=Users,DC=corp,DC=com'
        Mixed input list: UPN, SamAccountName, and DistinguishedName resolved automatically via Auto detection

    .EXAMPLE
        Get-ADBulkUserHashtable -UserList 'user1@company.com', 'user2@company.com' -SearchBy 'UserPrincipalName' -Verbose
        Explicit SearchBy - all values searched by UPN with verbose output for tracking search results

    .EXAMPLE
        Get-ADBulkUserHashtable -UserList 'John Doe', 'Jane Smith' -SearchBy 'DisplayName' -Properties 'Department', 'Title'
        Retrieves users by display name with additional properties

    .NOTES
        Author: https://github.com/dan-metzler
        PowerShellVersion: PowerShell 5.1 or Later Recommended.
        Features: Bulk user lookup, flexible search criteria, automatic failover to global catalog, hashtable return for efficient lookups, verbose logging
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$UserList,

        [Parameter()]
        [ValidateSet("Auto", "SamAccountName", "UserPrincipalName", "Mail", "DisplayName", "EmployeeID", "DistinguishedName")]
        [string]$SearchBy = "Auto",

        # Parameter help description
        [Parameter()]
        [string]$Server,

        # this parameter is when users are not found in the default domain, we check a backup domain, this is the server for the backup domain.
        [Parameter()]
        [string]$ADGlobalCatalog,

        # Optional properties parameter
        [Parameter()]
        [string[]]$Properties
    )

    # Map parameter values to actual LDAP attribute names
    $ldapAttributeMap = @{
        "SamAccountName"    = "sAMAccountName"
        "UserPrincipalName" = "userPrincipalName"
        "Mail"              = "mail"
        "DisplayName"       = "displayName"
        "EmployeeID"        = "employeeID"
        "DistinguishedName" = "distinguishedName"
    }

    # When SearchBy is Auto, detect each input value's attribute type by its distinct form:
    #   ^\s*(?i:(CN|OU|DC|...))  -> DistinguishedName  |  ^[^@\s]+@[^\s]+$  -> UserPrincipalName
    #   ^\d+$                    -> EmployeeID          |  whitespace        -> DisplayName  |  default -> SamAccountName
    if ($SearchBy -eq 'Auto') {
        $inputAttributeMap = @{}
        foreach ($inputValue in $UserList) {
            $inputAttributeMap[$inputValue] = switch -Regex ($inputValue) {
                '^\s*(?i:(CN|OU|DC|O|L|ST|C)=)' { 'DistinguishedName'; break }
                '^[^@\s]+@[^\s]+$'               { 'UserPrincipalName'; break }
                '^\d+$'                          { 'EmployeeID'; break }
                '\s'                             { 'DisplayName'; break }
                default                          { 'SamAccountName' }
            }
        }
    }
    else {
        $ldapAttribute = $ldapAttributeMap[$SearchBy]
    }

    # DisplayName, EmployeeID, and Mail are not in the default Get-ADUser property set.
    # In Auto mode, auto-inject whichever of those were detected so the post-search matching
    # can read them back from the returned user objects.
    $effectiveProperties = $Properties
    if ($SearchBy -eq 'Auto') {
        $autoProps = ($inputAttributeMap.Values | Select-Object -Unique | Where-Object { $_ -in 'DisplayName', 'EmployeeID', 'Mail' })
        if ($autoProps) {
            $effectiveProperties = @($autoProps) + @($Properties | Where-Object { $_ }) | Select-Object -Unique
        }
        Write-Verbose "Auto-detected attribute types: $(($inputAttributeMap.GetEnumerator() | ForEach-Object { "'$($_.Key)' -> '$($_.Value)'" }) -join ' | ')"
    }

    # Construct LDAP filter - in Auto mode each value uses its detected attribute; otherwise all share the same attribute
    $hashtable = @{}
    if ($SearchBy -eq 'Auto') {
        $ldapFilter = "(|" + ($UserList | ForEach-Object { "($($ldapAttributeMap[$inputAttributeMap[$_]])=$_)" }) + ")"
    }
    else {
        $ldapFilter = "(|" + ($UserList | ForEach-Object { "($ldapAttribute=$_)" }) + ")"
    }

    # Use splatting to conditionally include Properties parameter
    $getUserParams = @{
        LDAPFilter = $ldapFilter
    }

    if ($effectiveProperties) {
        $getUserParams['Properties'] = $effectiveProperties
    }

    if ($Server) {
        $getUserParams['Server'] = $Server
    }

    $userDetailsList = @(Get-ADUser @getUserParams)

    # Create lookup mapping from search input to found users
    $searchInputToUser = @{}
    for ($i = 0; $i -lt $userDetailsList.Count; $i++) {
        $currentUser = $userDetailsList[$i]
        # Find which input value(s) match this user - in Auto mode each input value checks its own detected attribute
        $matchingInputs = $UserList | Where-Object {
            $attr = if ($SearchBy -eq 'Auto') { $inputAttributeMap[$_] } else { $SearchBy }
            $currentUser.$attr -eq $_
        }
        foreach ($input in $matchingInputs) {
            $searchInputToUser[$input] = $currentUser
        }
    }

    # add the results to the hashtable keyed by SamAccountName for consistent lookups regardless of input form
    foreach ($inputValue in $UserList) {
        if ($searchInputToUser.ContainsKey($inputValue)) {
            $hashtable[$searchInputToUser[$inputValue].SamAccountName] = $searchInputToUser[$inputValue]
        }
    }

    if ($hashtable.Count -ne $UserList.Count) {
        # Use the input-tracking map (not the hashtable) to find which inputs didn't resolve to a user
        $notFoundUsers = $UserList | Where-Object { -not $searchInputToUser.ContainsKey($_) }
        Write-Verbose "$($notFoundUsers.Count) users were not found in Default Active Directory, searching global catalog..."

        # for users not found in the original search we need a sub search against the global catalog, we can reuse the same parameters but need to change the server and ldap filter
        if ($SearchBy -eq 'Auto') {
            $notFoundUsersLdapFilter = "(|" + ($notFoundUsers | ForEach-Object { "($($ldapAttributeMap[$inputAttributeMap[$_]])=$_)" }) + ")"
        }
        else {
            $notFoundUsersLdapFilter = "(|" + ($notFoundUsers | ForEach-Object { "($ldapAttribute=$_)" }) + ")"
        }

        $getUserParams['Server'] = $ADGlobalCatalog
        $getUserParams['LDAPFilter'] = $notFoundUsersLdapFilter

        $userBackupDetailsList = @(Get-ADUser @getUserParams)

        # add the backup results to the hashtable, nothing added if the userBackupDetailsList is empty
        $backupSearchInputToUser = @{}
        for ($i = 0; $i -lt $userBackupDetailsList.Count; $i++) {
            $currentUser = $userBackupDetailsList[$i]
            # Find which input value(s) match this user from backup search - same Auto-mode attribute detection
            $matchingInputs = $notFoundUsers | Where-Object {
                $attr = if ($SearchBy -eq 'Auto') { $inputAttributeMap[$_] } else { $SearchBy }
                $currentUser.$attr -eq $_
            }
            foreach ($input in $matchingInputs) {
                $backupSearchInputToUser[$input] = $currentUser
            }
        }

        # add the backup results keyed by SamAccountName
        foreach ($inputValue in $notFoundUsers) {
            if ($backupSearchInputToUser.ContainsKey($inputValue)) {
                $hashtable[$backupSearchInputToUser[$inputValue].SamAccountName] = $backupSearchInputToUser[$inputValue]
            }
        }

        # Check if there are still users not found after backup search
        $stillNotFoundUsers = $notFoundUsers | Where-Object { -not $backupSearchInputToUser.ContainsKey($_) }
        if ($stillNotFoundUsers.Count -gt 0) {
            foreach ($user in $stillNotFoundUsers) {
                Write-Warning "User not found in ($env:USERDNSDOMAIN) or ($ADGlobalCatalog): $user"
            }
        }
    }

    if ($hashtable.count -gt 0) {
        $hashtable
    }
    else {
        $null
    }
}