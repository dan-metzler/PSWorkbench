---
external help file: PSWorkbench-help.xml
Module Name: PSWorkbench
online version:
schema: 2.0.0
---

# Get-ADBulkUserHashtable

## SYNOPSIS
Retrieves Active Directory user information for multiple users from primary and backup domains

## SYNTAX

```
Get-ADBulkUserHashtable [-UserList] <String[]> [[-SearchBy] <String>] [[-Server] <String>]
 [[-ADGlobalCatalog] <String>] [[-Properties] <String[]>] [-ProgressAction <ActionPreference>]
 [<CommonParameters>]
```

## DESCRIPTION
Searches for multiple AD users simultaneously using an optimized LDAP filter with flexible search criteria.
If users are not found in the default domain,
performs a secondary search against a specified global catalog server.
Returns user details in a hashtable for efficient lookups.
Uses verbose output to report users not found in either domain.

## EXAMPLES

### EXAMPLE 1
```
Get-ADBulkUserHashtable -UserList 'user1', 'user2', 'user3'
Searches for three users using Auto detection (all resolve to SamAccountName)
```

### EXAMPLE 2
```
Get-ADBulkUserHashtable -UserList 'user1@company.com', 'jdoe', 'CN=Jane Smith,OU=Users,DC=corp,DC=com'
Mixed input list: UPN, SamAccountName, and DistinguishedName resolved automatically via Auto detection
```

### EXAMPLE 3
```
Get-ADBulkUserHashtable -UserList 'user1@company.com', 'user2@company.com' -SearchBy 'UserPrincipalName' -Verbose
Explicit SearchBy - all values searched by UPN with verbose output for tracking search results
```

### EXAMPLE 4
```
Get-ADBulkUserHashtable -UserList 'John Doe', 'Jane Smith' -SearchBy 'DisplayName' -Properties 'Department', 'Title'
Retrieves users by display name with additional properties
```

## PARAMETERS

### -UserList
Array of user identifiers to search for in Active Directory.
The identifier type is determined by the SearchBy parameter.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SearchBy
Specifies which AD attribute to use for user lookups.
Use 'Auto' (default) to detect per-value based on format:
values containing '@' resolve to UserPrincipalName, 'CN=' prefix to DistinguishedName, all-digits to EmployeeID,
whitespace to DisplayName, and everything else to SamAccountName.
Mixed input lists are fully supported in Auto mode.
Note: EmployeeID and Mail are not in the default Get-ADUser property set - include them via -Properties if needed.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: Auto
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
Active Directory server to target for the primary search.
When omitted, the default domain controller is used.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ADGlobalCatalog
Global catalog server and port for backup domain searches when users are not found in the default domain.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Properties
Optional array of additional AD properties to retrieve for each user

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
{{ Fill ProgressAction Description }}

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
Author: https://github.com/dan-metzler
PowerShellVersion: PowerShell 5.1 or Later Recommended.
Features: Bulk user lookup, flexible search criteria, automatic failover to global catalog, hashtable return for efficient lookups, verbose logging

## RELATED LINKS
