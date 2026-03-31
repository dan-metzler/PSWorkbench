---
external help file: PSWorkbench-help.xml
Module Name: PSWorkbench
online version:
schema: 2.0.0
---

# Resolve-ADGroupMember

## SYNOPSIS
Retrieves Active Directory group members with cross-domain resolution capabilities to handle complex multi-domain environments.

## SYNTAX

```
Resolve-ADGroupMember [-Identity] <String[]> -ADGlobalCatalog <String> [-ProgressAction <ActionPreference>]
 [<CommonParameters>]
```

## DESCRIPTION
This function addresses common challenges in multi-domain Active Directory environments by retrieving group members
and automatically handling cross-domain member resolution.
It queries the specified Active Directory groups for
their membership details, attempts to resolve each member object in the local domain first, and falls back to
global catalog queries when members exist in different domains.
The function provides robust error handling for
orphaned or inaccessible member references and returns detailed member object information for analysis and reporting.

## EXAMPLES

### EXAMPLE 1
```
Resolve-ADGroupMember -Identity "Domain-SecurityGroup-Name"
```

Retrieves all members of the specified security group, resolving members across domains as needed.

### EXAMPLE 2
```
"Group1", "Group2", "Group3" | Resolve-ADGroupMember
```

Uses pipeline input to process multiple groups and return comprehensive member information with cross-domain resolution.

## PARAMETERS

### -Identity
Array of Active Directory group identities (names, distinguished names, or SIDs) for which to retrieve membership
information.
Supports pipeline input and processes multiple groups efficiently with cross-domain member resolution.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ADGlobalCatalog
Global catalog server for cross-domain member resolution.
Used as a fallback when a member object cannot be found
in the local domain.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
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
Features: Cross-domain resolution, Global catalog queries, Pipeline support, Error handling, Multi-group processing

## RELATED LINKS
