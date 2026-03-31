---
external help file: PSWorkbench-help.xml
Module Name: PSWorkbench
online version:
schema: 2.0.0
---

# Update-GenericList

## SYNOPSIS
Sanitizes and normalizes user input arrays by removing whitespaces, converting case, and filtering null/duplicate values

## SYNTAX

```
Update-GenericList [-UserInput] <String[]> [-RemoveWhitespaces] [-Trim] [-ConvertToLowercase]
 [-ConvertToUppercase] [-RemoveNullOrEmptyItems] [-RemoveDuplicates] [-ProgressAction <ActionPreference>]
 [<CommonParameters>]
```

## DESCRIPTION
The **Update-GenericList** function processes user input arrays to standardize and clean the data.
It provides flexible options to remove whitespaces,
convert case (uppercase or lowercase), remove null/empty items, and eliminate duplicates.

## EXAMPLES

### EXAMPLE 1
```
Update-GenericList -UserInput @("  User1  ", "USER2", "user1") -RemoveWhitespaces -ConvertToLowercase -RemoveDuplicates
```

Returns: @("user1", "user2") - removes spaces, converts to lowercase, and eliminates duplicates

### EXAMPLE 2
```
Update-GenericList -UserInput @("account1", "", "ACCOUNT2", $null) -ConvertToUppercase -RemoveNullOrEmptyItems
```

Returns: @("ACCOUNT1", "ACCOUNT2") - converts to uppercase and removes null/empty items

### EXAMPLE 3
```
Update-GenericList -UserInput @(" John Doe ", " Jane Smith ", "Bob Jones") -Trim -RemoveDuplicates
```

Returns: @("John Doe", "Jane Smith", "Bob Jones") - removes leading/trailing spaces while preserving internal spaces

## PARAMETERS

### -UserInput
Array of strings that require sanitization and normalization.
This parameter is mandatory and accepts empty collections.

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

### -RemoveWhitespaces
Switch parameter to remove all whitespace characters from each input item using regex replacement.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Trim
Switch parameter to remove leading and trailing whitespace from each input item while preserving internal spaces.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConvertToLowercase
Switch parameter to convert all input items to lowercase.
Cannot be used simultaneously with ConvertToUppercase.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConvertToUppercase
Switch parameter to convert all input items to uppercase.
Cannot be used simultaneously with ConvertToLowercase.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -RemoveNullOrEmptyItems
Switch parameter to filter out null, empty, or whitespace-only items from the input array.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -RemoveDuplicates
Switch parameter to remove duplicate values from the processed array using Select-Object -Unique.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
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
PowerShellVersion: PowerShell 5.1 or Later Recommended

Features:
- Flexible input sanitization with multiple processing options
- Parameter validation prevents conflicting case conversion options
- Efficient processing using .NET collections and regex
- Verbose logging for processing operations performed
- Support for empty collections and null handling

## RELATED LINKS
