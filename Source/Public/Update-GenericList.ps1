function Update-GenericList {
    <#
    .SYNOPSIS
        Sanitizes and normalizes user input arrays by removing whitespaces, converting case, and filtering null/duplicate values

    .DESCRIPTION
        The **Update-GenericList** function processes user input arrays to standardize and clean the data. It provides flexible options to remove whitespaces,
        convert case (uppercase or lowercase), remove null/empty items, and eliminate duplicates.

    .PARAMETER UserInput
        Array of strings that require sanitization and normalization. This parameter is mandatory and accepts empty collections.

    .PARAMETER RemoveWhitespaces
        Switch parameter to remove all whitespace characters from each input item using regex replacement.

    .PARAMETER Trim
        Switch parameter to remove leading and trailing whitespace from each input item while preserving internal spaces.

    .PARAMETER ConvertToLowercase
        Switch parameter to convert all input items to lowercase. Cannot be used simultaneously with ConvertToUppercase.

    .PARAMETER ConvertToUppercase
        Switch parameter to convert all input items to uppercase. Cannot be used simultaneously with ConvertToLowercase.

    .PARAMETER RemoveNullOrEmptyItems
        Switch parameter to filter out null, empty, or whitespace-only items from the input array.

    .PARAMETER RemoveDuplicates
        Switch parameter to remove duplicate values from the processed array using Select-Object -Unique.

    .EXAMPLE
        Update-GenericList -UserInput @("  User1  ", "USER2", "user1") -RemoveWhitespaces -ConvertToLowercase -RemoveDuplicates

        Returns: @("user1", "user2") - removes spaces, converts to lowercase, and eliminates duplicates

    .EXAMPLE
        Update-GenericList -UserInput @("account1", "", "ACCOUNT2", $null) -ConvertToUppercase -RemoveNullOrEmptyItems

        Returns: @("ACCOUNT1", "ACCOUNT2") - converts to uppercase and removes null/empty items

    .EXAMPLE
        Update-GenericList -UserInput @(" John Doe ", " Jane Smith ", "Bob Jones") -Trim -RemoveDuplicates

        Returns: @("John Doe", "Jane Smith", "Bob Jones") - removes leading/trailing spaces while preserving internal spaces

    .NOTES
        Author: https://github.com/dan-metzler
        PowerShellVersion: PowerShell 5.1 or Later Recommended
    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = "Array of strings that require sanitization and normalization."
        )]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$UserInput,

        [Parameter(
        )]
        [switch]$RemoveWhitespaces,

        [Parameter(
        )]
        [switch]$Trim,

        [Parameter()]
        [switch]$ConvertToLowercase,

        [Parameter()]
        [switch]$ConvertToUppercase,

        [Parameter()]
        [switch]$RemoveNullOrEmptyItems,

        [Parameter()]
        [switch]$RemoveDuplicates
    )

    # PARAMETER VALIDATION, ONE MUST BE SET TO TRUE
    if (-Not($RemoveWhitespaces -or $Trim -or $ConvertToLowercase -or $ConvertToUppercase)) {
        throw "At least one of the boolean parameters [RemoveWhitespaces, Trim, ConvertToLowercase, ConvertToUppercase] must be set to `$true"
    }

    if ($ConvertToLowercase -and $ConvertToUppercase) {
        throw "[ConvertToLowercase] and [ConvertToUppercase] CANNOT both be set at the same time, only one can be chosen"
    }

    # IF WHITE SPACE SWITCH IS SELECTED, CLEAN THE INPUT DATA AND GET RID OF ANY SPACES
    $LIST_CollectUpdatedItems = [System.Collections.Generic.List[string]]::New()

    if ($RemoveWhitespaces -and $ConvertToLowercase) {
        for ($i = 0; $i -lt $UserInput.Count; $i++) {
            $LIST_CollectUpdatedItems.Add($UserInput[$i].Replace(' ', '').ToLowerInvariant())
        }
        Write-Verbose "Cleaned User Input :: [Removed Whitespaces & Converted To Lowercase]"
    }
    elseif ($RemoveWhitespaces -and $ConvertToUppercase) {
        for ($i = 0; $i -lt $UserInput.Count; $i++) {
            $LIST_CollectUpdatedItems.Add($UserInput[$i].Replace(' ', '').ToUpperInvariant())
        }
        Write-Verbose "Cleaned User Input :: [Removed Whitespaces & Converted To Uppercase]"
    }
    elseif ($RemoveWhitespaces) {
        for ($i = 0; $i -lt $UserInput.Count; $i++) {
            $LIST_CollectUpdatedItems.Add($UserInput[$i].Replace(' ', ''))
        }
        Write-Verbose "Cleaned User Input :: [Removed Whitespaces Only]"
    }
    elseif ($ConvertToLowercase -and (-Not($RemoveWhitespaces))) {
        for ($i = 0; $i -lt $UserInput.Count; $i++) {
            $LIST_CollectUpdatedItems.Add($UserInput[$i].ToLowerInvariant())
        }
        Write-Verbose "Cleaned User Input :: [Converted To Lowercase]"
    }
    elseif ($ConvertToUppercase -and (-Not($RemoveWhitespaces))) {
        for ($i = 0; $i -lt $UserInput.Count; $i++) {
            $LIST_CollectUpdatedItems.Add($UserInput[$i].ToUpperInvariant())
        }
        Write-Verbose "Cleaned User Input :: [Converted To Uppercase]"
    }
    elseif ($Trim -and (-Not($RemoveWhitespaces -or $ConvertToLowercase -or $ConvertToUppercase))) {
        for ($i = 0; $i -lt $UserInput.Count; $i++) {
            $LIST_CollectUpdatedItems.Add($UserInput[$i].Trim())
        }
        Write-Verbose "Cleaned User Input :: [Trimmed Leading/Trailing Whitespace]"
    }

    # Apply Trim processing if specified along with other operations
    if ($Trim -and ($ConvertToLowercase -or $ConvertToUppercase -or $RemoveWhitespaces)) {
        for ($i = 0; $i -lt $LIST_CollectUpdatedItems.Count; $i++) {
            $LIST_CollectUpdatedItems[$i] = $LIST_CollectUpdatedItems[$i].Trim()
        }
        Write-Verbose "Cleaned User Input :: [Trimmed Leading/Trailing Whitespace]"
    }

    if ($RemoveNullOrEmptyItems) {
        $revised_list = [System.Collections.Generic.List[string]]::New()
        $removed_null_empty_counter = 0

        for ($i = 0; $i -lt $LIST_CollectUpdatedItems.Count; $i++) {
            if ([string]::IsNullOrEmpty($LIST_CollectUpdatedItems[$i].Trim())) {
                #Write-Verbose "String is Null or Empty, Removed From List :: [$i]"
                $removed_null_empty_counter++
            }
            else {
                $revised_list.Add($LIST_CollectUpdatedItems[$i])
            }
        }

        if ($removed_null_empty_counter -ne 0) {
            Write-Verbose "Number of null or empty items removed from list :: [$($removed_null_empty_counter)]"
        }

        if ($RemoveDuplicates) {
            $deduped = [System.Collections.Generic.List[string]]::new()
            foreach ($item in ($revised_list | Select-Object -Unique)) {
                $deduped.Add($item)
            }
            Write-Output -NoEnumerate $deduped
        }
        else {
            Write-Output -NoEnumerate $revised_list
        }
    }
    else {
        if ($RemoveDuplicates) {
            $deduped = [System.Collections.Generic.List[string]]::new()
            foreach ($item in ($LIST_CollectUpdatedItems | Select-Object -Unique)) {
                $deduped.Add($item)
            }
            Write-Output -NoEnumerate $deduped
        }
        else {
            Write-Output -NoEnumerate $LIST_CollectUpdatedItems
        }
    }
}