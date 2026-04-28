function Test-Base64Image {
    <#
    .SYNOPSIS
    Tests whether a Base64-encoded string represents a valid image.

    .DESCRIPTION
    Decodes a Base64 string and attempts to load it as a System.Drawing.Image.
    Returns $true if the string decodes to a valid image, $false otherwise.

    Accepts bare Base64 strings as well as data URI strings with the prefix
    "data:image/<type>;base64," — the prefix is stripped automatically before decoding.

    .PARAMETER Base64String
    The Base64-encoded string to validate. Accepts a bare Base64 value or a full
    data URI (e.g., "data:image/png;base64,<data>").

    .EXAMPLE
    Test-Base64Image -Base64String $encodedString

    Returns $true if $encodedString decodes to a valid image, $false otherwise.

    .EXAMPLE
    Test-Base64Image -Base64String "data:image/png;base64,iVBORw0KGgo..."

    Strips the data URI prefix and validates the embedded Base64 image data.

    .INPUTS
    None. Does not accept pipeline input.

    .OUTPUTS
    System.Boolean
    Returns $true if the string is a valid image, $false if not.

    .NOTES
    Author: https://github.com/dan-metzler
    PowerShellVersion: PowerShell 5.1 or later.
    Requires the System.Drawing assembly, which is loaded automatically.

    .LINK
    https://github.com/dan-metzler/PSWorkbench
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Base64String
    )

    begin {
        Add-Type -AssemblyName System.Drawing
    }

    process {
        $base64 = $Base64String -replace '^data:image/[^;]+;base64,', ''

        try {
            $bytes = [Convert]::FromBase64String($base64)
            $ms = [System.IO.MemoryStream]::new($bytes)
            $img = [System.Drawing.Image]::FromStream($ms)
            $img.Dispose()
            $ms.Dispose()
            return $true
        }
        catch {
            return $false
        }
    }
}