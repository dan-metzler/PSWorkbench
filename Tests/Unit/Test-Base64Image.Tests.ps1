#Requires -Version 5.1

Describe "Test-Base64Image" {

    BeforeAll {
        . "$PSScriptRoot\..\..\Source\Public\Test-Base64Image.ps1"

        Add-Type -AssemblyName System.Drawing

        # Generate a valid PNG base64 string in memory using a 1x1 Bitmap.
        $bitmap = [System.Drawing.Bitmap]::new(1, 1)
        $bitmap.SetPixel(0, 0, [System.Drawing.Color]::Red)
        $pngStream = [System.IO.MemoryStream]::new()
        $bitmap.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
        $bitmap.Dispose()
        $script:validPngBase64 = [Convert]::ToBase64String($pngStream.ToArray())
        $pngStream.Dispose()

        # Same image wrapped in a data URI prefix.
        $script:validPngDataUri = "data:image/png;base64,$($script:validPngBase64)"

        # Valid base64 that is not an image (plain text bytes).
        $script:notAnImageBase64 = [Convert]::ToBase64String(
            [System.Text.Encoding]::UTF8.GetBytes("This is not an image")
        )
    }

    # -------------------------------------------------------------------
    Context "Valid Images" {
        # -------------------------------------------------------------------

        It "returns true for a valid PNG base64 string" {
            Test-Base64Image -Base64String $script:validPngBase64 | Should -BeTrue
        }

        It "returns true when the data URI prefix is present" {
            Test-Base64Image -Base64String $script:validPngDataUri | Should -BeTrue
        }

        It "returns a [bool] type" {
            $result = Test-Base64Image -Base64String $script:validPngBase64
            $result | Should -BeOfType [bool]
        }
    }

    # -------------------------------------------------------------------
    Context "Invalid Input" {
        # -------------------------------------------------------------------

        It "returns false for an invalid base64 string" {
            Test-Base64Image -Base64String "!!!not-base64!!!" | Should -BeFalse
        }

        It "returns false for valid base64 that is not an image" {
            Test-Base64Image -Base64String $script:notAnImageBase64 | Should -BeFalse
        }

        It "returns false for an empty string" {
            Test-Base64Image -Base64String "" | Should -BeFalse
        }

        It "returns false for a whitespace-only string" {
            Test-Base64Image -Base64String "   " | Should -BeFalse
        }
    }
}
