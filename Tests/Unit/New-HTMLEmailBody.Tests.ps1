#Requires -Version 5.1

Describe "New-HTMLEmailBody" {

    BeforeAll {
        . "$PSScriptRoot\..\..\Source\Public\Test-Base64Image.ps1"
        . "$PSScriptRoot\..\..\Source\Public\New-HTMLEmailBody.ps1"

        Add-Type -AssemblyName System.Drawing

        $bitmap = [System.Drawing.Bitmap]::new(1, 1)
        $bitmap.SetPixel(0, 0, [System.Drawing.Color]::Blue)
        $pngStream = [System.IO.MemoryStream]::new()
        $bitmap.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
        $bitmap.Dispose()
        $script:validLogoBase64 = [Convert]::ToBase64String($pngStream.ToArray())
        $pngStream.Dispose()

        $script:invalidLogoBase64 = [Convert]::ToBase64String(
            [System.Text.Encoding]::UTF8.GetBytes("not-an-image")
        )

        $script:baseParams = @{
            Base64ImageString = $script:validLogoBase64
            MainHeader        = "Test Header"
            PreviewText       = "Test Preview"
            TeamSignOff       = "Test Team"
            ParagraphIntro    = "Test intro paragraph."
            FooterText        = "Test Footer"
            EmailFilterText   = "[TestFilter]"
        }
    }

    # -------------------------------------------------------------------
    Context "Output Structure" {
        # -------------------------------------------------------------------

        It "returns a string" {
            New-HTMLEmailBody @script:baseParams | Should -BeOfType [string]
        }

        It "output contains an HTML doctype" {
            New-HTMLEmailBody @script:baseParams | Should -Match '(?i)<!doctype html>'
        }

        It "output contains a closing html tag" {
            New-HTMLEmailBody @script:baseParams | Should -Match '(?i)</html>'
        }

        It "output contains no unreplaced tokens" {
            New-HTMLEmailBody @script:baseParams | Should -Not -Match '\{\{[A-Z_]+\}\}'
        }
    }

    # -------------------------------------------------------------------
    Context "Token Replacement" {
        # -------------------------------------------------------------------

        BeforeAll {
            $script:tokenResult = New-HTMLEmailBody @script:baseParams
        }

        It "replaces {{MAIN_HEADER}}" {
            $script:tokenResult | Should -Match 'Test Header'
        }

        It "replaces {{PREVIEW_TEXT}}" {
            $script:tokenResult | Should -Match 'Test Preview'
        }

        It "replaces {{TEAM_SIGN_OFF}}" {
            $script:tokenResult | Should -Match 'Test Team'
        }

        It "replaces {{PARAGRAPH_INTRO}}" {
            $script:tokenResult | Should -Match 'Test intro paragraph\.'
        }

        It "replaces {{FOOTER_TEXT}}" {
            $script:tokenResult | Should -Match 'Test Footer'
        }

        It "replaces {{EMAIL_FILTER_TEXT}}" {
            $script:tokenResult | Should -Match '\[TestFilter\]'
        }
    }

    # -------------------------------------------------------------------
    Context "Logo Handling" {
        # -------------------------------------------------------------------

        It "injects the base64 string into the img src when valid" {
            $result = New-HTMLEmailBody @script:baseParams
            $result | Should -Match ([regex]::Escape($script:validLogoBase64))
        }

        It "removes the img tag when the base64 is not a valid image" {
            $params = $script:baseParams.Clone()
            $params.Base64ImageString = $script:invalidLogoBase64
            $result = New-HTMLEmailBody @params -WarningAction SilentlyContinue
            $result | Should -Not -Match '<img'
        }

        It "emits a warning when the base64 is not a valid image" {
            $params = $script:baseParams.Clone()
            $params.Base64ImageString = $script:invalidLogoBase64
            { New-HTMLEmailBody @params -WarningAction Stop } | Should -Throw
        }
    }

    # -------------------------------------------------------------------
    Context "Table Injection" {
        # -------------------------------------------------------------------

        It "does not inject a GeneratedTable element when -Table is not specified" {
            New-HTMLEmailBody @script:baseParams | Should -Not -Match '<table class="GeneratedTable">'
        }

        It "injects a GeneratedTable element when -Table is specified" {
            $tableObj = @([PSCustomObject]@{ Account = "svc-test"; Status = "Removed" })
            New-HTMLEmailBody @script:baseParams -Table -TableObject $tableObj |
                Should -Match '<table class="GeneratedTable">'
        }

        It "renders property names as table header cells" {
            $tableObj = @([PSCustomObject]@{ Account = "svc-test" })
            New-HTMLEmailBody @script:baseParams -Table -TableObject $tableObj |
                Should -Match 'Account'
        }

        It "renders property values as table data cells" {
            $tableObj = @([PSCustomObject]@{ Account = "svc-test" })
            New-HTMLEmailBody @script:baseParams -Table -TableObject $tableObj |
                Should -Match 'svc-test'
        }

        It "renders rows for multiple objects" {
            $tableObj = @(
                [PSCustomObject]@{ Account = "svc-alpha" }
                [PSCustomObject]@{ Account = "svc-beta" }
            )
            $result = New-HTMLEmailBody @script:baseParams -Table -TableObject $tableObj
            $result | Should -Match 'svc-alpha'
            $result | Should -Match 'svc-beta'
        }

        It "renders all properties of a single object as separate rows" {
            $tableObj = @([PSCustomObject]@{ Account = "svc-test"; Status = "Removed"; Department = "IT" })
            $result = New-HTMLEmailBody @script:baseParams -Table -TableObject $tableObj
            $result | Should -Match 'Account'
            $result | Should -Match 'Status'
            $result | Should -Match 'Department'
        }
    }

    # -------------------------------------------------------------------
    Context "Table Layout - RowHeaders" {
        # -------------------------------------------------------------------

        BeforeAll {
            $script:rowObj = @(
                [PSCustomObject]@{ Account = "svc-alpha"; Status = "Removed" }
                [PSCustomObject]@{ Account = "svc-beta";  Status = "Active"  }
            )
            $script:rowResult = New-HTMLEmailBody @script:baseParams -Table -TableObject $script:rowObj -TableLayout RowHeaders
        }

        It "renders property names as th elements" {
            $script:rowResult | Should -Match '<th[^>]*>Account'
            $script:rowResult | Should -Match '<th[^>]*>Status'
        }

        It "renders property values as td elements" {
            $script:rowResult | Should -Match '<td[^>]*>svc-alpha'
            $script:rowResult | Should -Match '<td[^>]*>Removed'
        }

        It "does not contain a tbody element" {
            $script:rowResult | Should -Not -Match '<tbody'
        }
    }

    # -------------------------------------------------------------------
    Context "Table Layout - ColumnHeaders" {
        # -------------------------------------------------------------------

        BeforeAll {
            $script:colObj = @(
                [PSCustomObject]@{ Account = "svc-alpha"; Status = "Removed" }
                [PSCustomObject]@{ Account = "svc-beta";  Status = "Active"  }
            )
            $script:colResult = New-HTMLEmailBody @script:baseParams -Table -TableObject $script:colObj -TableLayout ColumnHeaders
        }

        It "renders property names as th elements in the header row" {
            $script:colResult | Should -Match '<th[^>]*>Account'
            $script:colResult | Should -Match '<th[^>]*>Status'
        }

        It "renders each object as a data row in tbody" {
            $script:colResult | Should -Match '<tbody'
            $script:colResult | Should -Match '<td[^>]*>svc-alpha'
            $script:colResult | Should -Match '<td[^>]*>svc-beta'
        }

        It "each object produces exactly one tr in tbody" {
            $tbodyBlock = [regex]::Match($script:colResult, '(?s)<tbody>(.*?)</tbody>').Groups[1].Value
            $trCount = ([regex]::Matches($tbodyBlock, '<tr>')).Count
            $trCount | Should -Be 2
        }

        It "does not repeat property names as row headers" {
            $tbodyBlock = [regex]::Match($script:colResult, '(?s)<tbody>(.*?)</tbody>').Groups[1].Value
            $tbodyBlock | Should -Not -Match '<th'
        }
    }

    # -------------------------------------------------------------------
    Context "Special Characters in Values" {
        # -------------------------------------------------------------------

        It "preserves a dollar sign in MainHeader without mangling" {
            $params = $script:baseParams.Clone()
            $params.MainHeader = 'Cost $50'
            New-HTMLEmailBody @params | Should -Match ([regex]::Escape('Cost $50'))
        }

        It "preserves a backslash in ParagraphIntro without mangling" {
            $params = $script:baseParams.Clone()
            $params.ParagraphIntro = 'Path is C:\Temp\file.txt'
            New-HTMLEmailBody @params | Should -Match ([regex]::Escape('C:\Temp\file.txt'))
        }

        It "preserves special characters in table cell values" {
            $tableObj = @([PSCustomObject]@{ Path = 'C:\Users\$Admin' })
            $result = New-HTMLEmailBody @script:baseParams -Table -TableObject $tableObj
            $result | Should -Match ([regex]::Escape('C:\Users\$Admin'))
        }
    }

    # -------------------------------------------------------------------
    Context "Theme Override" {
        # -------------------------------------------------------------------

        It "applies a custom COLOR_PRIMARY to the output" {
            New-HTMLEmailBody @script:baseParams -Theme @{ COLOR_PRIMARY = '#ABCDEF' } |
                Should -Match '#ABCDEF'
        }

        It "applies multiple theme overrides" {
            $result = New-HTMLEmailBody @script:baseParams -Theme @{
                COLOR_PRIMARY      = '#111111'
                COLOR_PRIMARY_DARK = '#222222'
            }
            $result | Should -Match '#111111'
            $result | Should -Match '#222222'
        }

        It "emits a warning for an unknown theme key" {
            { New-HTMLEmailBody @script:baseParams -Theme @{ UNKNOWN_KEY = '#000000' } -WarningAction Stop } |
                Should -Throw
        }
    }
}
