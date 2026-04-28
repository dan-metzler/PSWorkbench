function New-HTMLEmailBody {
    <#
        .SYNOPSIS
        Generates an HTML email body with token replacement, theming, and optional table injection.

        .DESCRIPTION
        Builds a fully rendered HTML email string from an embedded template. Replaces content tokens
        (e.g., {{MAIN_HEADER}}, {{PARAGRAPH_INTRO}}) with parameter values, applies theme colors from
        a customizable hashtable, and optionally injects an HTML table from a PSObject array.
        Validates the logo image via Test-Base64Image and gracefully removes it if invalid.
        Returns the final HTML string for use with Send-MailMessage or similar cmdlets.

        .PARAMETER Base64ImageString
        A Base64-encoded image string (with or without data URI prefix) used as the email logo.

        .PARAMETER MainHeader
        Text replacing the {{MAIN_HEADER}} token. Displayed as the email heading.

        .PARAMETER PreviewText
        Text replacing the {{PREVIEW_TEXT}} token. Used for email client preview snippets.

        .PARAMETER TeamSignOff
        Team name or sign-off text replacing the {{TEAM_SIGN_OFF}} token.

        .PARAMETER ParagraphIntro
        Introductory paragraph text replacing the {{PARAGRAPH_INTRO}} token.

        .PARAMETER FooterText
        Footer content replacing the {{FOOTER_TEXT}} token.

        .PARAMETER EmailFilterText
        Filter tag text replacing the {{EMAIL_FILTER_TEXT}} token, used for mailbox rule filtering.

        .PARAMETER Table
        Switch to enable HTML table generation and injection into the {{TABLE}} placeholder.

        .PARAMETER TableObject
        An array of PSObjects whose properties are rendered in the HTML table.
        Required when -Table is specified.

        .PARAMETER TableLayout
        Controls how the table is rendered. Defaults to RowHeaders.
        RowHeaders  — property names appear as row headers on the left; one row per property per object.
        ColumnHeaders — property names appear as column headers across the top; one row per object.

        .PARAMETER Theme
        Hashtable of color overrides. Valid keys: COLOR_PRIMARY, COLOR_PRIMARY_DARK, COLOR_BG_BODY,
        COLOR_BG_CONTENT, COLOR_BORDER_MAIN, COLOR_TEXT, COLOR_TEXT_WHITE, COLOR_FOOTER_TEXT, COLOR_FILTER_TEXT.

        .EXAMPLE
        New-HTMLEmailBody -Base64ImageString $logo -MainHeader "Request Completed" -PreviewText "Details inside." -TeamSignOff "AD Team" -ParagraphIntro "Your request has been processed." -FooterText "Internal Use Only" -EmailFilterText "[Filter]"

        .EXAMPLE
        $items = @([PSCustomObject]@{ Account = "us-svc-test" })
        New-HTMLEmailBody -Base64ImageString $logo -MainHeader "DIL Removal" -PreviewText "Summary" -TeamSignOff "AD Team" -ParagraphIntro "Accounts removed." -FooterText "Internal Use Only" -EmailFilterText "[Filter]" -Table -TableObject $items -Theme @{ COLOR_PRIMARY = '#FF0000' }

        .NOTES
        PowerShellVersion: PowerShell 5.1 or Later Recommended.
    #>
    [CmdletBinding(DefaultParameterSetName = 'NoTable')]
    param (
        [Parameter(Mandatory)]
        [string]$Base64ImageString,

        [Parameter(Mandatory)]
        [string]$MainHeader,

        [Parameter(Mandatory)]
        [string]$PreviewText,

        [Parameter(Mandatory)]
        [string]$TeamSignOff,

        [Parameter(Mandatory)]
        [string]$ParagraphIntro,

        [Parameter(Mandatory)]
        [string]$FooterText,

        [Parameter(Mandatory)]
        [string]$EmailFilterText,

        [Parameter(ParameterSetName = 'WithTable')]
        [switch]$Table,

        [Parameter(Mandatory, ParameterSetName = 'WithTable')]
        [psobject[]]$TableObject,

        [Parameter(ParameterSetName = 'WithTable')]
        [ValidateSet('RowHeaders', 'ColumnHeaders')]
        [string]$TableLayout = 'RowHeaders',

        [Parameter(HelpMessage = "Hashtable of theme colors to override defaults. Keys: COLOR_PRIMARY, COLOR_PRIMARY_DARK, COLOR_BG_BODY, COLOR_BG_CONTENT, COLOR_BORDER_MAIN, COLOR_TEXT, COLOR_TEXT_WHITE, COLOR_FOOTER_TEXT, COLOR_FILTER_TEXT")]
        [hashtable]$Theme = @{}
    )

    begin {
        $validLogo = Test-Base64Image -Base64String $Base64ImageString

        if (-Not($validLogo)) {
            Write-Warning "Provided Base64String is not a valid image."
        }

        # Default theme - override any key via the -Theme parameter
        $defaultTheme = @{
            COLOR_PRIMARY      = '#009e00'  # Headings, table header background
            COLOR_PRIMARY_DARK = '#006e00'   # Table borders, table cell text
            COLOR_BG_BODY      = '#f4f5f6'   # Page / outer background
            COLOR_BG_CONTENT   = '#ffffff'   # Main content & table background
            COLOR_BORDER_MAIN  = '#eaebed'   # Main content card border
            COLOR_TEXT         = '#000000'   # Body text, divider
            COLOR_TEXT_WHITE   = '#ffffff'   # Text on primary backgrounds
            COLOR_FOOTER_TEXT  = '#7F7F7F'   # Footer paragraph text
            COLOR_FILTER_TEXT  = '#f6f6f6'   # Near-invisible email filter tag
        }

        # Merge user overrides into defaults
        foreach ($key in $Theme.Keys) {
            if ($defaultTheme.ContainsKey($key)) {
                $defaultTheme[$key] = $Theme[$key]
            }
            else {
                Write-Warning "Unknown theme key: '$key'. Valid keys: $($defaultTheme.Keys -join ', ')"
            }
        }

        # Embedded HTML email template
        $htmlTemplate = @'
    <!doctype html>
    <html lang="en">
    <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Simple Transactional Email</title>
    <style media="all" type="text/css">
    /* ========================================
        THEME COLORS - All {{COLOR_*}} tokens
        are replaced at runtime by PowerShell,
        ======================================== */

    @media only screen and (max-width: 640px) {
        .main p,
        .main td,
        .main span {
        font-size: 16px !important;
        }

        .wrapper {
        padding: 8px !important;
        }

        .content {
        padding: 0 !important;
        }

        .container {
        padding: 0 !important;
        padding-top: 8px !important;
        width: 100% !important;
        }

        .main {
        border-left-width: 0 !important;
        border-radius: 0 !important;
        border-right-width: 0 !important;
        }

        .btn table {
        max-width: 100% !important;
        width: 100% !important;
        }

        .btn a {
        font-size: 16px !important;
        max-width: 100% !important;
        width: 100% !important;
        }
    }
    @media all {
        .ExternalClass {
        width: 100%;
        }

        .ExternalClass,
        .ExternalClass p,
        .ExternalClass span,
        .ExternalClass font,
        .ExternalClass td,
        .ExternalClass div {
        line-height: 100%;
        }

        .apple-link a {
        color: inherit !important;
        font-family: inherit !important;
        font-size: inherit !important;
        font-weight: inherit !important;
        line-height: inherit !important;
        text-decoration: none !important;
        }

        #MessageViewBody a {
        color: inherit;
        text-decoration: none;
        font-size: inherit;
        font-family: inherit;
        font-weight: inherit;
        line-height: inherit;
        }
    }

    table.GeneratedTable {
        font-family: "Calibri", sans-serif;
        font-size: .9rem;
        width: 100%;
        background-color: {{COLOR_BG_CONTENT}};
        border-collapse: collapse;
        border-width: 2px;
        border-color: {{COLOR_PRIMARY_DARK}};
        border-style: solid;
        color: {{COLOR_TEXT}};
    }

    table.GeneratedTable th {
        border-collapse: collapse;
        border-width: 2px;
        border-color: {{COLOR_PRIMARY_DARK}};
        background-color: {{COLOR_PRIMARY}};
        border-style: solid;
        color: {{COLOR_TEXT_WHITE}};
        padding: 3px 10px;
        width: 1%;
        white-space: nowrap;
        text-align: right;
    }

    table.GeneratedTable td {
        font-weight: bold;
        border-width: 2px;
        border-color: {{COLOR_PRIMARY_DARK}};
        color: {{COLOR_PRIMARY_DARK}};
        border-style: solid;
        padding: 3px;
        width: auto;
    }

    </style>
    </head>
    <body style="font-family: Calibri, sans-serif; -webkit-font-smoothing: antialiased; font-size: 16px; line-height: 1.3; -ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%; background-color: {{COLOR_BG_BODY}}; margin: 0; padding: 0;">
    <table role="presentation" border="0" cellpadding="0" cellspacing="0" class="body" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; background-color: {{COLOR_BG_BODY}}; width: 100%;" width="100%">
        <tr>
        <td style="font-family: Calibri, sans-serif; font-size: 16px; vertical-align: top;" valign="top">&nbsp;</td>
        <td class="container" style="font-family: Calibri, sans-serif; font-size: 16px; vertical-align: top; max-width: 600px; padding: 0; padding-top: 24px; width: 600px; margin: 0 auto;" width="600" valign="top">
            <div class="content" style="box-sizing: border-box; display: block; margin: 0 auto; max-width: 600px; padding: 0;">

            <!-- START CENTERED WHITE CONTAINER -->
            <span class="preheader" style="color: transparent; display: none; height: 0; max-height: 0; max-width: 0; opacity: 0; overflow: hidden; mso-hide: all; visibility: hidden; width: 0;">{{PREVIEW_TEXT}}</span>
            <table role="presentation" border="0" cellpadding="0" cellspacing="0" class="main" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; background: {{COLOR_BG_CONTENT}}; border: 1px solid {{COLOR_BORDER_MAIN}}; width: 100%;" width="100%">

                <!-- START MAIN CONTENT AREA -->
                <tr>
                <td class="wrapper" style="font-family: Calibri, sans-serif; font-size: 16px; vertical-align: top; box-sizing: border-box; padding: 24px;" valign="top">
                    <img height=37 src="{{BASE_64_LOGO}}">
                    <br><br>

                    <p style="font-family: Arial, Helvetica, sans-serif, sans-serif; font-size: 18px; font-weight: normal; margin: 0; margin-bottom: 16px; font-weight: bold; color: {{COLOR_PRIMARY}};">{{MAIN_HEADER}}</p>
                    <p style="font-family: Calibri, sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 16px;">Hello,</p>
                    <p style="font-family: Calibri, sans-serif; font-size: 14px; font-weight: normal; margin: 0; margin-bottom: 16px;">{{PARAGRAPH_INTRO}}</p>

                    <table class=MsoNormalTable border=0 cellspacing=0 cellpadding=0 width=100%>
                    <tr>
                        <td width=100% valign=top
                        style='border-bottom:solid #d0d0d0 1.0pt;'>
                        </td>
                    </tr>
                    </table>
                    <br>

                    {{TABLE}}

                    <br>

                    <p style="font-family: Calibri, sans-serif; font-size: 16px; font-weight: normal; margin: 0; margin-bottom: 16px;">Thank you,</p>
                    <p style="font-family: Calibri, sans-serif; font-size: 16px; font-weight: normal; margin: 0; margin-bottom: 16px;"><b>{{TEAM_SIGN_OFF}}</b></p>
                </td>
                </tr>

                <!-- END MAIN CONTENT AREA -->
            </table>

            <!-- START FOOTER -->
            <div class="footer" style="clear: both; padding-top: 24px; text-align: center; width: 100%;">
                <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;" width="100%">
                <tr>
                    <td class="content-block" style="font-family: Calibri, sans-serif; vertical-align: top; color: {{COLOR_FOOTER_TEXT}}; font-size: 10px; text-align: center;" valign="top" align="center">
                    <br>
                    {{FOOTER_TEXT}}
                    </td>
                </tr>
                <tr>
                    <td class="content-block powered-by" style="font-family: Calibri, sans-serif; vertical-align: top; color: {{COLOR_FOOTER_TEXT}}; font-size: 16px; text-align: center;" valign="top" align="center">
                    | <span style="color: {{COLOR_FILTER_TEXT}}; font-size: 8px; text-align: center;">{{EMAIL_FILTER_TEXT}}</span>
                    </td>
                </tr>
                </table>
            </div>

            <!-- END FOOTER -->

            <!-- END CENTERED WHITE CONTAINER --></div>
        </td>
        <td style="font-family: Calibri, sans-serif; font-size: 16px; vertical-align: top;" valign="top">&nbsp;</td>
        </tr>
    </table>
    </body>
    </html>
'@

    }

    process {

        $htmlContent = $htmlTemplate

        # Replace color tokens with theme values
        foreach ($key in $defaultTheme.Keys) {
            $htmlContent = $htmlContent.Replace("{{$key}}", $defaultTheme[$key])
        }

        # Replace or remove logo based on validation
        if ($validLogo) {
            $htmlContent = $htmlContent.Replace('{{BASE_64_LOGO}}', $Base64ImageString)
        }
        else {
            $htmlContent = $htmlContent -replace '<img height=37 src="{{BASE_64_LOGO}}">\s*<br><br>', ''
        }

        $htmlContent = $htmlContent.Replace('{{MAIN_HEADER}}', $MainHeader)
        $htmlContent = $htmlContent.Replace('{{PARAGRAPH_INTRO}}', $ParagraphIntro)
        $htmlContent = $htmlContent.Replace('{{PREVIEW_TEXT}}', $PreviewText)
        $htmlContent = $htmlContent.Replace('{{TEAM_SIGN_OFF}}', $TeamSignOff)
        $htmlContent = $htmlContent.Replace('{{FOOTER_TEXT}}', $FooterText)
        $htmlContent = $htmlContent.Replace('{{EMAIL_FILTER_TEXT}}', $EmailFilterText)

        if ($Table) {
            if ($TableLayout -eq 'ColumnHeaders') {
                $headers = $TableObject[0].PSObject.Properties.Name
                $headerRow = '<tr>' + (($headers | ForEach-Object { "<th style=`"text-align: center;`">$_</th>" }) -join '') + '</tr>'
                $dataRows = foreach ($obj in $TableObject) {
                    '<tr>' + (($obj.PSObject.Properties | ForEach-Object { "<td style=`"text-align: left;`">$($_.Value)</td>" }) -join '') + '</tr>'
                }

                $tableHtml = @"
<table class="GeneratedTable">
  <thead>
$headerRow
  </thead>
  <tbody>
$($dataRows -join "`n")
  </tbody>
</table>
"@
            }
            else {
                $rows = foreach ($obj in $TableObject) {
                    foreach ($prop in $obj.PSObject.Properties) {
                        '<tr>' +
                        "<th style=`"text-align: right;`">$($prop.Name) :</th>" +
                        "<td style=`"text-align: left;`">$($prop.Value)</td>" +
                        '</tr>'
                    }
                }

                $tableHtml = @"
<table class="GeneratedTable">
  <thead>
$($rows -join "`n")
  </thead>
</table>
"@
            }

            $htmlContent = $htmlContent.Replace('{{TABLE}}', $tableHtml)
        }
        else {
            $htmlContent = $htmlContent.Replace('{{TABLE}}', '')
        }

        Write-Output $htmlContent

    }

    end {

    }
}