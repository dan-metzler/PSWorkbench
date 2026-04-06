function Install-Certificate {
    <#
    .SYNOPSIS
        Writes a certificate file into a Windows certificate store.

    .DESCRIPTION
        Accepts a filesystem path or HTTPS URL pointing to a certificate file (PFX, CER,
        SST, P7B, or PEM) and writes it into the target Windows certificate store.

        The destination store location is resolved automatically from the execution context.
        Processes running as NT AUTHORITY\SYSTEM write to LocalMachine; all other contexts
        write to the CurrentUser store of the calling user.

        Certificate collections (PFX, P7B, SST) are always committed as a unit to a single
        store. To route individual certificates from a collection into different stores,
        split the collection upstream and invoke this function once per certificate.

    .PARAMETER CertificatePath
        Filesystem path or HTTPS URL to the source certificate file.
        Accepted extensions: .pfx  .cer  .sst  .p7b  .pem

    .PARAMETER CertificateStore
        Target store identified by its Windows-friendly name. Must be one of:
            Personal
            Trusted Root Certification Authorities
            Third-Party Root Certification Authorities
            Trusted Publisher
            Intermediate Certification Authorities
            Untrusted Certificates
            Trusted People
            Other People

    .PARAMETER CertificatePassword
        SecureString password required to open the certificate file, if one is set.

    .PARAMETER OverwriteExisting
        Before writing, remove any certificate already present in the target store whose
        thumbprint matches the incoming certificate. Without this switch, a matching
        thumbprint causes the function to return without making any changes.

    .EXAMPLE
        $pw = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force
        Install-Certificate -CertificatePath 'C:\Certs\internal-ca.pfx' -CertificateStore 'Personal' -CertificatePassword $pw

    .EXAMPLE
        Install-Certificate -CertificatePath 'C:\Certs\root-ca.cer' -CertificateStore 'Trusted Root Certification Authorities' -OverwriteExisting

    .NOTES
        Execution context determines the store location written to:
          NT AUTHORITY\SYSTEM  ->  LocalMachine
          All other users      ->  CurrentUser
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificatePath,

        [Parameter(Mandatory)]
        [ValidateSet(
            "Personal",
            "Trusted Root Certification Authorities",
            "Third-Party Root Certification Authorities",
            "Trusted Publisher",
            "Intermediate Certification Authorities",
            "Untrusted Certificates",
            "Trusted People",
            "Other People"
        )]
        [string]$CertificateStore,

        [Parameter()]
        [SecureString]$CertificatePassword,

        [Parameter()]
        [switch]$OverwriteExisting
    )

    begin {

        function Test-IsSystemAccount {
            $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            return $currentIdentity.Name -like "NT AUTHORITY*" -or $currentIdentity.IsSystem
        }

        function Invoke-CertificateDownload {
            param (
                [Parameter(Mandatory)]
                [string]$SourceUrl,

                [Parameter(Mandatory)]
                [string]$DestinationPath,

                [Parameter()]
                [int]$MaxAttempts = 3,

                [Parameter()]
                [switch]$SkipDelay
            )

            Write-Verbose "Downloading certificate from '$SourceUrl'"

            $supportedTls = [enum]::GetValues('Net.SecurityProtocolType')
            if (($supportedTls -contains 'Tls13') -and ($supportedTls -contains 'Tls12')) {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
            }
            elseif ($supportedTls -contains 'Tls12') {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            }
            else {
                Write-Warning "TLS 1.2 and TLS 1.3 are not supported on this system. The download may fail."
            }

            $attempt = 1
            while ($attempt -le $MaxAttempts) {
                if (-not $SkipDelay) {
                    $delaySecs = Get-Random -Minimum 3 -Maximum 15
                    Write-Verbose "Waiting $delaySecs seconds before attempt $attempt."
                    Start-Sleep -Seconds $delaySecs
                }

                Write-Verbose "Download attempt $attempt of $MaxAttempts"

                $previousProgress = $ProgressPreference
                $ProgressPreference = 'SilentlyContinue'
                try {
                    if ($PSVersionTable.PSVersion.Major -lt 4) {
                        $webClient = [System.Net.WebClient]::new()
                        $webClient.DownloadFile($SourceUrl, $DestinationPath)
                    }
                    else {
                        Invoke-WebRequest -Uri $SourceUrl -OutFile $DestinationPath -MaximumRedirection 10 -UseBasicParsing
                    }
                    $fileExists = Test-Path -Path $DestinationPath -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Warning "Download attempt $attempt failed: $($_.Exception.Message)"
                    if (Test-Path -Path $DestinationPath -ErrorAction SilentlyContinue) {
                        Remove-Item -Path $DestinationPath -Force -Confirm:$false -ErrorAction SilentlyContinue
                    }
                    $fileExists = $false
                }

                $ProgressPreference = $previousProgress

                if ($fileExists) {
                    $attempt = $MaxAttempts
                }
                else {
                    Write-Warning "Download attempt $attempt did not produce a file."
                }

                $attempt++
            }

            if (-not (Test-Path $DestinationPath)) {
                throw "Failed to download certificate from '$SourceUrl'. Verify the URL is accessible and the certificate exists at that location."
            }

            return $DestinationPath
        }

        function ConvertTo-PlainText {
            # Converts a SecureString to a plain-text string via BSTR, then immediately zeroes the BSTR.
            # The returned string lives in managed memory and cannot be zeroed, so keep its lifetime as short as possible.
            param (
                [Parameter(Mandatory)]
                [SecureString]$SecureValue
            )
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
            try {
                return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }

        # Map the friendly store name to the .NET StoreName enum value
        $storeName = switch ($CertificateStore) {
            "Personal" { [System.Security.Cryptography.X509Certificates.StoreName]::My }
            "Trusted Root Certification Authorities" { [System.Security.Cryptography.X509Certificates.StoreName]::Root }
            "Third-Party Root Certification Authorities" { [System.Security.Cryptography.X509Certificates.StoreName]::AuthRoot }
            "Trusted Publisher" { [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher }
            "Intermediate Certification Authorities" { [System.Security.Cryptography.X509Certificates.StoreName]::CertificateAuthority }
            "Untrusted Certificates" { [System.Security.Cryptography.X509Certificates.StoreName]::Disallowed }
            "Trusted People" { [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople }
            "Other People" { [System.Security.Cryptography.X509Certificates.StoreName]::AddressBook }
        }
    }

    process {

        # Stage the certificate to a unique temp path to avoid file collisions
        $certGuid = [System.Guid]::NewGuid().Guid
        $certTempPath = "$env:TEMP\cert_$certGuid"

        if ($CertificatePath -like "*.*") {
            $fileExtension = $CertificatePath.Split(".")[-1].ToLower()
            switch ($fileExtension) {
                "pfx" { $certTempPath += ".pfx" }
                "cer" { $certTempPath += ".cer" }
                "sst" { $certTempPath += ".sst" }
                "p7b" { $certTempPath += ".p7b" }
                "pem" { $certTempPath += ".pem" }
                default {
                    throw "Unsupported certificate file extension '.$fileExtension'. Supported formats: pfx, cer, pem, sst, p7b."
                }
            }
        }
        else {
            throw "Certificate path '$CertificatePath' has no file extension. Supported formats: pfx, cer, pem, sst, p7b."
        }

        # Obtain the certificate file - download if a URL was provided, otherwise copy locally
        if ($CertificatePath -like "http*") {
            if ($CertificatePath -notmatch "^https?://") {
                throw "Invalid URL format: '$CertificatePath'"
            }
            if ($CertificatePath -match "^http://") {
                Write-Warning "Certificate is being downloaded over an unencrypted HTTP connection."
            }
            Invoke-CertificateDownload -SourceUrl $CertificatePath -DestinationPath $certTempPath
        }
        else {
            if (-not (Test-Path $CertificatePath)) {
                throw "Certificate file not found at path '$CertificatePath'."
            }
            try {
                Copy-Item -Path (Resolve-Path -Path $CertificatePath) -Destination $certTempPath -Force
            }
            catch {
                throw "Failed to copy certificate from '$CertificatePath': $($_.Exception.Message)"
            }
        }

        # Load the certificate into a .NET object
        $certObject = $null
        $importFailed = $false

        try {
            Write-Verbose "Detecting certificate content type"
            $certContentType = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($certTempPath)
            Write-Verbose "Certificate content type: $certContentType"

            $keyFlags = if (Test-IsSystemAccount) {
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
            }
            else {
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -bor
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
            }

            switch ($certContentType) {
                "Unknown" {
                    throw "Certificate file is empty or unreadable: '$certTempPath'"
                }
                { $_ -in @("Cert", "SerializedCert") } {
                    Write-Verbose "Loading $certContentType certificate"
                    $certObject = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certTempPath)
                    Write-Verbose "Certificate loaded"
                }
                { $_ -in @("Pfx", "Pkcs12", "SerializedStore", "Pkcs7", "Authenticode") } {
                    Write-Verbose "Loading $certContentType certificate collection"
                    $certCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
                    if ($null -ne $CertificatePassword -and $CertificatePassword.Length -gt 0) {
                        # X509Certificate2Collection.Import has no SecureString overload in .NET Framework 4.x;
                        # convert via BSTR and zero it immediately after the call.
                        $plainPassword = ConvertTo-PlainText -SecureValue $CertificatePassword
                        try {
                            $certCollection.Import($certTempPath, $plainPassword, $keyFlags)
                        }
                        finally {
                            $plainPassword = $null
                        }
                    }
                    else {
                        $certCollection.Import($certTempPath)
                    }
                    $certObject = $certCollection
                    Write-Verbose "Certificate collection loaded ($($certCollection.Count) certificate(s))"
                }
                default {
                    throw "Unrecognised certificate content type: $certContentType"
                }
            }
        }
        catch {
            $importFailed = $true
        }

        # Fall back to direct password-based construction if the initial load failed
        if ($importFailed) {
            try {
                # X509Certificate2 has a native SecureString constructor - no plain-text conversion needed here.
                $certObject = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certTempPath, $CertificatePassword)
            }
            catch {
                Remove-Item -Path $certTempPath -Force -ErrorAction SilentlyContinue
                switch -Regex ($_.Exception.Message) {
                    "Cannot find the original signer" { throw "Certificate load failed: cannot find the original signer." }
                    default { throw "Failed to load certificate from '$CertificatePath': $($_.Exception.Message)" }
                }
            }
        }

        # Open the target certificate store
        $storeLocation = if (Test-IsSystemAccount) {
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        }
        else {
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        }

        try {
            $certStore = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
        }
        catch {
            throw "Failed to create certificate store object for '$CertificateStore': $($_.Exception.Message)"
        }

        try {
            $certStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
            Write-Verbose "Opened certificate store '$CertificateStore' ($storeLocation) with read/write access"
        }
        catch {
            throw "Failed to open certificate store '$CertificateStore': $($_.Exception.Message)"
        }

        # Flatten the cert object to a consistent list for thumbprint checks
        $certsToInstall = if (
            $certObject -is [System.Security.Cryptography.X509Certificates.X509Certificate2Collection] -or
            $certObject -is [System.Object[]]
        ) {
            $certObject
        }
        elseif ($certObject -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            @($certObject)
        }
        else {
            $certStore.Close()
            Remove-Item -Path $certTempPath -Force -ErrorAction SilentlyContinue
            throw "Unexpected certificate object type: $($certObject.GetType().FullName)"
        }

        # Check for existing installations and handle overwrite if requested
        foreach ($cert in $certsToInstall) {
            if ($certStore.Certificates.Thumbprint -contains $cert.Thumbprint) {
                if ($OverwriteExisting) {
                    $certStore.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint } | ForEach-Object {
                        try {
                            Write-Verbose "Removing existing certificate: $($_.FriendlyName) (Thumbprint: $($_.Thumbprint))"
                            $certStore.Remove($_)
                            Write-Verbose "Existing certificate removed"
                        }
                        catch {
                            $certStore.Close()
                            throw "Failed to remove existing certificate '$($_.FriendlyName)': $($_.Exception.Message)"
                        }
                    }
                }
                else {
                    Write-Verbose "Certificate already present in store (Thumbprint: $($cert.Thumbprint)). Specify -OverwriteExisting to replace it."
                    $certStore.Close()
                    Remove-Item -Path $certTempPath -Force -ErrorAction SilentlyContinue
                    return
                }
            }
        }

        # Install certificates into the store
        try {
            if ($certObject -is [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]) {
                $certStore.AddRange($certObject)
                $certObject | ForEach-Object {
                    Write-Verbose "Installed: $($_.FriendlyName) (Thumbprint: $($_.Thumbprint))"
                }
            }
            elseif ($certObject -is [System.Object[]]) {
                $certObject | ForEach-Object {
                    $certStore.Add($_)
                    Write-Verbose "Installed: $($_.FriendlyName) (Thumbprint: $($_.Thumbprint))"
                }
            }
            else {
                $certStore.Add($certObject)
                Write-Verbose "Installed: $($certObject.FriendlyName) (Thumbprint: $($certObject.Thumbprint))"
            }
        }
        catch {
            $certStore.Close()
            throw "Failed to install certificate into '$CertificateStore': $($_.Exception.Message)"
        }

        try {
            $certStore.Close()
            Write-Verbose "Certificate store '$CertificateStore' closed"
        }
        catch {
            Write-Warning "Failed to close certificate store '$CertificateStore': $($_.Exception.Message)"
        }

        Remove-Item -Path $certTempPath -Force -ErrorAction SilentlyContinue
        Write-Verbose "Certificate installation complete"
    }

    end {}
}