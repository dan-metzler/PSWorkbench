#Requires -Version 5.1

Describe "Install-Certificate" {

    BeforeAll {
        . "$PSScriptRoot\..\..\Source\Public\Install-Certificate.ps1"

        # Build a self-signed test certificate entirely in memory using .NET.
        # CertificateRequest requires .NET Framework 4.7.2+ (available on all modern
        # Windows GitHub Actions runners which ship with .NET Framework 4.8).
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=PesterInstallCertificateTest")
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $subject,
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        $script:testCert = $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddYears(1))
        $script:cerPath = Join-Path $TestDrive "test.cer"
        $script:pfxPath = Join-Path $TestDrive "test.pfx"
        $pfxPasswordPlain = "PesterTestCertPassword1!"
        $script:pfxSecurePass = ConvertTo-SecureString $pfxPasswordPlain -AsPlainText -Force
        $script:testStore = "Trusted People"
        $script:storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        $script:storeName = [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople

        # Export the generated cert to disk for use in tests
        [System.IO.File]::WriteAllBytes(
            $script:cerPath,
            $script:testCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        )
        [System.IO.File]::WriteAllBytes(
            $script:pfxPath,
            $script:testCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPasswordPlain)
        )

        # Helper: removes the test cert from CurrentUser\TrustedPeople so each test starts clean.
        # Must be defined inside BeforeAll so it is available in the run phase (not just discovery).
        function script:Remove-TestCertFromStore {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($script:storeName, $script:storeLocation)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $store.Certificates |
            Where-Object { $_.Thumbprint -eq $script:testCert.Thumbprint } |
            ForEach-Object { $store.Remove($_) }
            $store.Close()
        }

        # Helper: returns $true if the test cert is currently in CurrentUser\TrustedPeople
        function script:Test-CertInStore {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($script:storeName, $script:storeLocation)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $script:testCert.Thumbprint }
            $store.Close()
            return ($null -ne $found -and @($found).Count -gt 0)
        }
    }

    AfterAll {
        # Remove any test certificates that may remain in the store
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($script:storeName, $script:storeLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Certificates |
        Where-Object { $_.Subject -eq "CN=PesterInstallCertificateTest" } |
        ForEach-Object { $store.Remove($_) }
        $store.Close()

    }

    # -------------------------------------------------------------------
    Context "Parameter Validation" {
        # -------------------------------------------------------------------

        It "throws when CertificatePath is empty" {
            { Install-Certificate -CertificatePath "" -CertificateStore $script:testStore -ErrorAction Stop } |
            Should -Throw
        }

        It "throws when CertificateStore is empty" {
            { Install-Certificate -CertificatePath $script:cerPath -CertificateStore "" -ErrorAction Stop } |
            Should -Throw
        }

        It "throws when CertificateStore value is not in the ValidateSet" {
            { Install-Certificate -CertificatePath $script:cerPath -CertificateStore "NotARealStore" -ErrorAction Stop } |
            Should -Throw
        }

        It "throws when CertificatePath does not exist on disk" {
            { Install-Certificate -CertificatePath "C:\DoesNotExist\cert.cer" -CertificateStore $script:testStore } |
            Should -Throw -ExpectedMessage "*Certificate file not found*"
        }

        It "throws when CertificatePath has an unsupported file extension" {
            $badExtPath = Join-Path $TestDrive "test.xyz"
            New-Item -Path $badExtPath -ItemType File -Force | Out-Null

            { Install-Certificate -CertificatePath $badExtPath -CertificateStore $script:testStore } |
            Should -Throw -ExpectedMessage "*Unsupported certificate file extension*"
        }

        It "throws when CertificatePath has no file extension at all" {
            $noExtPath = Join-Path $TestDrive "testnoext"
            New-Item -Path $noExtPath -ItemType File -Force | Out-Null

            { Install-Certificate -CertificatePath $noExtPath -CertificateStore $script:testStore } |
            Should -Throw -ExpectedMessage "*has no file extension*"
        }

        It "throws when CertificatePath is a malformed URL" {
            { Install-Certificate -CertificatePath "httpXXX://example.com/cert.cer" -CertificateStore $script:testStore } |
            Should -Throw -ExpectedMessage "*Invalid URL format*"
        }

    }

    # -------------------------------------------------------------------
    Context "CER Installation" {
        # -------------------------------------------------------------------

        BeforeEach { Remove-TestCertFromStore }
        AfterEach { Remove-TestCertFromStore }

        It "installs a CER file into CurrentUser\Trusted People without error" {
            { Install-Certificate -CertificatePath $script:cerPath -CertificateStore $script:testStore } |
            Should -Not -Throw
        }

        It "installs a CER file and the certificate is present in the store afterwards" {
            Install-Certificate -CertificatePath $script:cerPath -CertificateStore $script:testStore

            Test-CertInStore | Should -BeTrue
        }

        It "does not throw when the certificate already exists and OverwriteExisting is not specified" {
            Install-Certificate -CertificatePath $script:cerPath -CertificateStore $script:testStore

            { Install-Certificate -CertificatePath $script:cerPath -CertificateStore $script:testStore } |
            Should -Not -Throw
        }

        It "still has exactly one copy of the certificate after a duplicate install without OverwriteExisting" {
            Install-Certificate -CertificatePath $script:cerPath -CertificateStore $script:testStore
            Install-Certificate -CertificatePath $script:cerPath -CertificateStore $script:testStore

            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($script:storeName, $script:storeLocation)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $matchCount = @($store.Certificates | Where-Object { $_.Thumbprint -eq $script:testCert.Thumbprint }).Count
            $store.Close()

            $matchCount | Should -Be 1
        }

        It "replaces the existing certificate when OverwriteExisting is specified" {
            Install-Certificate -CertificatePath $script:cerPath -CertificateStore $script:testStore

            { Install-Certificate -CertificatePath $script:cerPath -CertificateStore $script:testStore -OverwriteExisting } |
            Should -Not -Throw
        }

        It "has exactly one copy of the certificate in the store after an overwrite" {
            Install-Certificate -CertificatePath $script:cerPath -CertificateStore $script:testStore
            Install-Certificate -CertificatePath $script:cerPath -CertificateStore $script:testStore -OverwriteExisting

            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($script:storeName, $script:storeLocation)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $matchCount = @($store.Certificates | Where-Object { $_.Thumbprint -eq $script:testCert.Thumbprint }).Count
            $store.Close()

            $matchCount | Should -Be 1
        }

    }

    # -------------------------------------------------------------------
    Context "PFX Installation" {
        # -------------------------------------------------------------------

        BeforeEach { Remove-TestCertFromStore }
        AfterEach { Remove-TestCertFromStore }

        It "installs a password-protected PFX without error" {
            { Install-Certificate -CertificatePath $script:pfxPath -CertificateStore $script:testStore -CertificatePassword $script:pfxSecurePass } |
            Should -Not -Throw
        }

        It "installs a password-protected PFX and the certificate is present in the store" {
            Install-Certificate -CertificatePath $script:pfxPath -CertificateStore $script:testStore -CertificatePassword $script:pfxSecurePass

            Test-CertInStore | Should -BeTrue
        }

        It "throws when a PFX requiring a password is given no password" {
            { Install-Certificate -CertificatePath $script:pfxPath -CertificateStore $script:testStore } |
            Should -Throw
        }

        It "throws when a PFX is given the wrong password" {
            $wrongPass = ConvertTo-SecureString "WrongPassword999!" -AsPlainText -Force

            { Install-Certificate -CertificatePath $script:pfxPath -CertificateStore $script:testStore -CertificatePassword $wrongPass } |
            Should -Throw
        }

        It "replaces the existing PFX certificate when OverwriteExisting is specified" {
            Install-Certificate -CertificatePath $script:pfxPath -CertificateStore $script:testStore -CertificatePassword $script:pfxSecurePass

            { Install-Certificate -CertificatePath $script:pfxPath -CertificateStore $script:testStore -CertificatePassword $script:pfxSecurePass -OverwriteExisting } |
            Should -Not -Throw
        }

        It "has exactly one copy of the PFX certificate in the store after an overwrite" {
            Install-Certificate -CertificatePath $script:pfxPath -CertificateStore $script:testStore -CertificatePassword $script:pfxSecurePass
            Install-Certificate -CertificatePath $script:pfxPath -CertificateStore $script:testStore -CertificatePassword $script:pfxSecurePass -OverwriteExisting

            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($script:storeName, $script:storeLocation)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $matchCount = @($store.Certificates | Where-Object { $_.Thumbprint -eq $script:testCert.Thumbprint }).Count
            $store.Close()

            $matchCount | Should -Be 1
        }
    }
}