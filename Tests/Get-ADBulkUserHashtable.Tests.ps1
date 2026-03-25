Describe "Get-ADBulkUserHashtable" {
    BeforeAll {
        . "$PSScriptRoot\..\Source\Public\Get-ADBulkUserHashtable.ps1"

        Mock Write-Warning {}

        # Shared factory - builds a minimal AD user object with attributes needed for matching
        function New-MockADUser {
            param (
                [string]$SamAccountName,
                [string]$UserPrincipalName = '',
                [string]$DisplayName = '',
                [string]$EmployeeID = '',
                [string]$DistinguishedName = '',
                [string]$Mail = ''
            )
            [PSCustomObject]@{
                SamAccountName    = $SamAccountName
                UserPrincipalName = $UserPrincipalName
                DisplayName       = $DisplayName
                EmployeeID        = $EmployeeID
                DistinguishedName = $DistinguishedName
                Mail              = $Mail
            }
        }
    }

    # -----------------------------------------------------------------------
    Context "Parameter Validation" {

        It "Requires UserList parameter" {
            { Get-ADBulkUserHashtable -UserList $null } | Should -Throw
        }

        It "Rejects empty UserList array" {
            { Get-ADBulkUserHashtable -UserList @() } | Should -Throw
        }

        It "Rejects invalid SearchBy value" {
            { Get-ADBulkUserHashtable -UserList 'jdoe' -SearchBy 'InvalidAttribute' } | Should -Throw
        }

        It "Accepts all valid SearchBy values without throwing on parameter binding" {
            $validValues = 'Auto', 'SamAccountName', 'UserPrincipalName', 'Mail', 'DisplayName', 'EmployeeID', 'DistinguishedName'
            foreach ($value in $validValues) {
                Mock Get-ADUser { return @() }
                { Get-ADBulkUserHashtable -UserList 'jdoe' -SearchBy $value -ADGlobalCatalog 'test-gc.test.local:3268' } | Should -Not -Throw
            }
        }
    }

    # -----------------------------------------------------------------------
    Context "Auto Mode - Attribute Detection" {
        BeforeEach {
            Mock Get-ADUser { return @() }
        }

        It "Detects SamAccountName for plain alphanumeric input" {
            Get-ADBulkUserHashtable -UserList 'jdoe' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $LDAPFilter -like '*(sAMAccountName=jdoe)*'
            }
        }

        It "Detects UserPrincipalName for input containing '@'" {
            Get-ADBulkUserHashtable -UserList 'jdoe@company.com' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $LDAPFilter -like '*(userPrincipalName=jdoe@company.com)*'
            }
        }

        It "Detects EmployeeID for all-digit input" {
            Get-ADBulkUserHashtable -UserList '123456' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $LDAPFilter -like '*(employeeID=123456)*'
            }
        }

        It "Detects DisplayName for input containing whitespace" {
            Get-ADBulkUserHashtable -UserList 'John Doe' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $LDAPFilter -like '*(displayName=John Doe)*'
            }
        }

        It "Detects DistinguishedName for input starting with 'CN='" {
            $dn = 'CN=John Doe,OU=Users,DC=corp,DC=com'
            Get-ADBulkUserHashtable -UserList $dn -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $LDAPFilter -like '*(distinguishedName=CN=John Doe,OU=Users,DC=corp,DC=com)*'
            }
        }

        It "Detects DistinguishedName for input starting with 'OU='" {
            $dn = 'OU=Users,DC=corp,DC=com'
            Get-ADBulkUserHashtable -UserList $dn -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $LDAPFilter -like '*(distinguishedName=OU=Users,DC=corp,DC=com)*'
            }
        }

        It "Handles mixed input list with different detected attributes" {
            Get-ADBulkUserHashtable -UserList 'jdoe', 'jdoe@company.com', 'John Doe', '99999' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $LDAPFilter -like '*(sAMAccountName=jdoe)*' -and
                $LDAPFilter -like '*(userPrincipalName=jdoe@company.com)*' -and
                $LDAPFilter -like '*(displayName=John Doe)*' -and
                $LDAPFilter -like '*(employeeID=99999)*'
            }
        }
    }

    # -----------------------------------------------------------------------
    Context "Explicit SearchBy Mode" {
        BeforeEach {
            Mock Get-ADUser { return @() }
        }

        It "Uses SamAccountName attribute when SearchBy is SamAccountName" {
            Get-ADBulkUserHashtable -UserList 'jdoe' -SearchBy 'SamAccountName' -ADGlobalCatalog 'test-gc.test.local:3268'
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $LDAPFilter -like '*(sAMAccountName=jdoe)*'
            }
        }

        It "Uses UserPrincipalName attribute when SearchBy is UserPrincipalName" {
            Get-ADBulkUserHashtable -UserList 'jdoe@company.com' -SearchBy 'UserPrincipalName' -ADGlobalCatalog 'test-gc.test.local:3268'
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $LDAPFilter -like '*(userPrincipalName=jdoe@company.com)*'
            }
        }

        It "Builds OR filter combining all supplied values" {
            Get-ADBulkUserHashtable -UserList 'user1', 'user2', 'user3' -SearchBy 'SamAccountName' -ADGlobalCatalog 'test-gc.test.local:3268'
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $LDAPFilter -like '*(sAMAccountName=user1)*' -and
                $LDAPFilter -like '*(sAMAccountName=user2)*' -and
                $LDAPFilter -like '*(sAMAccountName=user3)*'
            }
        }
    }

    # -----------------------------------------------------------------------
    Context "Primary Domain Search - All Users Found" {
        BeforeAll {
            $mockUser1 = New-MockADUser -SamAccountName 'user1'
            $mockUser2 = New-MockADUser -SamAccountName 'user2'

            Mock Get-ADUser {
                return @($mockUser1, $mockUser2)
            }
        }

        It "Returns a hashtable keyed by SamAccountName" {
            $result = Get-ADBulkUserHashtable -UserList 'user1', 'user2' -SearchBy 'SamAccountName'
            $result | Should -BeOfType [hashtable]
            $result.Keys | Should -Contain 'user1'
            $result.Keys | Should -Contain 'user2'
        }

        It "Returns correct user objects for each key" {
            $result = Get-ADBulkUserHashtable -UserList 'user1', 'user2' -SearchBy 'SamAccountName'
            $result['user1'].SamAccountName | Should -Be 'user1'
            $result['user2'].SamAccountName | Should -Be 'user2'
        }

        It "Does not call backup search when all users are found" {
            Get-ADBulkUserHashtable -UserList 'user1', 'user2' -SearchBy 'SamAccountName'
            # Only one Get-ADUser call - no backup
            Assert-MockCalled Get-ADUser -Times 1 -Scope It
        }
    }

    # -----------------------------------------------------------------------
    Context "Global Catalog Fallback - Some Users Not Found" {
        BeforeAll {
            $primaryUser = New-MockADUser -SamAccountName 'user1'
            $backupUser  = New-MockADUser -SamAccountName 'user2'

            # Primary search finds only user1
            Mock Get-ADUser {
                return @($primaryUser)
            } -ParameterFilter { $Server -ne 'test-gc.test.local:3268' }

            # Backup global catalog search finds user2
            Mock Get-ADUser {
                return @($backupUser)
            } -ParameterFilter { $Server -eq 'test-gc.test.local:3268' }
        }

        It "Makes two Get-ADUser calls when not all users found in primary" {
            Get-ADBulkUserHashtable -UserList 'user1', 'user2' -SearchBy 'SamAccountName' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 2 -Scope It
        }

        It "Backup search targets the default global catalog server" {
            Get-ADBulkUserHashtable -UserList 'user1', 'user2' -SearchBy 'SamAccountName' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $Server -eq 'test-gc.test.local:3268'
            }
        }

        It "Backup search targets a custom ADGlobalCatalog server when provided" {
            Get-ADBulkUserHashtable -UserList 'user1', 'user2' -SearchBy 'SamAccountName' `
                -ADGlobalCatalog 'custom-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $Server -eq 'custom-gc.test.local:3268'
            }
        }

        It "Returns hashtable containing users from both primary and backup searches" {
            $result = Get-ADBulkUserHashtable -UserList 'user1', 'user2' -SearchBy 'SamAccountName' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            $result | Should -BeOfType [hashtable]
            $result.Keys | Should -Contain 'user1'
            $result.Keys | Should -Contain 'user2'
        }

        It "Backup LDAP filter contains only the users not found in primary" {
            Get-ADBulkUserHashtable -UserList 'user1', 'user2' -SearchBy 'SamAccountName' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $Server -eq 'test-gc.test.local:3268' -and
                $LDAPFilter -like '*(sAMAccountName=user2)*' -and
                $LDAPFilter -notlike '*(sAMAccountName=user1)*'
            }
        }
    }

    # -----------------------------------------------------------------------
    Context "Return Value - No Users Found" {
        BeforeEach {
            Mock Get-ADUser { return @() }
        }

        It "Returns null when no users are found in primary or backup" {
            $result = Get-ADBulkUserHashtable -UserList 'ghost1' -SearchBy 'SamAccountName' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            $result | Should -BeNullOrEmpty
        }
    }

    # -----------------------------------------------------------------------
    Context "Properties Parameter" {
        BeforeEach {
            Mock Get-ADUser { return @() }
        }

        It "Passes extra Properties to Get-ADUser when specified" {
            Get-ADBulkUserHashtable -UserList 'jdoe' -SearchBy 'SamAccountName' -Properties 'Department', 'Title' -ADGlobalCatalog 'test-gc.test.local:3268'
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $Properties -contains 'Department' -and $Properties -contains 'Title'
            }
        }

        It "Auto mode injects DisplayName into Properties when DisplayName input is detected" {
            Get-ADBulkUserHashtable -UserList 'John Doe' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $Properties -contains 'DisplayName'
            }
        }

        It "Auto mode injects EmployeeID into Properties when digit input is detected" {
            Get-ADBulkUserHashtable -UserList '99999' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $Properties -contains 'EmployeeID'
            }
        }

        It "Does not inject extra Properties for SamAccountName-only inputs in Auto mode" {
            Get-ADBulkUserHashtable -UserList 'jdoe' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                -not $Properties
            }
        }

        It "Caller-supplied Properties are preserved alongside auto-injected properties" {
            Get-ADBulkUserHashtable -UserList 'John Doe' -Properties 'Title' -ADGlobalCatalog 'test-gc.test.local:3268' -Verbose 4>$null
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $Properties -contains 'DisplayName' -and $Properties -contains 'Title'
            }
        }
    }

    # -----------------------------------------------------------------------
    Context "Server Parameter" {
        BeforeEach {
            Mock Get-ADUser { return @() }
        }

        It "Passes Server parameter to Get-ADUser when specified" {
            Get-ADBulkUserHashtable -UserList 'jdoe' -SearchBy 'SamAccountName' -Server 'test-dc.test.local' -ADGlobalCatalog 'test-gc.test.local:3268'
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                $Server -eq 'test-dc.test.local'
            }
        }

        It "Does not include Server in Get-ADUser call when not specified" {
            Get-ADBulkUserHashtable -UserList 'jdoe' -SearchBy 'SamAccountName' -ADGlobalCatalog 'test-gc.test.local:3268'
            Assert-MockCalled Get-ADUser -Times 1 -Scope It -ParameterFilter {
                -not $Server
            }
        }
    }

    AfterAll {
        Remove-Item "$TestDrive\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
}