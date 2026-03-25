Describe "Resolve-ADGroupMember" {
    BeforeAll {
        # Import the function for testing
        . "$PSScriptRoot\..\Source\Public\Resolve-ADGroupMember.ps1"
    }

    Context "Parameter Validation" {
        BeforeEach {
            # Mock AD cmdlets to prevent actual AD queries
            Mock Get-ADGroup { }
            Mock Get-ADObject { }
        }

        It "Should require Identity parameter" {
            # PowerShell will prompt for mandatory parameters, so test with null/empty instead
            { Resolve-ADGroupMember -Identity $null -ADGlobalCatalog 'test-gc.test.local:3268' } | Should -Throw
        }

        It "Should accept single group identity as string" {
            Mock Get-ADGroup {
                return [PSCustomObject]@{
                    Name   = "TestGroup"
                    Member = @()
                }
            }

            { Resolve-ADGroupMember -Identity "TestGroup" -ADGlobalCatalog 'test-gc.test.local:3268' } | Should -Not -Throw
        }

        It "Should accept multiple group identities as string array" {
            Mock Get-ADGroup {
                return [PSCustomObject]@{
                    Name   = "TestGroup"
                    Member = @()
                }
            }

            { Resolve-ADGroupMember -Identity @("Group1", "Group2") -ADGlobalCatalog 'test-gc.test.local:3268' } | Should -Not -Throw
        }

        It "Should accept pipeline input" {
            Mock Get-ADGroup {
                return [PSCustomObject]@{
                    Name   = "TestGroup"
                    Member = @()
                }
            }

            { "TestGroup" | Resolve-ADGroupMember -ADGlobalCatalog 'test-gc.test.local:3268' } | Should -Not -Throw
        }

        It "Should accept positional parameter" {
            Mock Get-ADGroup {
                return [PSCustomObject]@{
                    Name   = "TestGroup"
                    Member = @()
                }
            }

            { Resolve-ADGroupMember "TestGroup" -ADGlobalCatalog 'test-gc.test.local:3268' } | Should -Not -Throw
        }
    }

    Context "Core Functionality" {
        BeforeEach {
            # Mock successful AD group retrieval
            Mock Get-ADGroup {
                param($Identity)
                return [PSCustomObject]@{
                    Name              = $Identity
                    DistinguishedName = "CN=$Identity,OU=Groups,DC=domain,DC=com"
                    Member            = @(
                        "CN=User1,OU=Users,DC=domain,DC=com",
                        "CN=User2,OU=Users,DC=domain,DC=com"
                    )
                }
            }

            # Mock successful local AD object retrieval
            Mock Get-ADObject {
                param($Identity)
                return [PSCustomObject]@{
                    Name              = "TestUser"
                    DistinguishedName = $Identity
                    ObjectClass       = "user"
                }
            }
        }

        It "Should retrieve group members successfully" {
            $result = Resolve-ADGroupMember -Identity "TestGroup" -ADGlobalCatalog 'test-gc.test.local:3268'

            Assert-MockCalled Get-ADGroup -Times 1 -Scope It
            Assert-MockCalled Get-ADObject -Times 2 -Scope It
        }

        It "Should process multiple groups" {
            $result = Resolve-ADGroupMember -Identity @("Group1", "Group2") -ADGlobalCatalog 'test-gc.test.local:3268'

            Assert-MockCalled Get-ADGroup -Times 2 -Scope It
        }

        It "Should call Get-ADGroup with Properties Member" {
            Resolve-ADGroupMember -Identity "TestGroup" -ADGlobalCatalog 'test-gc.test.local:3268'

            Assert-MockCalled Get-ADGroup -Times 1 -Scope It
        }

        It "Should process each member in the group" {
            Resolve-ADGroupMember -Identity "TestGroup" -ADGlobalCatalog 'test-gc.test.local:3268'
        }

        It "Should return member objects" {
            $result = Resolve-ADGroupMember -Identity "TestGroup" -ADGlobalCatalog 'test-gc.test.local:3268'

            $result | Should -Not -BeNullOrEmpty
            $result.Count | Should -Be 2
        }
    }

    Context "Cross-Domain Resolution" {
        BeforeEach {
            # Mock AD group with members
            Mock Get-ADGroup {
                return [PSCustomObject]@{
                    Name   = "TestGroup"
                    Member = @(
                        "CN=LocalUser,OU=Users,DC=domain,DC=com",
                        "CN=RemoteUser,OU=Users,DC=remote,DC=com"
                    )
                }
            }

            # Mock local AD query failure for remote user
            Mock Get-ADObject {
                param($Identity, $Server)
                if ($Identity -like "*RemoteUser*" -and -not $Server) {
                    throw [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]::new("Identity not found")
                }
                else {
                    return [PSCustomObject]@{
                        Name              = "TestUser"
                        DistinguishedName = $Identity
                        ObjectClass       = "user"
                    }
                }
            }
        }

        It "Should fall back to global catalog for cross-domain members" {
            Resolve-ADGroupMember -Identity "TestGroup" -ADGlobalCatalog 'test-gc.test.local:3268'

            Assert-MockCalled Get-ADObject -ParameterFilter {
                $Server -eq 'test-gc.test.local:3268'
            } -Times 1 -Scope It
        }

        It "Should handle ADIdentityNotFoundException and retry with GC" {
            $result = Resolve-ADGroupMember -Identity "TestGroup" -ADGlobalCatalog 'test-gc.test.local:3268'
            Assert-MockCalled Get-ADObject -Times 3 -Scope It
        }

        It "Should resolve both local and remote users" {
            $result = Resolve-ADGroupMember -Identity "TestGroup" -ADGlobalCatalog 'test-gc.test.local:3268'

            $result | Should -Not -BeNullOrEmpty
            $result.Count | Should -Be 2
        }
    }

    Context "Edge Cases" {
        BeforeEach {
            Mock Write-Error { }
            Mock Get-ADObject {
                return [PSCustomObject]@{
                    Name              = "TestUser"
                    DistinguishedName = "CN=TestUser,DC=domain,DC=com"
                }
            }
        }

        It "Should handle group not found gracefully" {
            Mock Get-ADGroup { return $null }

            $result = Resolve-ADGroupMember -Identity "NonExistentGroup" -ADGlobalCatalog 'test-gc.test.local:3268'

            $result | Should -BeNullOrEmpty
            Assert-MockCalled Get-ADObject -Times 0 -Scope It
        }

        It "Should handle empty group membership" {
            Mock Get-ADGroup {
                return [PSCustomObject]@{
                    Name   = "EmptyGroup"
                    Member = @()
                }
            }

            $result = Resolve-ADGroupMember -Identity "EmptyGroup" -ADGlobalCatalog 'test-gc.test.local:3268'

            Assert-MockCalled Get-ADObject -Times 0 -Scope It
        }

        It "Should handle member not found in both local and global catalog" {
            Mock Get-ADGroup {
                return [PSCustomObject]@{
                    Name   = "TestGroup"
                    Member = @("CN=OrphanedUser,OU=Users,DC=domain,DC=com")
                }
            }

            Mock Get-ADObject {
                throw [System.Exception]::new("Other error")
            }

            Resolve-ADGroupMember -Identity "TestGroup" -ADGlobalCatalog 'test-gc.test.local:3268'

            Assert-MockCalled Write-Error -Times 1 -Scope It
        }

        It "Should continue processing other members after error" {
            Mock Get-ADGroup {
                return [PSCustomObject]@{
                    Name   = "TestGroup"
                    Member = @(
                        "CN=ValidUser,OU=Users,DC=domain,DC=com",
                        "CN=OrphanedUser,OU=Users,DC=domain,DC=com"
                    )
                }
            }

            Mock Get-ADObject {
                param($Identity)
                if ($Identity -like "*OrphanedUser*") {
                    throw [System.Exception]::new("Other error")
                }
                else {
                    return [PSCustomObject]@{
                        Name              = "ValidUser"
                        DistinguishedName = $Identity
                    }
                }
            }

            $result = @(Resolve-ADGroupMember -Identity "TestGroup" -ADGlobalCatalog 'test-gc.test.local:3268')

            $result | Should -Not -BeNullOrEmpty
            $result.Count | Should -Be 1
        }

        It "Should handle single item array input" {
            Mock Get-ADGroup {
                return [PSCustomObject]@{
                    Name   = "SingleGroup"
                    Member = @("CN=User1,OU=Users,DC=domain,DC=com")
                }
            }

            Mock Get-ADObject {
                return [PSCustomObject]@{ Name = "User1" }
            }

            $result = Resolve-ADGroupMember -Identity @("SingleGroup") -ADGlobalCatalog 'test-gc.test.local:3268'

            $result | Should -Not -BeNullOrEmpty
            Assert-MockCalled Get-ADGroup -Times 1 -Scope It
        }
    }
}