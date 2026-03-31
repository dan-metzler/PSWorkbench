Describe "Update-GenericList" {
    BeforeAll {
        . "$PSScriptRoot\..\Source\Public\Update-GenericList.ps1"
    }

    Context "Parameter Validation" {

        It "Should throw when no processing switch is provided" {
            { Update-GenericList -UserInput @("hello") } | Should -Throw
        }

        It "Should throw when both ConvertToLowercase and ConvertToUppercase are used together" {
            { Update-GenericList -UserInput @("hello") -ConvertToLowercase -ConvertToUppercase } | Should -Throw
        }

        It "Should not throw when at least one valid processing switch is provided" {
            { Update-GenericList -UserInput @("hello") -Trim } | Should -Not -Throw
        }

    }

    Context "Return Type" {

        It "Should always return a List[string]" {
            $result = Update-GenericList -UserInput @("hello", "world") -Trim
            Should -ActualValue $result -BeOfType ([System.Collections.Generic.List[string]])
        }

        It "Should return a List[string] with a single item input - not a scalar" {
            $result = Update-GenericList -UserInput @("hello") -Trim
            Should -ActualValue $result -BeOfType ([System.Collections.Generic.List[string]])
            $result.Count | Should -Be 1
        }

        It "Should return a List[string] that supports .Add()" {
            $result = Update-GenericList -UserInput @("hello") -Trim
            { $result.Add("newItem") } | Should -Not -Throw
            $result.Count | Should -Be 2
        }

        It "Should return a list with correct Count after RemoveDuplicates" {
            $result = Update-GenericList -UserInput @("hello", "hello", "world") -Trim -RemoveDuplicates
            Should -ActualValue $result -BeOfType ([System.Collections.Generic.List[string]])
            $result.Count | Should -Be 2
        }

    }

    Context "RemoveWhitespaces" {

        It "Should remove all spaces from items" {
            $result = Update-GenericList -UserInput @("h e l l o", "w o r l d") -RemoveWhitespaces
            $result[0] | Should -Be "hello"
            $result[1] | Should -Be "world"
        }

        It "Should not affect items that have no spaces" {
            $result = Update-GenericList -UserInput @("hello", "world") -RemoveWhitespaces
            $result[0] | Should -Be "hello"
            $result[1] | Should -Be "world"
        }

        It "Should remove internal spaces as well as leading and trailing spaces" {
            $result = Update-GenericList -UserInput @("  John Doe  ") -RemoveWhitespaces
            $result[0] | Should -Be "JohnDoe"
        }

    }

    Context "Trim" {

        It "Should remove leading whitespace" {
            $result = Update-GenericList -UserInput @("   hello") -Trim
            $result[0] | Should -Be "hello"
        }

        It "Should remove trailing whitespace" {
            $result = Update-GenericList -UserInput @("hello   ") -Trim
            $result[0] | Should -Be "hello"
        }

        It "Should preserve internal spaces" {
            $result = Update-GenericList -UserInput @("  John Doe  ") -Trim
            $result[0] | Should -Be "John Doe"
        }

    }

    Context "ConvertToLowercase" {

        It "Should convert all items to lowercase" {
            $result = Update-GenericList -UserInput @("HELLO", "WORLD") -ConvertToLowercase
            $result[0] | Should -Be "hello"
            $result[1] | Should -Be "world"
        }

        It "Should not change items already in lowercase" {
            $result = Update-GenericList -UserInput @("hello", "world") -ConvertToLowercase
            $result[0] | Should -Be "hello"
            $result[1] | Should -Be "world"
        }

    }

    Context "ConvertToUppercase" {

        It "Should convert all items to uppercase" {
            $result = Update-GenericList -UserInput @("hello", "world") -ConvertToUppercase
            $result[0] | Should -Be "HELLO"
            $result[1] | Should -Be "WORLD"
        }

        It "Should not change items already in uppercase" {
            $result = Update-GenericList -UserInput @("HELLO", "WORLD") -ConvertToUppercase
            $result[0] | Should -Be "HELLO"
            $result[1] | Should -Be "WORLD"
        }

    }

    Context "Combination - RemoveWhitespaces + ConvertToLowercase" {

        It "Should remove spaces and convert to lowercase" {
            $result = Update-GenericList -UserInput @("H E L L O", "W O R L D") -RemoveWhitespaces -ConvertToLowercase
            $result[0] | Should -Be "hello"
            $result[1] | Should -Be "world"
        }

    }

    Context "Combination - RemoveWhitespaces + ConvertToUppercase" {

        It "Should remove spaces and convert to uppercase" {
            $result = Update-GenericList -UserInput @("h e l l o", "w o r l d") -RemoveWhitespaces -ConvertToUppercase
            $result[0] | Should -Be "HELLO"
            $result[1] | Should -Be "WORLD"
        }

    }

    Context "Combination - Trim + ConvertToLowercase" {

        It "Should trim and convert to lowercase" {
            $result = Update-GenericList -UserInput @("  HELLO  ", "  WORLD  ") -Trim -ConvertToLowercase
            $result[0] | Should -Be "hello"
            $result[1] | Should -Be "world"
        }

        It "Should preserve internal spaces when trimming and converting to lowercase" {
            $result = Update-GenericList -UserInput @("  John Doe  ") -Trim -ConvertToLowercase
            $result[0] | Should -Be "john doe"
        }

    }

    Context "Combination - Trim + ConvertToUppercase" {

        It "Should trim and convert to uppercase" {
            $result = Update-GenericList -UserInput @("  hello  ", "  world  ") -Trim -ConvertToUppercase
            $result[0] | Should -Be "HELLO"
            $result[1] | Should -Be "WORLD"
        }

        It "Should preserve internal spaces when trimming and converting to uppercase" {
            $result = Update-GenericList -UserInput @("  john doe  ") -Trim -ConvertToUppercase
            $result[0] | Should -Be "JOHN DOE"
        }

    }

    Context "RemoveNullOrEmptyItems" {

        It "Should remove empty strings" {
            $result = Update-GenericList -UserInput @("hello", "", "world") -Trim -RemoveNullOrEmptyItems
            $result.Count | Should -Be 2
            $result | Should -Contain "hello"
            $result | Should -Contain "world"
        }

        It "Should remove whitespace-only strings" {
            $result = Update-GenericList -UserInput @("hello", "   ", "world") -Trim -RemoveNullOrEmptyItems
            $result.Count | Should -Be 2
        }

        It "Should remove null values coerced to empty string" {
            # [string[]] coerces $null to "" in PowerShell
            $result = Update-GenericList -UserInput @("hello", $null, "world") -Trim -RemoveNullOrEmptyItems
            $result.Count | Should -Be 2
        }

        It "Should return an empty list when all items are null or empty" {
            $result = Update-GenericList -UserInput @("", "  ", $null) -Trim -RemoveNullOrEmptyItems
            Should -ActualValue $result -BeOfType ([System.Collections.Generic.List[string]])
            $result.Count | Should -Be 0
        }

    }

    Context "RemoveDuplicates" {

        It "Should remove duplicate values" {
            $result = Update-GenericList -UserInput @("hello", "hello", "world") -Trim -RemoveDuplicates
            $result.Count | Should -Be 2
        }

        It "Should keep a single instance of each unique value" {
            $result = Update-GenericList -UserInput @("hello", "hello", "hello") -Trim -RemoveDuplicates
            $result.Count | Should -Be 1
            $result[0] | Should -Be "hello"
        }

        It "Should return a list with correct Count when combined with RemoveNullOrEmptyItems" {
            $result = Update-GenericList -UserInput @("hello", "hello", "", "world") -Trim -RemoveNullOrEmptyItems -RemoveDuplicates
            $result.Count | Should -Be 2
        }

        It "Should not throw when RemoveDuplicates is used on an empty collection" {
            { Update-GenericList -UserInput @() -Trim -RemoveDuplicates } | Should -Not -Throw
        }

        It "Should return an empty List when RemoveDuplicates is used on an empty collection" {
            $result = Update-GenericList -UserInput @() -Trim -RemoveDuplicates
            Should -ActualValue $result -BeOfType ([System.Collections.Generic.List[string]])
            $result.Count | Should -Be 0
        }

        It "Should not throw when RemoveDuplicates is used and all items are removed by RemoveNullOrEmptyItems" {
            { Update-GenericList -UserInput @("", $null, "  ") -Trim -RemoveNullOrEmptyItems -RemoveDuplicates } | Should -Not -Throw
        }

        It "Should return an empty List when RemoveDuplicates is used and all items are removed by RemoveNullOrEmptyItems" {
            $result = Update-GenericList -UserInput @("", $null, "  ") -Trim -RemoveNullOrEmptyItems -RemoveDuplicates
            Should -ActualValue $result -BeOfType ([System.Collections.Generic.List[string]])
            $result.Count | Should -Be 0
        }

    }

    Context "Example Scenarios from Documentation" {

        It "Example 1: RemoveWhitespaces + ConvertToLowercase + RemoveDuplicates" {
            # Input: @("  User1  ", "USER2", "user1") => @("user1", "user2")
            $result = Update-GenericList -UserInput @("  User1  ", "USER2", "user1") -RemoveWhitespaces -ConvertToLowercase -RemoveDuplicates
            $result.Count | Should -Be 2
            $result | Should -Contain "user1"
            $result | Should -Contain "user2"
        }

        It "Example 2: ConvertToUppercase + RemoveNullOrEmptyItems" {
            # Input: @("account1", "", "ACCOUNT2", $null) => @("ACCOUNT1", "ACCOUNT2")
            $result = Update-GenericList -UserInput @("account1", "", "ACCOUNT2", $null) -ConvertToUppercase -RemoveNullOrEmptyItems
            $result.Count | Should -Be 2
            $result | Should -Contain "ACCOUNT1"
            $result | Should -Contain "ACCOUNT2"
        }

        It "Example 3: Trim + RemoveDuplicates preserves internal spaces" {
            # Input: @(" John Doe ", " Jane Smith ", "Bob Jones") => @("John Doe", "Jane Smith", "Bob Jones")
            $result = Update-GenericList -UserInput @(" John Doe ", " Jane Smith ", "Bob Jones") -Trim -RemoveDuplicates
            $result.Count | Should -Be 3
            $result | Should -Contain "John Doe"
            $result | Should -Contain "Jane Smith"
            $result | Should -Contain "Bob Jones"
        }

    }

    Context "Edge Cases" {

        It "Should return an empty list when given an empty collection" {
            $result = Update-GenericList -UserInput @() -Trim
            Should -ActualValue $result -BeOfType ([System.Collections.Generic.List[string]])
            $result.Count | Should -Be 0
        }

        It "Should return a single-item list with correct Count for single input - not a scalar" {
            $result = Update-GenericList -UserInput @("hello") -ConvertToLowercase
            Should -ActualValue $result -BeOfType ([System.Collections.Generic.List[string]])
            $result.Count | Should -Be 1
            $result[0] | Should -Be "hello"
        }

        It "Should correctly index into a single-item result - not return first character" {
            $result = Update-GenericList -UserInput @("Sec-Group-Finance-Read") -Trim
            $result[0] | Should -Be "Sec-Group-Finance-Read"
            $result[0] | Should -Not -Be "S"
        }

        It "Should return a List where Count -gt 0 is true when items exist" {
            $result = Update-GenericList -UserInput @("hello") -Trim
            ($result.Count -gt 0) | Should -Be $true
        }

        It "Should return a list where Count -gt 0 is false when result is empty" {
            $result = Update-GenericList -UserInput @("") -Trim -RemoveNullOrEmptyItems
            ($result.Count -gt 0) | Should -Be $false
        }

    }
}