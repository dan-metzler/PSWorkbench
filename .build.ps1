[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Local', 'Full')]
    [string]$Type,

    [Parameter()]
    [string]$Version = $(
        $tag = git describe --tags --abbrev=0 2>$null
        if ($tag) { $tag.TrimStart('v') } else { '0.1.0' }
    )
)

<#
.SYNOPSIS
    Build orchestration script using InvokeBuild framework.

.DESCRIPTION
    This script defines the complete build pipeline for the PowerShell module project.
    It coordinates multiple build tasks: Git status validation, module compilation,
    module import verification, documentation generation, and automated testing via Pester.

.NOTES
    - Requires InvokeBuild module (dependency management for task-based builds)
    - Builds are restricted to the 'main' git branch
    - Returns exit code 0 on success; non-zero on task failures
#>

# ============================================================================
# Import Dependencies and Build Functions
# ============================================================================
#Requires -Module ModuleBuilder
#Requires -Module InvokeBuild

Import-Module InvokeBuild
. "$PSScriptRoot\Build\BuildFunctions.ps1"

# ============================================================================
# Script-Scoped Variables
# ============================================================================
# Shared across all tasks to avoid redundant module discovery and imports.
# Populated by the ModuleImport task and consumed by downstream tasks.

$script:moduleName = $null

# ============================================================================
# Define Build Tasks
# ============================================================================

task BuildModule {
    $ok = & "$PSScriptRoot\Source\ModuleBuilder.ps1" -Version $Version
    if (-not $ok) { throw 'ModuleBuilder.ps1 failed' }
}

# ============================================================================
# Task: ModuleImport
# ============================================================================
# Validates and imports the compiled module into the current session.
# Populates the script-scoped $script:moduleName variable for use by
# downstream tasks (e.g., GenerateMarkdownDocs, RunTests).
#
# Validations performed:
#   - Module manifest (.psd1) exists in the Output directory
#   - Module name is defined and non-empty in the manifest

task ModuleImport BuildModule, {
    $getPsdFile = Get-ChildItem -Path "$PSScriptRoot\Output\*.psd1" -Recurse | Select-Object -First 1

    if (-not $getPsdFile) {
        throw 'No .psd1 file found in the Output directory.'
    }

    $script:moduleName = [System.IO.Path]::GetFileNameWithoutExtension($getPsdFile.Name)

    if ([string]::IsNullOrEmpty($script:moduleName)) {
        throw 'Module name is missing in the .psd1 file. Confirm .psd1 file configuration.'
    }

    Remove-Module -Name $script:moduleName -Force -ErrorAction SilentlyContinue
    Import-Module -Name $getPsdFile.FullName -Force -ErrorAction Stop
    Write-Verbose "Imported module: $script:moduleName" -Verbose
}

# ============================================================================
# Task: GenerateMarkdownDocs
# ============================================================================
# Generates markdown documentation for all exported module functions using platyPS.
# Depends on ModuleImport to ensure $script:moduleName is populated.
# Creates function reference documentation in the Docs directory.

task GenerateMarkdownDocs ModuleImport, {
    Import-Module platyPS -ErrorAction Stop
    Write-Verbose 'Generating Function Markdown Documentation...' -Verbose

    $docsPath = "$PSScriptRoot\Docs"
    if (-not (Test-Path -Path $docsPath -PathType Container)) {
        throw "Could not find the Docs directory at $docsPath. Confirm the directory exists and try again."
    }

    $result = New-MarkdownHelp -Module $script:moduleName -OutputFolder $docsPath -Force
    if ($result) {
        Write-Verbose 'Done.' -Verbose
    }
    else {
        throw 'New-MarkdownHelp did not produce output. Check that the module exports at least one function.'
    }
}

# ============================================================================
# Task: RunTests
# ============================================================================
# Executes all Pester test suites against the compiled module.
# Discovers and runs all .Tests.ps1 files in the Tests directory.
# Validates module functionality, command exports, and parameter sets.

task RunTests ModuleImport, {
    Import-Module Pester -ErrorAction Stop

    # Remove the compiled module before Pester runs so that tests which
    # import the Source module via InModuleScope do not collide with it.
    Get-Module -Name $script:moduleName -All | Remove-Module -Force -ErrorAction SilentlyContinue

    $config = New-PesterConfiguration
    $config.Run.Path = @(
        (Join-Path -Path $PSScriptRoot -ChildPath 'Tests\Unit'),
        (Join-Path -Path $PSScriptRoot -ChildPath 'Tests\Integration')
    )
    $config.Run.Exit = $true
    $config.Output.Verbosity = 'Detailed'

    Invoke-Pester -Configuration $config
}

# ============================================================================
# Default Build Pipeline
# ============================================================================
# Defines the complete build orchestration sequence.
# Tasks execute in order; failure at any stage halts the pipeline.
#
# Execution sequence (Local):
#   1. BuildModule    - Compile and package the module
#   2. ModuleImport   - Validate and import module artifact
#   3. GenerateMarkdownDocs  - Create function documentation

# Execution sequence (Full):
#   1. BuildModule           - Compile and package the module
#   2. ModuleImport          - Validate and import module artifact
#   3. RunTests              - Verify module functionality via Pester

switch ($Type) {
    'Local' {
        Write-Verbose 'Executing local build pipeline...' -Verbose
        task . BuildModule, ModuleImport, GenerateMarkdownDocs
    }
    'Full' {
        Write-Verbose 'Executing full build pipeline...' -Verbose
        task .  BuildModule, CopyLibFiles, ModuleImport, RunTests
    }
    default {
        throw "Invalid build type specified. Use 'Local' or 'Full'."
    }
}
