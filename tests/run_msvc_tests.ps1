param(
    [Parameter(Mandatory=$true)][string]$VcVarsAll,
    [string]$OutputDir = (Join-Path $env:TEMP ('obfusheader-msvc-' + [guid]::NewGuid().ToString('N'))),
    [ValidateSet('x64','x86')][string]$Architecture = 'x64',
    [switch]$Initialized
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
if (!$Initialized) {
    $pwsh = (Get-Command pwsh).Source
    foreach ($arch in @('x64','x86')) {
        $targetDir = Join-Path $OutputDir $arch
        New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
        $batch = Join-Path $OutputDir "initialize-$arch.cmd"
        $lines = @('@echo off', 'chcp 65001 >nul', "call `"$VcVarsAll`" $arch >nul", 'if errorlevel 1 exit /b 1',
            "`"$pwsh`" -NoProfile -File `"$PSCommandPath`" -Initialized -Architecture $arch -VcVarsAll `"$VcVarsAll`" -OutputDir `"$targetDir`"")
        [IO.File]::WriteAllText($batch, ($lines -join "`r`n") + "`r`n", [Text.UTF8Encoding]::new($false))
        & cmd.exe /d /c $batch
        if ($LASTEXITCODE -ne 0) { throw "MSVC $arch failed; artifacts: $targetDir" }
    }
    exit
}
$env:TEMP = $OutputDir
$env:TMP = $OutputDir
Push-Location $OutputDir
try {
    $fixture = Join-Path $OutputDir 'obf_fixture.dll'
    $export = '/EXPORT:obf_fixture'
    & cl.exe /nologo /LD /MT (Join-Path $PSScriptRoot 'resolver_fixture.cpp') "/Fo$OutputDir\fixture.obj" "/Fe$fixture" /link $export > "$OutputDir\fixture.log" 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Fixture build failed' }
    $cases = @(
        @{Name='Od'; Flags=@('/Od')},
        @{Name='O2'; Flags=@('/O2')},
        @{Name='LTCG'; Flags=@('/O2','/GL')},
        @{Name='minimal'; Flags=@('/O2','/DCFLOW_BRANCHING=0','/DCFLOW_CONST_DECRYPTION=0','/DCFLOW_ASM_JUNK=0','/DJUNK_ASM=0','/DVAULT_CHECK=0')},
        @{Name='constexpr'; Flags=@('/O2','/DCFLOW_ASM_JUNK=0')},
        @{Name='tls'; Flags=@('/O2','/DCONST_ENCRYPT_MODE=1')},
        @{Name='manual'; Flags=@('/O2','/DIMPORT_RESOLVER=1')},
        @{Name='api'; Flags=@('/O2','/DIMPORT_RESOLVER=2')},
        @{Name='uncached'; Flags=@('/O2','/DIMPORT_CACHE=0')},
        @{Name='no-clear'; Flags=@('/O2','/DCONST_CLEAR=0')},
        @{Name='cpp17'; Standard='c++17'; Flags=@('/O2')},
        @{Name='cpp20-constexpr'; Standard='c++20'; Flags=@('/O2','/DCFLOW_ASM_JUNK=0')}
    )
    $rows = @()
    foreach ($case in $cases) {
        foreach ($source in @('selftest','leak_probe','hardening','polymorphism','asm_regression')) {
            $exe = Join-Path $OutputDir "$($case.Name)-$source.exe"
            $standard = if ($case.Standard) { $case.Standard } else { 'c++14' }
            $arguments = @('/nologo',"/std:$standard",'/Zc:__cplusplus','/EHsc','/MT','/W3','/WX','/DOBF_SEED=123456789') + $case.Flags
            $arguments += @((Join-Path $PSScriptRoot "$source.cpp"),"/Fo$exe.obj","/Fe$exe","/Fd$exe.pdb")
            if ($case.Name -eq 'LTCG') { $arguments += @('/link','/LTCG') }
            & cl.exe @arguments > "$exe.build.log" 2>&1
            if ($LASTEXITCODE -ne 0) { throw "Compile failed: $exe" }
            $runArguments = @()
            if ($source -eq 'hardening') { $runArguments = @($fixture) }
            & node (Join-Path $PSScriptRoot 'run_binary.mjs') $exe "$exe.run.log" @runArguments
            if ($LASTEXITCODE -ne 0) { throw "Runtime failed: $exe" }
            if ($source -eq 'leak_probe') {
                $data = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($exe))
                $output = Get-Content -Raw "$exe.run.log"
                foreach ($marker in @('LEAKPROBE_MARKER_ONE','LEAKPROBE MARKER TWO','WIDE_LEAKPROBE_MARKER')) {
                    if (!$output.Contains($marker)) { throw "Incorrect decryption: $exe" }
                    foreach ($encoding in @([Text.Encoding]::ASCII,[Text.Encoding]::Unicode)) {
                        $encoded = [Text.Encoding]::ASCII.GetString($encoding.GetBytes($marker))
                        if ($data.Contains($encoded)) { throw "Plaintext leak: $exe ($marker)" }
                    }
                }
            }
            $rows += [pscustomobject]@{Compiler='MSVC'; Architecture=$Architecture; Case=$case.Name; Source=$source; Result='PASS'}
        }
        Write-Host "MSVC $Architecture $($case.Name): behavior, concurrency and plaintext scan PASS"
    }
    & cl.exe /nologo /std:c11 /MT /O2 /W3 /WX (Join-Path $PSScriptRoot 'c_fallback.c') "/Fo$OutputDir\c-fallback.obj" "/Fe$OutputDir\c-fallback.exe" > "$OutputDir\c-fallback.build.log" 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'C fallback compile failed' }
    & "$OutputDir\c-fallback.exe" > "$OutputDir\c-fallback.run.log" 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'C fallback failed' }
    $rows | Export-Csv -NoTypeInformation "$OutputDir\results.csv"
    Write-Host "Passed $($rows.Count) MSVC $Architecture builds and C fallback. Artifacts: $OutputDir"
} finally {
    Pop-Location
}
