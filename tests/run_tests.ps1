param(
    [Parameter(Mandatory=$true)][string]$GccRoot,
    [Parameter(Mandatory=$true)][string]$Clang,
    [string]$OutputDir = (Join-Path $env:TEMP ('obfusheader-tests-' + [guid]::NewGuid().ToString('N')))
)
$ErrorActionPreference = 'Stop'
$GccRoot = (Resolve-Path -LiteralPath $GccRoot).Path
$Clang = (Resolve-Path -LiteralPath $Clang).Path
$repo = Split-Path $PSScriptRoot -Parent
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$env:TEMP = $OutputDir
$env:TMP = $OutputDir
$env:PATH = "$GccRoot\bin;$env:PATH"
$gccLib = (Get-ChildItem -LiteralPath "$GccRoot\lib\gcc\x86_64-w64-mingw32" -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName
$cppHeaders = "$gccLib\include\c++"
$clangFlags = @('--target=x86_64-w64-windows-gnu', "--sysroot=$GccRoot", "-B$GccRoot\bin", "-L$gccLib", '-nodefaultlibs', '-isystem', $cppHeaders, '-isystem', "$cppHeaders\x86_64-w64-mingw32")
$libraries = @('-lstdc++','-lmingw32','-lgcc','-lmingwex','-lmsvcrt','-lkernel32','-lpthread','-ladvapi32','-lshell32','-luser32')
$cases = @(
    @{Name='O0'; Flags=@('-O0')},
    @{Name='O2'; Flags=@('-O2')},
    @{Name='O3'; Flags=@('-O3')},
    @{Name='Os'; Flags=@('-Os')},
    @{Name='lto'; Flags=@('-O3','-flto')},
    @{Name='minimal'; Flags=@('-O3','-flto','-DCFLOW_BRANCHING=0','-DCFLOW_CONST_DECRYPTION=0','-DCFLOW_ASM_JUNK=0','-DJUNK_ASM=0','-DVAULT_CHECK=0')},
    @{Name='constexpr'; Flags=@('-O2','-DCFLOW_ASM_JUNK=0')},
    @{Name='tls'; Flags=@('-O2','-DCONST_ENCRYPT_MODE=1')},
    @{Name='manual'; Flags=@('-O2','-DIMPORT_RESOLVER=1')},
    @{Name='api'; Flags=@('-O2','-DIMPORT_RESOLVER=2')},
    @{Name='uncached'; Flags=@('-O2','-DIMPORT_CACHE=0')},
    @{Name='no-clear'; Flags=@('-O2','-DCONST_CLEAR=0')},
    @{Name='slots'; Flags=@('-O2','-DVAULT_SLOTS=1','-DCALL_SLOTS=2')},
    @{Name='cpp17'; Flags=@('-O2','-std=c++17')},
    @{Name='cpp20-constexpr'; Flags=@('-O2','-std=c++20','-DCFLOW_ASM_JUNK=0')}
)
$rows = @()
$fixture = Join-Path $OutputDir 'obf_fixture.dll'
& "$GccRoot\bin\g++.exe" -shared (Join-Path $PSScriptRoot 'resolver_fixture.cpp') '-Wl,--export-all-symbols' -o $fixture > "$OutputDir\fixture.log" 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Failed to build resolver fixture DLL' }
foreach ($compilerName in @('gcc','clang')) {
    $compiler = if ($compilerName -eq 'gcc') { "$GccRoot\bin\g++.exe" } else { $Clang }
    & $compiler --version | Select-Object -First 1 | Out-File -Append "$OutputDir\versions.txt"
    foreach ($case in $cases) {
        # w64devkit GCC builds can intentionally omit LTO support.
        if ($compilerName -eq 'gcc' -and $case.Name -eq 'lto') {
            $probe = Join-Path $OutputDir 'lto-capability.cpp'
            [IO.File]::WriteAllText($probe, 'int main() { return 0; }')
            & $compiler -flto $probe -o "$OutputDir\lto-capability.exe" > "$OutputDir\lto-capability.log" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host 'gcc LTO unavailable (see lto-capability.log); minimal case runs without LTO'
                $gccHasLto = $false
                continue
            }
            $gccHasLto = $true
        }
        foreach ($source in @('selftest','leak_probe','hardening','polymorphism','asm_regression')) {
            # The concurrency test calls loader APIs to establish its expected result.
            $exe = Join-Path $OutputDir "$compilerName-$($case.Name)-$source.exe"
            $log = "$exe.build.log"
            $arguments = @('-std=c++14','-Wall','-Wextra','-Werror','-DOBF_SEED=123456789') + $case.Flags
            if ($compilerName -eq 'gcc' -and $case.Name -eq 'minimal' -and !$gccHasLto) { $arguments = @($arguments | Where-Object { $_ -ne '-flto' }) }
            if ($compilerName -eq 'clang') { $arguments += $clangFlags }
            $arguments += @((Join-Path $PSScriptRoot "$source.cpp"),'-o',$exe)
            if ($compilerName -eq 'clang') { $arguments += $libraries }
            & $compiler @arguments > $log 2>&1
            if ($LASTEXITCODE -ne 0) { throw "Compile failed: $exe (see $log)" }
            $runArguments = @()
            if ($source -eq 'hardening') { $runArguments = @($fixture) }
            & node (Join-Path $PSScriptRoot 'run_binary.mjs') $exe "$exe.run.log" @runArguments
            if ($LASTEXITCODE -ne 0) { throw "Runtime failed: $exe" }
            if ($source -eq 'leak_probe') {
                $bytes = [IO.File]::ReadAllBytes($exe)
                $ascii = [Text.Encoding]::ASCII.GetString($bytes)
                foreach ($marker in @('LEAKPROBE_MARKER_ONE','LEAKPROBE MARKER TWO')) {
                    if ($ascii.Contains($marker)) { throw "Plaintext leak: $exe ($marker)" }
                    if (!(Get-Content -Raw "$exe.run.log").Contains($marker)) { throw "Incorrect decryption: $exe" }
                }
                # UTF-16 on Windows (also scan UTF-32 for portable test reuse).
                foreach ($encoding in @([Text.Encoding]::Unicode,[Text.Encoding]::UTF32)) {
                    $encoded = [Text.Encoding]::ASCII.GetString($encoding.GetBytes('WIDE_LEAKPROBE_MARKER'))
                    if ($ascii.Contains($encoded)) { throw "Wide plaintext leak: $exe" }
                }
                if (!(Get-Content -Raw "$exe.run.log").Contains('WIDE_LEAKPROBE_MARKER')) { throw "Incorrect wide decryption: $exe" }
            }
            $rows += [pscustomobject]@{Compiler=$compilerName; Case=$case.Name; Source=$source; Result='PASS'}
        }
        Write-Host "$compilerName $($case.Name): behavior, concurrency and plaintext scan PASS"
    }
}
$rows | Export-Csv -NoTypeInformation -Path "$OutputDir\results.csv"
Write-Host "Passed $($rows.Count) builds. Artifacts: $OutputDir"
