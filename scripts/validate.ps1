param([string]$DeveloperShell = 'C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\Launch-VsDevShell.ps1')
$ErrorActionPreference = 'Stop'
& $DeveloperShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
New-Item -ItemType Directory -Force artifacts | Out-Null
function Invoke-Checked([string]$Name, [scriptblock]$Action) {
 & $Action 2>&1 | Tee-Object -FilePath "artifacts/$Name.txt"
 if ($LASTEXITCODE -ne 0) { throw "$Name failed ($LASTEXITCODE)" }
}
foreach ($item in @(@('debug','Debug'), @('release','Release'), @('independent','Release'), @('analyze','Release'), @('asan','RelWithDebInfo'))) {
 $dir = "build-$($item[0])-validated"
 if ($item[0] -eq 'independent') {
  $dir = Join-Path ([IO.Path]::GetTempPath()) ('ahe-independent-' + [guid]::NewGuid().ToString('N'))
  $dir | Set-Content artifacts/independent-build-path.txt
 }
 $extra = @()
 if ($item[0] -eq 'analyze') { $extra += '-DAHE_ANALYZE=ON' }
 if ($item[0] -eq 'asan') { $extra += '-DAHE_ASAN=ON' }
 Invoke-Checked "configure-$($item[0])" { cmake -S . -B $dir -G Ninja "-DCMAKE_BUILD_TYPE=$($item[1])" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON @extra }
 Invoke-Checked "build-$($item[0])" { cmake --build $dir --clean-first }
 Invoke-Checked "ctest-$($item[0])" { ctest --test-dir $dir --output-on-failure --timeout 40 }
 if ($item[0] -eq 'independent') {
  Copy-Item -LiteralPath (Join-Path $dir 'Testing/Temporary/LastTest.log') -Destination artifacts/independent-LastTest.log
 }
}
Invoke-Checked install { cmake --install build-release-validated --prefix install }
$synthetic = & .\build-release-validated\ahe_tests.exe
$synthetic | Set-Content artifacts/synthetic.json -Encoding utf8
$synthetic | ConvertFrom-Json | Out-Null
$live = & .\build-release-validated\application-hang-explainer.exe --pid $PID --json
if ($LASTEXITCODE -ne 0) { throw 'Real process inspection failed' }
$live | Set-Content artifacts/real-process.json -Encoding utf8
$parsed = $live | ConvertFrom-Json
if ($parsed.schema_version -ne '1.0' -or $parsed.target_process.pid -ne $PID) { throw 'JSON contract mismatch' }
foreach ($entry in (Get-Content build-release-validated/compile_commands.json -Raw | ConvertFrom-Json)) {
 $name = [IO.Path]::GetFileNameWithoutExtension($entry.file)
 Invoke-Checked "tidy-$name" { & 'C:\Program Files\LLVM\bin\clang-tidy.exe' $entry.file -p build-release-validated '--checks=clang-analyzer-*,bugprone-*,performance-*,portability-*' '--header-filter=.*application-hang-explainer.*' '--warnings-as-errors=*' '--extra-arg=/EHsc' }
}
Invoke-Checked cppcheck { & 'C:\Program Files\Cppcheck\cppcheck.exe' --enable=warning,performance,portability --error-exitcode=1 --std=c++17 --platform=win64 --library=windows --inline-suppr -I include src tests }
Invoke-Checked imports { dumpbin /imports build-release-validated/application-hang-explainer.exe }
Invoke-Checked headers { dumpbin /headers build-release-validated/application-hang-explainer.exe }
& ./scripts/audit.ps1
if ($LASTEXITCODE -ne 0) { throw 'Source audit failed' }
