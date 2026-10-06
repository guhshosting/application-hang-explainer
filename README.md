# application-hang-explainer 1.0.0

> Release context: see [qualified platforms, runtime requirements and package scope](RELEASE-QUALIFICATION.md).


A portable Windows command-line explainer for an existing local process. It uses supported Windows Wait Chain Traversal (WCT) to report observable thread waits, synchronization objects, participating threads, cross-process dependencies, and WCT deadlock evidence. It does not diagnose application bugs from a wait alone.

```text
application-hang-explainer --pid 1234
application-hang-explainer --pid 1234 --json
application-hang-explainer --pid 1234 --thread 5678
application-hang-explainer --help
application-hang-explainer --version
```

PID is authoritative. A thread selector must belong to that process in the thread snapshot. Output is Unicode (native console output, UTF-8 when redirected). No executable-name selection, monitoring, remote targets, or auto-elevation.

A wait chain alternates waiting threads and the objects or relationships preventing them from proceeding. WCT can expose certain mutex, critical-section, send-message, ALPC, COM, process, and thread waits. Supported SDK types are decoded and future values retained numerically. A single thread node can mean running or an unsupported wait; it does not establish progress. Only Windows' cycle flag produces: “Windows Wait Chain Traversal reports a deadlock in this wait chain.” A long wait alone is not a deadlock. WCT is a transient observation with limited coverage, not a debugger or hang root-cause proof. COM callbacks are not registered. GUI responsiveness is not measured.

The target is opened with `PROCESS_QUERY_LIMITED_INFORMATION`, threads with `THREAD_QUERY_LIMITED_INFORMATION`. Handles are held while querying to reduce identifier reuse races; thread ownership is checked. Enumeration and chains are not atomic. Creation time is reported as UTC Windows FILETIME ticks (100 ns since 1601-01-01). Dependent PIDs are queried once for minimal metadata; their metadata is best effort and may race PID reuse. No recursive system inspection occurs. Architecture uses `IsWow64Process2`.

WCT may require privileges unavailable to a standard user. Access-denied/protected-process results retain evidence when available. The tool does not enable debug privilege or elevate. Partial nodes and failures are explicit; missing names and metadata are not invented. Chains are capped at the SDK's 16 nodes. Synchronous WCT calls cannot be cancelled and have no application-enforced deadline; Windows controls their duration.

Application code performs only diagnostic/query operations and intentionally requests no target-process state changes. No process termination, suspension, debugging, injection, memory inspection, recovery, UI commands, or scheduling changes are implemented. No intentional network communication, hostname resolution, telemetry, updates, symbols, or helper execution occurs. WCT itself is a Windows facility; this guarantee describes application code. Test-only code deliberately creates local synchronization waits.

Human output summarizes all inspected threads and expands interesting/failed/partial chains. JSON emits only a JSON document to stdout; usage/internal diagnostics use stderr. Reports include numeric Windows error codes, target metadata, summaries, threads, chains, findings, dependencies, warnings, and limitations. `schema_version` is `1.0`, `application_version` is `1.0.0`. Additive fields may be introduced within schema 1; incompatible changes require a new major schema. Consumers should tolerate unknown fields and enum numbers. Unavailable values are null. `chains_found` counts chains with more than one node. `threads_inspected` counts attempted inspections. A successful partial inspection returns 0 if any chain evidence exists; consult summary and warnings.

| Exit | Meaning |
|---|---|
| 0 | Inspection completed with evidence; partial observations may remain |
| 2 | Usage error or requested thread absent from target snapshot |
| 3 | Target absent/exited before useful observation |
| 4 | Access denied prevented all requested inspection |
| 5 | Windows diagnostic/API failure prevented all inspection |
| 6 | Unexpected internal/output failure |

A deadlock finding does not change exit status. An error report requested with `--json` remains JSON when acquisition fails; invalid CLI and internal exceptions have no JSON report.

## Supported Windows policy

Intended for Windows 10, Windows 11, and corresponding supported Windows Server generations. Windows 8.1 and older are excluded. Build requires MSVC, CMake 3.24+, C++17, and a current Windows SDK. Runtime qualification is recorded separately in [VALIDATION.md](VALIDATION.md); intended support is not a claim that every version has been tested.

## Build, test, install

From an x64 Visual Studio developer shell:

```text
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure --timeout 40
cmake --install build --prefix install
```

`AHE_ANALYZE=ON` enables MSVC `/analyze`; `AHE_ASAN=ON` enables MSVC ASan (use RelWithDebInfo). CMake copies the installed MSVC ASan runtime beside test binaries. All targets use `/W4 /WX`. `BUILD_TESTING=OFF` excludes test code. CTest creates bounded mutex waits in its own process and a controlled helper, observes WCT deadlock and cross-process evidence, then cleans up. Test-only emergency cleanup can terminate a helper created by the test; those functions are excluded from the production target. The independent JSON test uses CMake's parser with explicit UTF-8 decoding. Install contains the CLI, README and MIT license. The Release executable statically links the MSVC runtime and can be copied for portable operation without a separate VC redistributable. See `scripts/validate.ps1` for reproducible local validation.

The linked runtime contains its own local synchronization, crash-reporting, and self-termination paths. Consequently, an import table can contain `TerminateProcess` and `IsDebuggerPresent` even though application sources implement no target mutation or debugger attachment. The safety guarantee concerns application code and the selected target; it does not promise that the utility's own runtime cannot exit or fail fast.

API references: [WCT overview](https://learn.microsoft.com/en-us/windows/win32/debug/wait-chain-traversal), [GetThreadWaitChain](https://learn.microsoft.com/en-us/windows/win32/api/wct/nf-wct-getthreadwaitchain).
