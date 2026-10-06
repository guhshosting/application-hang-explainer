#include "native.hpp"
#include <utility>
namespace ahe::native {
std::uint64_t time_value(FILETIME t) {
    return (static_cast<std::uint64_t>(t.dwHighDateTime) << 32U) | t.dwLowDateTime;
}
Identity metadata(DWORD pid, HANDLE h) {
    Identity r;
    r.pid = pid;
    std::wstring buffer(32768, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (QueryFullProcessImageNameW(h, 0, buffer.data(), &size)) {
        buffer.resize(size);
        r.path = std::move(buffer);
    } else
        r.error = GetLastError();
    FILETIME c{}, e{}, k{}, u{};
    if (GetProcessTimes(h, &c, &e, &k, &u))
        r.creation = time_value(c);
    else if (!r.error)
        r.error = GetLastError();
    USHORT process = 0, native = 0;
    if (IsWow64Process2(h, &process, &native)) {
        const auto m = process == IMAGE_FILE_MACHINE_UNKNOWN ? native : process;
        switch (m) {
        case IMAGE_FILE_MACHINE_AMD64:
            r.architecture = "x64";
            break;
        case IMAGE_FILE_MACHINE_I386:
            r.architecture = "x86";
            break;
        case IMAGE_FILE_MACHINE_ARM64:
            r.architecture = "arm64";
            break;
        default:
            r.architecture = "machine_" + std::to_string(m);
        }
    } else if (!r.error)
        r.error = GetLastError();
    return r;
}
bool exited(HANDLE h) {
    FILETIME c{}, e{}, k{}, u{};
    return GetProcessTimes(h, &c, &e, &k, &u) && time_value(e) != 0;
}
} // namespace ahe::native

namespace ahe {
using native::Handle;
using native::metadata;
Identity identity(DWORD pid) {
    Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!h.valid()) {
        Identity r;
        r.pid = pid;
        r.error = GetLastError();
        return r;
    }
    return metadata(pid, h.get());
}
} // namespace ahe
