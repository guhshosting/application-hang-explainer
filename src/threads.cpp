#include "native.hpp"
#include <algorithm>
#include <tlhelp32.h>
namespace ahe::native {
ThreadSnapshot enumerate_threads(DWORD pid) {
    ThreadSnapshot r;
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot.valid()) {
        r.error = GetLastError();
        return r;
    }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    BOOL more = Thread32First(snapshot.get(), &entry);
    while (more) {
        if (entry.th32OwnerProcessID == pid)
            r.tids.push_back(entry.th32ThreadID);
        entry.dwSize = sizeof(entry);
        more = Thread32Next(snapshot.get(), &entry);
    }
    const DWORD e = GetLastError();
    if (e != ERROR_NO_MORE_FILES)
        r.error = e;
    std::sort(r.tids.begin(), r.tids.end());
    return r;
}
} // namespace ahe::native
