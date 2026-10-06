// Test-only process creation, restricted tokens, and bounded cleanup. Never linked into the CLI.
#include "ahe.hpp"
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
namespace {
_Post_satisfies_(b) void check(bool b, const char *s) {
    if (!b)
        throw std::runtime_error(std::string(s) + ": " + std::to_string(GetLastError()));
}
struct Handle {
    HANDLE h = nullptr;
    ~Handle() {
        if (h && h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }
    Handle() = default;
    explicit Handle(HANDLE v) : h(v) {}
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
};
struct Child {
    PROCESS_INFORMATION p{};
    ~Child() {
        if (p.hProcess) {
            if (WaitForSingleObject(p.hProcess, 12000) == WAIT_TIMEOUT) {
                TerminateProcess(p.hProcess, 99);
                WaitForSingleObject(p.hProcess, 1000);
            }
            CloseHandle(p.hProcess);
        }
        if (p.hThread)
            CloseHandle(p.hThread);
    }
};
std::wstring executable() {
    std::wstring b(32768, L'\0');
    const auto n = GetModuleFileNameW(nullptr, b.data(), static_cast<DWORD>(b.size()));
    check(n != 0 && n < b.size(), "image path");
    b.resize(n);
    return b;
}
void run() {
    const auto exe = executable();
    const auto prefix = L"Local\\ahe_等待_" + std::to_wstring(GetCurrentProcessId());
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, (prefix + L"_ready").c_str()));
    Handle done(CreateEventW(nullptr, TRUE, FALSE, (prefix + L"_done").c_str()));
    check(ready.h && done.h, "events");
    Child child;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    auto cmd = L"\"" + exe + L"\" --owner " + prefix;
    check(CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                         &si, &child.p) != FALSE,
          "helper creation");
    CloseHandle(child.p.hThread);
    child.p.hThread = nullptr;
    check(WaitForSingleObject(ready.h, 3000) == WAIT_OBJECT_0, "helper readiness");
    Handle mutex(OpenMutexW(SYNCHRONIZE | MUTEX_MODIFY_STATE, FALSE, (prefix + L"_mutex").c_str()));
    check(mutex.h != nullptr, "mutex open");
    std::atomic<DWORD> tid{0};
    std::thread waiter([&]() {
        tid = GetCurrentThreadId();
        const auto s = WaitForSingleObject(mutex.h, 7000);
        if (s == WAIT_OBJECT_0 || s == WAIT_ABANDONED)
            ReleaseMutex(mutex.h);
    });
    bool cross = false, unicode = false;
    for (unsigned attempt = 0; attempt < 30 && !cross; ++attempt) {
        Sleep(25);
        ahe::Options o;
        o.pid = GetCurrentProcessId();
        o.tid = tid.load();
        const auto r = ahe::inspect(o);
        for (const auto &c : r.chains)
            for (const auto &n : c.nodes) {
                cross |= n.pid == child.p.dwProcessId;
                unicode |= n.name.find(L"等待") != std::wstring::npos;
            }
        if (cross)
            std::cout << ahe::json(r);
    }
    SetEvent(done.h);
    waiter.join();
    check(cross, "cross-process WCT participant");
    check(WaitForSingleObject(child.p.hProcess, 3000) == WAIT_OBJECT_0, "helper exit");
    ahe::Options exited;
    exited.pid = child.p.dwProcessId;
    const auto r = ahe::inspect(exited);
    check(r.exit_code == 3, "exited process");
    CloseHandle(child.p.hProcess);
    child.p.hProcess = nullptr;
    Child racing;
    auto race_command = L"\"" + exe + L"\" --short-lived";
    check(CreateProcessW(exe.c_str(), race_command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                         nullptr, &si, &racing.p) != FALSE,
          "race helper creation");
    CloseHandle(racing.p.hThread);
    racing.p.hThread = nullptr;
    bool observed_exit = false;
    for (unsigned attempt = 0; attempt < 40 && !observed_exit; ++attempt) {
        ahe::Options race;
        race.pid = racing.p.dwProcessId;
        const auto observation = ahe::inspect(race);
        check(observation.exit_code == 0 || observation.exit_code == 3 || observation.exit_code == 5,
              "process exit race documented outcome");
        observed_exit = observation.exit_code == 3;
        Sleep(5);
    }
    check(observed_exit, "process exit race detected");
    check(WaitForSingleObject(racing.p.hProcess, 3000) == WAIT_OBJECT_0, "race helper exited");
    CloseHandle(racing.p.hProcess);
    racing.p.hProcess = nullptr;
    std::cout << "Cross-process WCT and process exit verified; Unicode object name exposed=" << unicode
              << '\n';
    // A restricted token disables privileges and marks Administrators deny-only.
    Handle token;
    check(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                           &token.h) != FALSE,
          "token open");
    BYTE sid_buffer[SECURITY_MAX_SID_SIZE]{};
    DWORD sid_size = sizeof(sid_buffer);
    check(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid_buffer, &sid_size) != FALSE,
          "admin SID");
    BOOL current_admin = FALSE;
    check(CheckTokenMembership(nullptr, sid_buffer, &current_admin) != FALSE, "admin membership");
    if (!current_admin) {
        ahe::Options current;
        current.pid = GetCurrentProcessId();
        check(ahe::inspect(current).exit_code == 0, "actual non-admin self WCT");
        std::cout << "Current execution token is non-admin; self inspection verified.\n";
        return;
    }
    SID_AND_ATTRIBUTES disable{sid_buffer, 0};
    Handle restricted;
    check(CreateRestrictedToken(token.h, DISABLE_MAX_PRIVILEGE, 1, &disable, 0, nullptr, 0, nullptr,
                                &restricted.h) != FALSE,
          "restricted token");
    Child standard;
    auto command = L"\"" + exe + L"\" --restricted";
    check(CreateProcessAsUserW(restricted.h, exe.c_str(), command.data(), nullptr, nullptr, FALSE,
                               CREATE_NO_WINDOW, nullptr, nullptr, &si, &standard.p) != FALSE,
          "non-admin child");
    CloseHandle(standard.p.hThread);
    standard.p.hThread = nullptr;
    check(WaitForSingleObject(standard.p.hProcess, 10000) == WAIT_OBJECT_0, "non-admin completed");
    DWORD code = 99;
    check(GetExitCodeProcess(standard.p.hProcess, &code) && code == 0, "non-admin self inspection");
    CloseHandle(standard.p.hProcess);
    standard.p.hProcess = nullptr;
    std::cout << "Restricted non-admin token self inspection verified.\n";
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    try {
        if (argc == 2 && std::wstring(argv[1]) == L"--short-lived") {
            Sleep(25);
            return 0;
        }
        if (argc == 3 && std::wstring(argv[1]) == L"--owner") {
            const std::wstring prefix = argv[2];
            Handle mutex(CreateMutexW(nullptr, TRUE, (prefix + L"_mutex").c_str()));
            Handle ready(OpenEventW(EVENT_MODIFY_STATE, FALSE, (prefix + L"_ready").c_str()));
            Handle done(OpenEventW(SYNCHRONIZE, FALSE, (prefix + L"_done").c_str()));
            check(mutex.h && ready.h && done.h, "owner handles");
            SetEvent(ready.h);
            WaitForSingleObject(done.h, 10000);
            ReleaseMutex(mutex.h);
            return 0;
        }
        if (argc == 2 && std::wstring(argv[1]) == L"--restricted") {
            BYTE sid[SECURITY_MAX_SID_SIZE]{};
            DWORD size = sizeof(sid);
            check(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sid, &size) != FALSE, "SID");
            BOOL member = TRUE;
            check(CheckTokenMembership(nullptr, sid, &member) != FALSE && !member, "not admin");
            ahe::Options o;
            o.pid = GetCurrentProcessId();
            check(ahe::inspect(o).exit_code == 0, "restricted self WCT");
            return 0;
        }
        run();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
