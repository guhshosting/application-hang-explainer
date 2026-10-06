#include "ahe.hpp"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <thread>
namespace {
_Post_satisfies_(b) void check(bool b, const char *message) {
    if (!b)
        throw std::runtime_error(message);
}
void synthetic() {
    using namespace ahe;
    check(parse({L"--pid", L"42", L"--json", L"--thread", L"12"}).tid == 12UL, "CLI valid");
    for (const auto &args : std::vector<std::vector<std::wstring>>{{},
                                                                   {L"--pid"},
                                                                   {L"--pid", L"0"},
                                                                   {L"--pid", L"-1"},
                                                                   {L"--pid", L"4294967296"},
                                                                   {L"--pid", L"1", L"--pid", L"2"},
                                                                   {L"--help", L"--json"},
                                                                   {L"--wat"}}) {
        bool rejected = false;
        try {
            (void)parse(args);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        check(rejected, "CLI rejection");
    }
    WAITCHAIN_NODE_INFO w{WctUnknownType, WctStatusUnknown, {}};
    w.ObjectType = WctThreadType;
    w.ObjectStatus = WctStatusBlocked;
    w.ThreadObject.ProcessId = 42;
    w.ThreadObject.ThreadId = 12;
    auto t = decode(w);
    check(t.pid == 42UL && t.tid == 12UL && t.name.empty(), "thread decode");
    w.ObjectType = WctMutexType;
    w.ObjectStatus = WctStatusOwned;
    wcscpy_s(w.LockObject.ObjectName, L"Local\\等待\"\n");
    auto m = decode(w);
    check(m.name == L"Local\\等待\"\n" && !m.pid, "Unicode mutex decode");
    const unsigned future_type = 900, future_status = 901;
    std::memcpy(&w.ObjectType, &future_type, sizeof(future_type));
    std::memcpy(&w.ObjectStatus, &future_status, sizeof(future_status));
    auto u = decode(w);
    check(u.type == 900 && u.status == 901 && !u.pid && u.name.empty(), "unknown union not decoded");
    check(type_name(900) == "unknown" && status_name(901) == "unknown", "unknown enums");
    Report r;
    r.target.pid = 42;
    r.target.path = L"C:\\程序\\app.exe";
    r.chains.push_back({12, 0, false, false, {}});
    explain(r);
    check(r.findings.size() == 1, "empty chain");
    r.chains[0].nodes = {t};
    explain(r);
    check(r.findings[0].code == "no_observed_relationship", "one node");
    Node other = t;
    other.pid = 99;
    other.tid = 100;
    Node wait;
    wait.type = WctThreadWaitType;
    wait.status = WctStatusOwned;
    r.chains[0].nodes = {t, wait, other, m, u};
    r.chains[0].deadlock = true;
    r.chains[0].partial = true;
    explain(r);
    check(r.findings.size() == 5, "deadlock, partial, cross process, synchronization, thread findings");
    check(r.findings[0].explanation == "Windows Wait Chain Traversal reports a deadlock in this wait chain.",
          "deadlock wording");
    r.chains.push_back({13, ERROR_ACCESS_DENIED, false, false, {}});
    r.chains.push_back({14, ERROR_PROCESS_ABORTED, false, false, {}});
    explain(r);
    const auto j = json(r);
    check(j.find("\\u000a") != std::string::npos && j.find("\\\"") != std::string::npos &&
              j.find("\"raw_type\":900") != std::string::npos &&
              j.find("\"creation_time_filetime\":null") != std::string::npos,
          "JSON escaping and metadata");
    std::cout << j;
}
void live() {
    using namespace ahe;
    Options o;
    o.pid = GetCurrentProcessId();
    auto self = inspect(o);
    check(self.exit_code == 0 && !self.chains.empty(), "self inspection");
    const HANDLE first = CreateMutexW(nullptr, FALSE, nullptr),
                 second = CreateMutexW(nullptr, FALSE, nullptr);
    const HANDLE ready1 = CreateEventW(nullptr, TRUE, FALSE, nullptr),
                 ready2 = CreateEventW(nullptr, TRUE, FALSE, nullptr),
                 go = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    check(first && second && ready1 && ready2 && go, "test handles");
    std::atomic<DWORD> tid1{0}, tid2{0};
    struct WorkerArguments {
        HANDLE own, other, ready;
        std::atomic<DWORD> *tid;
    };
    auto worker = [&](const WorkerArguments &arguments) {
        const auto own = arguments.own, other = arguments.other, ready = arguments.ready;
        auto &tid = *arguments.tid;
        tid = GetCurrentThreadId();
        if (WaitForSingleObject(own, 1000) != WAIT_OBJECT_0) {
            SetEvent(ready);
            return;
        }
        SetEvent(ready);
        if (WaitForSingleObject(go, 5000) == WAIT_OBJECT_0) {
            const auto status = WaitForSingleObject(other, 5000);
            if (status == WAIT_OBJECT_0 || status == WAIT_ABANDONED)
                ReleaseMutex(other);
        }
        ReleaseMutex(own);
    };
    std::thread a(worker, WorkerArguments{first, second, ready1, &tid1}),
        b(worker, WorkerArguments{second, first, ready2, &tid2});
    const HANDLE ready[] = {ready1, ready2};
    const DWORD ready_status = WaitForMultipleObjects(2, ready, TRUE, 2000);
    SetEvent(go);
    bool deadlock = false, sync = false;
    Report evidence;
    for (int tries = 0; tries < 20 && !deadlock; ++tries) {
        Sleep(25);
        o.tid = tid1.load();
        const auto r = inspect(o);
        for (const auto &c : r.chains) {
            deadlock |= c.deadlock;
            sync |= std::any_of(c.nodes.begin(), c.nodes.end(),
                                [](const Node &n) { return n.type == WctMutexType; });
        }
        if (deadlock)
            evidence = r;
    }
    a.join();
    b.join();
    for (HANDLE h : {first, second, ready1, ready2, go})
        CloseHandle(h);
    check(ready_status == WAIT_OBJECT_0, "workers ready");
    check(sync, "live mutex visible");
    check(deadlock, "live WCT deadlock flag");
    std::cout << json(evidence);
    o.tid = tid1.load();
    const auto gone = inspect(o);
    check(gone.exit_code == 2, "thread exit race");
    std::cout << "Self, controlled mutex wait, WCT deadlock, and exited-thread checks passed.\n";
}
} // namespace
int main(int argc, char **) {
    try {
        if (argc > 1)
            live();
        else
            synthetic();
        return 0;
    } catch (const std::exception &e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    } catch (...) {
        return 1;
    }
}
