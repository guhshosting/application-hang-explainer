#include "native.hpp"
#include <algorithm>
#include <map>
namespace ahe {
using namespace native;
Report inspect(const Options &o) {
    Report r;
    r.target.pid = o.pid;
    Handle target(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, o.pid));
    if (!target.valid()) {
        r.target.error = GetLastError();
        r.exit_code = r.target.error == ERROR_ACCESS_DENIED       ? 4
                      : r.target.error == ERROR_INVALID_PARAMETER ? 3
                                                                  : 5;
        r.warnings.push_back("Target process could not be opened: " + error_text(r.target.error));
        return r;
    }
    r.target = metadata(o.pid, target.get());
    if (exited(target.get())) {
        r.exit_code = 3;
        r.warnings.push_back("Target process exited before inspection.");
        return r;
    }
    auto snapshot = enumerate_threads(o.pid);
    if (snapshot.error) {
        r.exit_code = 5;
        r.warnings.push_back("Thread enumeration failed: " + error_text(snapshot.error));
        return r;
    }
    auto tids = std::move(snapshot.tids);
    r.enumerated = static_cast<unsigned>(tids.size());
    if (o.tid) {
        if (std::find(tids.begin(), tids.end(), *o.tid) == tids.end()) {
            r.exit_code = exited(target.get()) ? 3 : 2;
            r.warnings.push_back("Requested thread was not present in the target thread snapshot.");
            return r;
        }
        tids = {*o.tid};
    }
    if (tids.empty()) {
        r.exit_code = 3;
        r.warnings.push_back("No target threads remain.");
        return r;
    }
    Session session;
    if (!session.get()) {
        const auto e = GetLastError();
        r.exit_code = e == ERROR_ACCESS_DENIED ? 4 : 5;
        r.warnings.push_back("WCT session could not be opened: " + error_text(e));
        return r;
    }
    for (const DWORD tid : tids) {
        Chain c;
        c.tid = tid;
        if (exited(target.get())) {
            c.error = ERROR_PROCESS_ABORTED;
            r.chains.push_back(c);
            continue;
        }
        Handle thread(OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid));
        if (!thread.valid())
            c.error = GetLastError();
        else {
            const DWORD owner = GetProcessIdOfThread(thread.get());
            if (!owner)
                c.error = GetLastError();
            else if (owner != o.pid)
                c.error = ERROR_OBJECT_NOT_FOUND;
            else
                c = acquire_chain(session.get(), tid, o.pid);
        }
        r.chains.push_back(std::move(c));
    }
    bool any = false, denied = false;
    std::map<DWORD, Identity> dependencies;
    for (const auto &c : r.chains) {
        any |= !c.nodes.empty();
        denied |= c.error == ERROR_ACCESS_DENIED;
        for (const auto &n : c.nodes)
            if (n.pid && *n.pid && *n.pid != o.pid && !dependencies.count(*n.pid))
                dependencies.emplace(*n.pid, identity(*n.pid));
    }
    for (auto &d : dependencies)
        r.dependencies.push_back(std::move(d.second));
    if (exited(target.get())) {
        r.warnings.push_back(
            "Target process exited during inspection; retained observations precede its exit.");
        if (!any)
            r.exit_code = 3;
    }
    if (!any && !r.exit_code)
        r.exit_code = denied ? 4 : 5;
    if (r.target.error)
        r.warnings.push_back("Some target metadata is unavailable: " + error_text(r.target.error));
    if (std::any_of(r.chains.begin(), r.chains.end(), [](const Chain &c) { return c.partial || c.error; }))
        r.warnings.push_back(
            "Inspection is incomplete for one or more threads; consult per-thread status and error codes.");
    explain(r);
    return r;
}
} // namespace ahe
