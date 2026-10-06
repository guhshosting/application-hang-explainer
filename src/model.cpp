#include "ahe.hpp"
#include <cstring>
namespace ahe {
std::string type_name(unsigned v) {
    switch (v) {
    case WctCriticalSectionType:
        return "critical_section";
    case WctSendMessageType:
        return "send_message";
    case WctMutexType:
        return "mutex";
    case WctAlpcType:
        return "alpc";
    case WctComType:
        return "com";
    case WctThreadWaitType:
        return "thread_wait";
    case WctProcessWaitType:
        return "process_wait";
    case WctThreadType:
        return "thread";
    case WctComActivationType:
        return "com_activation";
    case WctUnknownType:
        return "unknown";
    case WctSocketIoType:
        return "socket_io";
    case WctSmbIoType:
        return "smb_io";
    default:
        return "unknown";
    }
}
std::string status_name(unsigned v) {
    switch (v) {
    case WctStatusNoAccess:
        return "no_access";
    case WctStatusRunning:
        return "running";
    case WctStatusBlocked:
        return "blocked";
    case WctStatusPidOnly:
        return "pid_only";
    case WctStatusPidOnlyRpcss:
        return "pid_only_rpcss";
    case WctStatusOwned:
        return "owned";
    case WctStatusNotOwned:
        return "not_owned";
    case WctStatusAbandoned:
        return "abandoned";
    case WctStatusUnknown:
        return "unknown";
    case WctStatusError:
        return "error";
    default:
        return "unknown";
    }
}
Node decode(const WAITCHAIN_NODE_INFO &n) {
    Node r;
    // Read the ABI representation without evaluating an out-of-range C++ enum.
    // Future Windows versions may return values outside this SDK's enumerators.
    static_assert(sizeof(r.type) == sizeof(n.ObjectType));
    static_assert(sizeof(r.status) == sizeof(n.ObjectStatus));
    std::memcpy(&r.type, &n.ObjectType, sizeof(r.type));
    std::memcpy(&r.status, &n.ObjectStatus, sizeof(r.status));
    if (r.type == WctThreadType) {
        r.pid = n.ThreadObject.ProcessId;
        if (n.ThreadObject.ThreadId)
            r.tid = n.ThreadObject.ThreadId;
    } else if (r.type >= WctCriticalSectionType && r.type < WctMaxType) {
        size_t len = 0;
        while (len < WCT_OBJNAME_LENGTH && n.LockObject.ObjectName[len])
            ++len;
        r.name.assign(n.LockObject.ObjectName, len);
    }
    return r;
}
void explain(Report &r) {
    r.findings.clear();
    for (const auto &c : r.chains) {
        auto add = [&](const char *code, const char *text) { r.findings.push_back({c.tid, code, text}); };
        if (c.deadlock)
            add("wct_deadlock", "Windows Wait Chain Traversal reports a deadlock in this wait chain.");
        if (c.error && !c.partial)
            add(c.error == ERROR_ACCESS_DENIED ? "access_denied" : "chain_unavailable",
                "No wait chain available; see the Windows error code.");
        if (c.partial)
            add("partial_chain",
                "WCT returned incomplete information; the chain may continue beyond the visible nodes.");
        bool cross = false, sync = false, thread = false;
        for (const auto &n : c.nodes) {
            cross |= n.pid && *n.pid != r.target.pid;
            sync |= n.type == WctMutexType || n.type == WctCriticalSectionType;
            thread |= n.type == WctThreadWaitType;
        }
        if (cross)
            add("cross_process", "The observed chain includes a thread in another process.");
        if (sync)
            add("synchronization_wait", "The observed chain includes a synchronization object.");
        if (thread)
            add("thread_wait", "The observed chain includes a wait on a thread.");
        if (!c.error && c.nodes.size() <= 1)
            add("no_observed_relationship",
                "No blocked relationship was observed; unsupported waits and transient changes remain possible.");
    }
}
std::vector<std::string> limitations() {
    return {
        "WCT is a transient observation, not proof of application correctness or the cause of a hang.",
        "A wait is not automatically a deadlock. Only the WCT cycle indication is reported as deadlock evidence.",
        "WCT supports only certain wait mechanisms. One node does not prove a thread is healthy or making progress.",
        "Access restrictions, protected processes, thread exits, identifier reuse, and the 16-node WCT limit can hide relationships.",
        "Cross-process metadata is best effort and may describe a reused PID; it is not an atomic system snapshot.",
        "GUI responsiveness is not measured. COM-specific callbacks are not registered; COM visibility may be limited.",
        "Synchronous WCT calls have no application-enforced timeout and cannot be cancelled. Inspection duration depends on Windows."};
}
} // namespace ahe
