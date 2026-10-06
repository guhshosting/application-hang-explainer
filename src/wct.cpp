// SDK 10.0.26100.0 uses _In_opt_ on DWORD_PTR Context, a value type.
// C6553 diagnoses that SDK declaration, not an application access violation.
// Keep this suppression confined to the translation unit containing the WCT call.
#pragma warning(disable : 6553)
#include "native.hpp"
#include <algorithm>
namespace ahe::native {
Chain acquire_chain(HWCT session, DWORD tid, DWORD pid) {
    Chain c;
    c.tid = tid;
    WAITCHAIN_NODE_INFO nodes[WCT_MAX_NODE_COUNT];
    for (auto &node : nodes) {
        node.ObjectType = WctUnknownType;
        node.ObjectStatus = WctStatusUnknown;
        node.LockObject = {};
    }
    DWORD count = WCT_MAX_NODE_COUNT;
    BOOL cycle = FALSE;
    const BOOL ok = GetThreadWaitChain(session, 0, WCT_OUT_OF_PROC_FLAG, tid, &count, nodes, &cycle);
    c.error = ok ? ERROR_SUCCESS : GetLastError();
    const bool usable = ok || c.error == ERROR_MORE_DATA || c.error == ERROR_TOO_MANY_THREADS;
    if (!usable)
        return c;
    c.deadlock = cycle != FALSE;
    c.partial = !ok;
    for (DWORD i = 0; i < std::min<DWORD>(count, WCT_MAX_NODE_COUNT); ++i) {
        c.nodes.push_back(decode(nodes[i]));
        const auto s = c.nodes.back().status;
        c.partial |= s == WctStatusNoAccess || s == WctStatusPidOnly || s == WctStatusPidOnlyRpcss ||
                     s == WctStatusError || s == WctStatusUnknown;
    }
    if (!c.nodes.empty() && c.nodes.front().pid.value_or(pid) != pid) {
        c.nodes.clear();
        c.deadlock = false;
        c.error = ERROR_OBJECT_NOT_FOUND;
        c.partial = false;
    }
    return c;
}
} // namespace ahe::native
