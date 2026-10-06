#ifndef AHE_NATIVE_HPP
#define AHE_NATIVE_HPP
#include "ahe.hpp"
namespace ahe::native {
class Handle {
    HANDLE h_;

  public:
    explicit Handle(HANDLE h) : h_(h) {}
    ~Handle() {
        if (h_ && h_ != INVALID_HANDLE_VALUE)
            CloseHandle(h_);
    }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    HANDLE get() const {
        return h_;
    }
    bool valid() const {
        return h_ && h_ != INVALID_HANDLE_VALUE;
    }
};
class Session {
    HWCT h_ = OpenThreadWaitChainSession(0, nullptr);

  public:
    Session() = default;
    ~Session() {
        if (h_)
            CloseThreadWaitChainSession(h_);
    }
    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;
    HWCT get() const {
        return h_;
    }
};
Identity metadata(DWORD pid, HANDLE process);
bool exited(HANDLE process);
struct ThreadSnapshot {
    std::vector<DWORD> tids;
    DWORD error = 0;
};
ThreadSnapshot enumerate_threads(DWORD pid);
Chain acquire_chain(HWCT session, DWORD tid, DWORD pid);
} // namespace ahe::native
#endif
