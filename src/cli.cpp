#include "ahe.hpp"
#include <stdexcept>
namespace ahe {
namespace {
DWORD number(const std::wstring &s) {
    if (s.empty())
        throw std::invalid_argument("Missing identifier");
    std::uint64_t n = 0;
    for (const auto c : s) {
        if (c < L'0' || c > L'9')
            throw std::invalid_argument("Identifiers must be decimal integers");
        n = n * 10 + static_cast<unsigned>(c - L'0');
        if (n > MAXDWORD)
            throw std::invalid_argument("Identifier out of range");
    }
    if (!n)
        throw std::invalid_argument("Identifier must be nonzero");
    return static_cast<DWORD>(n);
}
} // namespace
Options parse(const std::vector<std::wstring> &args) {
    Options o;
    for (size_t i = 0; i < args.size(); ++i) {
        const auto &a = args[i];
        if (a == L"--pid" || a == L"--thread") {
            if (i + 1 == args.size())
                throw std::invalid_argument("Missing identifier");
            const DWORD n = number(args[++i]);
            if (a == L"--pid") {
                if (o.pid)
                    throw std::invalid_argument("Duplicate --pid");
                o.pid = n;
            } else {
                if (o.tid)
                    throw std::invalid_argument("Duplicate --thread");
                o.tid = n;
            }
        } else if (a == L"--json" && !o.json)
            o.json = true;
        else if (a == L"--help" && !o.help)
            o.help = true;
        else if (a == L"--version" && !o.version)
            o.version = true;
        else
            throw std::invalid_argument("Unknown or duplicate option");
    }
    if (o.help || o.version) {
        if (args.size() != 1)
            throw std::invalid_argument("--help and --version must be used alone");
    } else if (!o.pid)
        throw std::invalid_argument("--pid is required");
    return o;
}
} // namespace ahe
