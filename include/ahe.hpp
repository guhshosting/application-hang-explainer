#ifndef AHE_AHE_HPP
#define AHE_AHE_HPP
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <windows.h>
#include <wct.h>
namespace ahe {
inline constexpr char version[] = "1.0.0";
struct Options {
    DWORD pid = 0;
    std::optional<DWORD> tid;
    bool json = false, help = false, version = false;
};
Options parse(const std::vector<std::wstring> &args);
struct Identity {
    DWORD pid = 0, error = 0;
    std::wstring path;
    std::string architecture;
    std::optional<std::uint64_t> creation;
};
struct Node {
    unsigned type = 0, status = 0;
    std::optional<DWORD> pid, tid;
    std::wstring name;
};
struct Chain {
    DWORD tid = 0, error = 0;
    bool partial = false, deadlock = false;
    std::vector<Node> nodes;
};
struct Finding {
    DWORD tid = 0;
    std::string code, explanation;
};
struct Report {
    Identity target;
    std::vector<Identity> dependencies;
    std::vector<Chain> chains;
    std::vector<Finding> findings;
    std::vector<std::string> warnings;
    unsigned enumerated = 0;
    int exit_code = 0;
};
std::string type_name(unsigned value);
std::string status_name(unsigned value);
Node decode(const WAITCHAIN_NODE_INFO &node);
void explain(Report &report);
std::string utf8(const std::wstring &value);
std::string error_text(DWORD error);
Identity identity(DWORD pid);
Report inspect(const Options &options);
std::string json(const Report &report);
std::string human(const Report &report);
std::vector<std::string> limitations();
} // namespace ahe
#endif
