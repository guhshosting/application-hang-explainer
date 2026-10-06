#include "ahe.hpp"
#include <stdexcept>
namespace ahe {
std::string utf8(const std::wstring &s) {
    if (s.empty())
        return {};
    const int n =
        WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (!n)
        throw std::runtime_error("UTF-8 conversion failed");
    std::string r(static_cast<size_t>(n), '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), r.data(), n, nullptr, nullptr))
        throw std::runtime_error("UTF-8 conversion failed");
    return r;
}
std::string error_text(DWORD e) {
    wchar_t buffer[2048]{};
    const DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, e, 0,
                                   buffer, 2048, nullptr);
    if (!n)
        return "Windows error " + std::to_string(e);
    std::wstring message(buffer, n);
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n'))
        message.pop_back();
    return utf8(message);
}
} // namespace ahe
