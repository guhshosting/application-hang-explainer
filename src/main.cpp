#include "ahe.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
namespace {
void output(HANDLE h, const std::string &bytes) {
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        const int count =
            MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
        std::wstring wide(static_cast<size_t>(count), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), wide.data(), count);
        size_t pos = 0;
        while (pos < wide.size()) {
            DWORD written = 0;
            const DWORD chunk = static_cast<DWORD>(std::min<size_t>(wide.size() - pos, 16000));
            if (!WriteConsoleW(h, wide.data() + pos, chunk, &written, nullptr) || !written)
                throw std::runtime_error("Console output failed");
            pos += written;
        }
    } else {
        size_t pos = 0;
        while (pos < bytes.size()) {
            DWORD written = 0;
            const DWORD chunk = static_cast<DWORD>(std::min<size_t>(bytes.size() - pos, 65536));
            if (!WriteFile(h, bytes.data() + pos, chunk, &written, nullptr) || !written)
                throw std::runtime_error("Output failed");
            pos += written;
        }
    }
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    try {
        const auto o = ahe::parse(std::vector<std::wstring>(argv + 1, argv + argc));
        if (o.help) {
            output(
                GetStdHandle(STD_OUTPUT_HANDLE),
                "Usage: application-hang-explainer --pid <pid> [--thread <tid>] [--json]\n       application-hang-explainer --help | --version\nObserves Windows wait chains without changing target state.\nExit: 0 complete, 2 usage, 3 target exited/not found, 4 denied, 5 API failure, 6 internal failure.\n");
            return 0;
        }
        if (o.version) {
            output(GetStdHandle(STD_OUTPUT_HANDLE), "application-hang-explainer 1.0.0\n");
            return 0;
        }
        const auto r = ahe::inspect(o);
        output(GetStdHandle(STD_OUTPUT_HANDLE), o.json ? ahe::json(r) : ahe::human(r));
        return r.exit_code;
    } catch (const std::invalid_argument &e) {
        std::cerr << "Usage error: " << e.what() << '\n';
        return 2;
    } catch (const std::exception &e) {
        std::cerr << "Internal failure: " << e.what() << '\n';
        return 6;
    } catch (...) {
        std::cerr << "Unexpected internal failure\n";
        return 6;
    }
}
