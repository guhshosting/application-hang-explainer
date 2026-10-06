#include "ahe.hpp"
#include <sstream>
namespace ahe {
namespace {
std::string quote(const std::string &s) {
    std::string r = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (const char ch : s) {
        const unsigned c = static_cast<unsigned char>(ch);
        if (c == '"' || c == '\\') {
            r += '\\';
            r += ch;
        } else if (c < 32) {
            r += "\\u00";
            r += hex[c >> 4U];
            r += hex[c & 15U];
        } else
            r += ch;
    }
    return r + '"';
}
template <class T> std::string optional_number(const std::optional<T> &n) {
    return n ? std::to_string(*n) : "null";
}
void process(std::ostream &s, const Identity &p) {
    s << "{\"pid\":" << p.pid << ",\"image_path\":" << (p.path.empty() ? "null" : quote(utf8(p.path)))
      << ",\"architecture\":" << (p.architecture.empty() ? "null" : quote(p.architecture))
      << ",\"creation_time_filetime\":" << optional_number(p.creation) << ",\"metadata_error\":" << p.error
      << '}';
}
void strings(std::ostream &s, const std::vector<std::string> &v) {
    s << '[';
    bool first = true;
    for (const auto &x : v) {
        if (!first)
            s << ',';
        first = false;
        s << quote(x);
    }
    s << ']';
}
struct Counts {
    size_t found = 0, deadlocks = 0, partial = 0, failed = 0;
};
Counts counts(const Report &r) {
    Counts n;
    for (const auto &c : r.chains) {
        n.found += c.nodes.size() > 1;
        n.deadlocks += c.deadlock;
        n.partial += c.partial;
        n.failed += c.error != 0 && c.nodes.empty();
    }
    return n;
}
} // namespace
std::string json(const Report &r) {
    const auto n = counts(r);
    std::ostringstream s;
    s << "{\"schema_version\":\"1.0\",\"application_version\":\"" << version
      << "\",\"exit_code\":" << r.exit_code << ",\"target_process\":";
    process(s, r.target);
    s << ",\"inspection_summary\":{\"threads_enumerated\":" << r.enumerated
      << ",\"threads_inspected\":" << r.chains.size() << ",\"chains_found\":" << n.found
      << ",\"deadlocks_reported\":" << n.deadlocks << ",\"partial_inspections\":" << n.partial
      << ",\"failed_inspections\":" << n.failed << "},\"threads\":[";
    bool first = true;
    for (const auto &c : r.chains) {
        if (!first)
            s << ',';
        first = false;
        s << "{\"tid\":" << c.tid << ",\"wct_error\":" << c.error << ",\"state\":"
          << quote(c.nodes.empty() ? "unavailable"
                   : c.partial     ? "partial"
                                   : "complete")
          << '}';
    }
    s << "],\"wait_chains\":[";
    first = true;
    for (const auto &c : r.chains) {
        if (!first)
            s << ',';
        first = false;
        s << "{\"tid\":" << c.tid << ",\"wct_error\":" << c.error
          << ",\"partial\":" << (c.partial ? "true" : "false")
          << ",\"deadlock_reported\":" << (c.deadlock ? "true" : "false") << ",\"nodes\":[";
        bool fn = true;
        for (const auto &node : c.nodes) {
            if (!fn)
                s << ',';
            fn = false;
            s << "{\"type\":" << quote(type_name(node.type)) << ",\"raw_type\":" << node.type
              << ",\"status\":" << quote(status_name(node.status)) << ",\"raw_status\":" << node.status
              << ",\"pid\":" << optional_number(node.pid) << ",\"tid\":" << optional_number(node.tid)
              << ",\"object_name\":" << (node.name.empty() ? "null" : quote(utf8(node.name))) << '}';
        }
        s << "]}";
    }
    s << "],\"cross_process_dependencies\":[";
    first = true;
    for (const auto &p : r.dependencies) {
        if (!first)
            s << ',';
        first = false;
        process(s, p);
    }
    s << "],\"findings\":[";
    first = true;
    for (const auto &f : r.findings) {
        if (!first)
            s << ',';
        first = false;
        s << "{\"tid\":" << f.tid << ",\"code\":" << quote(f.code)
          << ",\"explanation\":" << quote(f.explanation) << '}';
    }
    s << "],\"warnings\":";
    strings(s, r.warnings);
    s << ",\"limitations\":";
    strings(s, limitations());
    s << "}\n";
    return s.str();
}
std::string human(const Report &r) {
    std::ostringstream s;
    const auto n = counts(r);
    s << "application-hang-explainer " << version << "\nProcess " << r.target.pid << ": "
      << (r.target.path.empty() ? "image unavailable" : utf8(r.target.path))
      << "\nArchitecture: " << (r.target.architecture.empty() ? "unavailable" : r.target.architecture)
      << "\nCreation time (Windows FILETIME ticks): " << optional_number(r.target.creation) << '\n';
    s << "Threads inspected: " << r.chains.size() << " / " << r.enumerated << "; chains found: " << n.found
      << "; deadlocks reported: " << n.deadlocks << "; partial: " << n.partial << "; failed: " << n.failed
      << "\n\nInteresting chains:\n";
    bool interesting = false;
    for (const auto &c : r.chains) {
        if (c.nodes.size() <= 1 && !c.partial && !c.error && !c.deadlock)
            continue;
        interesting = true;
        s << "  TID " << c.tid << (c.partial ? " (partial)" : "") << '\n';
        if (c.error)
            s << "    Windows error " << c.error << ": " << error_text(c.error) << '\n';
        for (const auto &node : c.nodes) {
            s << "    " << type_name(node.type) << " [" << node.type << "] " << status_name(node.status)
              << " [" << node.status << ']';
            if (node.pid)
                s << " PID=" << *node.pid;
            if (node.tid)
                s << " TID=" << *node.tid;
            if (!node.name.empty())
                s << " name=" << quote(utf8(node.name));
            s << '\n';
        }
        for (const auto &f : r.findings)
            if (f.tid == c.tid)
                s << "    " << f.explanation << '\n';
    }
    if (!interesting)
        s << (r.chains.empty() ? "  No thread observations available.\n"
                               : "  No blocked relationship was observed. This does not prove progress.\n");
    s << "\nDeadlock evidence: " << n.deadlocks
      << " chain(s) flagged by Windows WCT.\nCross-process dependencies:\n";
    if (r.dependencies.empty())
        s << "  None observed.\n";
    for (const auto &p : r.dependencies)
        s << "  PID " << p.pid << ": " << (p.path.empty() ? "metadata unavailable" : utf8(p.path))
          << " (metadata error " << p.error << ")\n";
    s << "\nWarnings and limitations:\n";
    for (const auto &w : r.warnings)
        s << "  " << w << '\n';
    for (const auto &w : limitations())
        s << "  " << w << '\n';
    return s.str();
}
} // namespace ahe
