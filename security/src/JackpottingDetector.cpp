#include "../include/JackpottingDetector.h"
#include <openssl/sha.h>
#include <algorithm>
#include <chrono>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstdio>

using Clock = std::chrono::system_clock;

static std::string hex_encode(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        oss << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}

JackpottingDetector::JackpottingDetector(const SecurityConfig& cfg) : cfg_(cfg) {}

std::vector<std::string> JackpottingDetector::running_processes() const {
    std::vector<std::string> procs;
    DIR* d = opendir("/proc");
    if (!d) return procs;
    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        std::string pid_s(ent->d_name);
        if (!std::all_of(pid_s.begin(), pid_s.end(), ::isdigit)) continue;
        std::ifstream f("/proc/" + pid_s + "/comm");
        std::string name; if (std::getline(f, name)) procs.push_back(name);
    }
    closedir(d);
    return procs;
}

bool JackpottingDetector::scan_processes(std::vector<ThreatEvent>& out) {
    if (cfg_.allowed_processes.empty()) return false;
    for (auto& p : running_processes()) {
        bool ok = false;
        for (auto& a : cfg_.allowed_processes) if (p == a) { ok = true; break; }
        if (!ok) {
            ThreatEvent ev;
            ev.type        = ThreatType::JACK_UNKNOWN_PROCESS;
            ev.severity    = default_severity(ev.type);
            ev.machine_id  = cfg_.machine_id;
            ev.description = "Unlisted process running: " + p;
            ev.evidence    = "{\"process\":\"" + p + "\"}";
            out.push_back(ev);
        }
    }
    return !out.empty();
}

std::vector<std::pair<std::string,int>> JackpottingDetector::outbound_connections() const {
    std::vector<std::pair<std::string,int>> conns;
    std::ifstream f("/proc/net/tcp");
    std::string line; std::getline(f, line);
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string idx, local, remote, state;
        if (!(iss >> idx >> local >> remote >> state)) continue;
        if (state != "01") continue;
        if (remote.size() < 9) continue;
        unsigned long rip_hex; int rport_hex;
        sscanf(remote.c_str(), "%8lX:%4X", &rip_hex, &rport_hex);
        unsigned char b[4];
        b[0] = rip_hex & 0xFF; b[1] = (rip_hex >> 8) & 0xFF;
        b[2] = (rip_hex >> 16) & 0xFF; b[3] = (rip_hex >> 24) & 0xFF;
        std::string ip = std::to_string(b[0]) + "." + std::to_string(b[1])
                       + "." + std::to_string(b[2]) + "." + std::to_string(b[3]);
        conns.push_back({ip, rport_hex});
    }
    return conns;
}

bool JackpottingDetector::scan_connections(std::vector<ThreatEvent>& out) {
    for (auto& [ip, port] : outbound_connections()) {
        bool allowed = false;
        for (auto& a : cfg_.allowed_ips) if (a == ip) { allowed = true; break; }
        if (!allowed) {
            ThreatEvent ev;
            ev.type        = ThreatType::JACK_UNEXPECTED_CONN;
            ev.severity    = default_severity(ev.type);
            ev.machine_id  = cfg_.machine_id;
            ev.source_ip   = ip;
            ev.description = "Outbound connection to unlisted IP: "
                             + ip + ":" + std::to_string(port);
            ev.evidence    = "{\"ip\":\"" + ip + "\",\"port\":"
                             + std::to_string(port) + "}";
            out.push_back(ev);
        }
    }
    return !out.empty();
}

std::string JackpottingDetector::sha256_of_file(const std::string& path) const {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    std::vector<uint8_t> buf(4096);
    SHA256_CTX ctx; SHA256_Init(&ctx);
    while (f.read(reinterpret_cast<char*>(buf.data()), buf.size()) || f.gcount())
        SHA256_Update(&ctx, buf.data(), f.gcount());
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &ctx);
    return hex_encode(digest, SHA256_DIGEST_LENGTH);
}

bool JackpottingDetector::verify_binaries(std::vector<ThreatEvent>& out) {
    for (auto& [path, expected] : cfg_.exe_hashes) {
        std::string actual = sha256_of_file(path);
        if (actual.empty() || actual == expected) continue;
        ThreatEvent ev;
        ev.type        = ThreatType::JACK_EXE_TAMPERED;
        ev.severity    = default_severity(ev.type);
        ev.machine_id  = cfg_.machine_id;
        ev.description = "Binary hash mismatch: " + path;
        ev.evidence    = "{\"path\":\"" + path + "\","
                         "\"expected\":\"" + expected + "\","
                         "\"actual\":\"" + actual + "\"}";
        out.push_back(ev);
    }
    return !out.empty();
}

void JackpottingDetector::prune_dispense_window() {
    auto cutoff = Clock::now() - std::chrono::seconds(60);
    disp_history_.erase(
        std::remove_if(disp_history_.begin(), disp_history_.end(),[&](auto& t){ return t < cutoff; }), disp_history_.end());
}

bool JackpottingDetector::check_dispense_rate(int amount_cents, std::vector<ThreatEvent>& out) {
    std::lock_guard<std::mutex> lk(disp_mtx_);
    prune_dispense_window();
    bool bad = false;
    if (static_cast<int>(disp_history_.size()) >= cfg_.max_dispense_per_minute) {
        ThreatEvent ev;
        ev.type        = ThreatType::JACK_DISPENSE_RATE;
        ev.severity    = default_severity(ev.type);
        ev.machine_id  = cfg_.machine_id;
        ev.description = "Dispense rate limit exceeded ("
                         + std::to_string(disp_history_.size()) + " in last 60s)";
        ev.evidence    = "{\"count\":" + std::to_string(disp_history_.size())
                         + ",\"limit\":" + std::to_string(cfg_.max_dispense_per_minute) + "}";
        out.push_back(ev); bad = true;
    }
    if (amount_cents > cfg_.max_dispense_cents) {
        ThreatEvent ev;
        ev.type        = ThreatType::JACK_DISPENSE_RATE;
        ev.severity    = ThreatSeverity::CRITICAL;
        ev.machine_id  = cfg_.machine_id;
        ev.description = "Single dispense exceeds limit: $"
                         + std::to_string(amount_cents / 100);
        ev.evidence    = "{\"amount_cents\":" + std::to_string(amount_cents)
                         + ",\"limit_cents\":" + std::to_string(cfg_.max_dispense_cents) + "}";
        out.push_back(ev); bad = true;
    }
    if (!bad) disp_history_.push_back(Clock::now());
    return bad;
}