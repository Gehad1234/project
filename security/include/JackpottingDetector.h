#pragma once
#include "Security_types.h"
#include <chrono>
#include <mutex>
#include <string>
#include <vector>

class JackpottingDetector {
public:
    explicit JackpottingDetector(const SecurityConfig& cfg);
    bool scan_processes   (std::vector<ThreatEvent>& out);
    bool scan_connections (std::vector<ThreatEvent>& out);
    bool verify_binaries  (std::vector<ThreatEvent>& out);
    bool check_dispense_rate(int amount_cents, std::vector<ThreatEvent>& out);

private:
    SecurityConfig cfg_;
    std::mutex  disp_mtx_;
    std::vector<std::chrono::system_clock::time_point> disp_history_;
    std::vector<std::string>                 running_processes()    const;
    std::vector<std::pair<std::string,int>>  outbound_connections() const;
    std::string                              sha256_of_file(const std::string& path) const;
    void                                     prune_dispense_window();
};