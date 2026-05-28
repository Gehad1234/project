#pragma once
#include "Security_types.h"
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class SkimmingDetector {
public:
    explicit SkimmingDetector(const SecurityConfig& cfg);
    bool check_timing   (double insert_ms,          std::vector<ThreatEvent>& out);
    bool check_entropy  (const std::string& track2, std::vector<ThreatEvent>& out);
    bool check_duplicate(const std::string& card_hash, std::vector<ThreatEvent>& out);

private:
    SecurityConfig cfg_;
    std::mutex timing_mtx_;
    std::vector<double> timing_window_;
    std::mutex dup_mtx_;
    std::unordered_map<std::string,
        std::chrono::system_clock::time_point> recent_reads_;
    double entropy(const std::string& data) const;
    double zscore (double sample)           const;
};