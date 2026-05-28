#include "../include/SkimmingDetector.h"
#include <algorithm>
#include <cmath>
#include <numeric>
#include <sstream>

using Clock = std::chrono::system_clock;

SkimmingDetector::SkimmingDetector(const SecurityConfig& cfg) : cfg_(cfg) {}

double SkimmingDetector::entropy(const std::string& data) const {
    if (data.empty()) return 0.0;
    int freq[256] = {};
    for (unsigned char c : data) freq[c]++;
    double e = 0.0;
    for (int f : freq) {
        if (!f) continue;
        double p = static_cast<double>(f) / data.size();
        e -= p * std::log2(p);
    }
    return e;
}

double SkimmingDetector::zscore(double sample) const {
    if (timing_window_.size() < 5) return 0.0;
    double mean = std::accumulate(timing_window_.begin(),
                                  timing_window_.end(), 0.0) / timing_window_.size();
    double sq = 0.0;
    for (double x : timing_window_) sq += (x - mean) * (x - mean);
    double sd = std::sqrt(sq / timing_window_.size());
    return (sd < 1e-9) ? 0.0 : std::abs((sample - mean) / sd);
}

bool SkimmingDetector::check_timing(double insert_ms, std::vector<ThreatEvent>& out) {
    std::lock_guard<std::mutex> lk(timing_mtx_);
    double z = zscore(insert_ms);
    timing_window_.push_back(insert_ms);
    if (timing_window_.size() > 50) timing_window_.erase(timing_window_.begin());
    if (z > cfg_.card_timing_zscore_threshold) {
        ThreatEvent ev;
        ev.type        = ThreatType::SKIM_TIMING_ANOMALY;
        ev.severity    = default_severity(ev.type);
        ev.machine_id  = cfg_.machine_id;
        ev.description = "Card reader timing anomaly (z=" + std::to_string(z) + ")";
        ev.evidence    = "{\"insert_ms\":" + std::to_string(insert_ms)
                         + ",\"zscore\":" + std::to_string(z) + "}";
        out.push_back(ev); return true;
    }
    return false;
}

bool SkimmingDetector::check_entropy(const std::string& track2,
                                      std::vector<ThreatEvent>& out) {
    double e = entropy(track2);
    if (e < cfg_.track_entropy_low || e > cfg_.track_entropy_high) {
        ThreatEvent ev;
        ev.type        = ThreatType::SKIM_ENTROPY_ANOMALY;
        ev.severity    = default_severity(ev.type);
        ev.machine_id  = cfg_.machine_id;
        ev.description = "Track-2 entropy out of range: " + std::to_string(e);
        ev.evidence    = "{\"entropy\":" + std::to_string(e)
                         + ",\"low\":" + std::to_string(cfg_.track_entropy_low)
                         + ",\"high\":" + std::to_string(cfg_.track_entropy_high) + "}";
        out.push_back(ev); return true;
    }
    return false;
}

bool SkimmingDetector::check_duplicate(const std::string& card_hash,
                                        std::vector<ThreatEvent>& out) {
    std::lock_guard<std::mutex> lk(dup_mtx_);
    auto it = recent_reads_.find(card_hash);
    auto now = Clock::now();
    if (it != recent_reads_.end()) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
                       now - it->second).count();
        if (age < cfg_.duplicate_card_window_sec) {
            ThreatEvent ev;
            ev.type        = ThreatType::SKIM_DUPLICATE_READ;
            ev.severity    = default_severity(ev.type);
            ev.machine_id  = cfg_.machine_id;
            ev.description = "Card read twice within " + std::to_string(age) + "s";
            ev.evidence    = "{\"card_hash\":\"" + card_hash
                             + "\",\"interval_sec\":" + std::to_string(age) + "}";
            out.push_back(ev); return true;
        }
    }
    recent_reads_[card_hash] = now;
    for (auto jt = recent_reads_.begin(); jt != recent_reads_.end(); )
        jt = (std::chrono::duration_cast<std::chrono::seconds>(now - jt->second).count() > 60)
           ? recent_reads_.erase(jt) : ++jt;
    return false;
}
