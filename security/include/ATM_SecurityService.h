#pragma once
#include "Security_types.h"
#include "MitM_Detector.h"
#include "SniffingDetector.h"
#include "JackpottingDetector.h"
#include "BlackBoxDetector.h"
#include "SkimmingDetector.h"
#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

using ThreatCallback = std::function<void(const ThreatEvent&)>;

class ATM_SecurityService {
public:
    explicit ATM_SecurityService(const SecurityConfig& cfg);
    ~ATM_SecurityService();

    void start();
    void stop();

    void on_threat(ThreatCallback cb);

    bool verify_request(const std::string& payload, const std::string& signature, uint64_t nonce, int64_t timestamp_unix, ThreatEvent& event_out);

    std::string sign_response(const std::string& body);

    std::string issue_dispense_token(const std::string& command_id);
    bool        authorize_dispense  (const std::string& command_id,const std::string& token, int amount_cents);

    bool process_card(double insert_ms, const std::string& track2, const std::string& card_hash);

    LockdownLevel            lockdown_level() const;
    void                     set_lockdown(LockdownLevel level);

    std::vector<ThreatEvent> drain_events();

    static std::string to_string(ThreatType t);

private:
    SecurityConfig       cfg_;
    std::atomic<uint8_t> lockdown_{0};

    MitM_Detector        mitm_;
    SniffingDetector     sniff_;
    JackpottingDetector  jackpot_;
    BlackBoxDetector     blackbox_;
    SkimmingDetector     skim_;

    std::mutex              q_mtx_;
    std::queue<ThreatEvent> event_queue_;

    std::mutex                  cb_mtx_;
    std::vector<ThreatCallback> callbacks_;

    std::thread             monitor_thread_;
    std::atomic<bool>       running_{false};
    std::condition_variable monitor_cv_;
    std::mutex              monitor_mtx_;

    void monitor_loop();
    void push_event(ThreatEvent e);
    void apply_lockdown_policy(const ThreatEvent& e);
};