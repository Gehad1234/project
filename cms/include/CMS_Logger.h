#pragma once
#include <fstream>
#include <mutex>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <nlohmann/json.hpp>
#include "ATMs_db.h"
#include "CMS_ATM.h"

using json = nlohmann::json;

class CMS_Logger {
public:
    static void init(const std::string& log_dir = "./cms/logs") {
        log_dir_ = log_dir;
    }

    static void update_event(const ATM_Rec& atm,
                              const CMS_ATM_result& result,
                              const std::string& final_status) {
        json rec = {
            {"timestamp",     now_iso8601()},
            {"machine_id",    atm.machine_id},
            {"ATM_ip",        atm.ATM_ip},
            {"port",          atm.port},
            {"location",      atm.location},
            {"atm_db_id",     atm.id},
            {"status",        final_status},
            {"http_code",     result.http_code},
            {"response_body", result.body},
            {"error",         result.error}
        };
        write_line("update_events.log", rec.dump());
    }

    static void error(const std::string& function,
                       const std::string& message,
                       const std::string& level = "ERROR") {
        json rec = {
            {"timestamp", now_iso8601()},
            {"level",     level},
            {"function",  function},
            {"message",   message}
        };
        write_line("error.log", rec.dump());
    }

private:
    inline static std::string log_dir_ = "./cms/logs";
    inline static std::mutex  mtx_;

    static std::string now_iso8601() {
        auto now = std::chrono::system_clock::now();
        auto tt  = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&tt), "%Y-%m-%dT%H:%M:%S");
        return oss.str();
    }

    static void write_line(const std::string& filename,
                            const std::string& line) {
        std::lock_guard<std::mutex> lock(mtx_);
        std::ofstream f(log_dir_ + "/" + filename, std::ios::app);
        if (f) f << line << "\n";
    }
};
