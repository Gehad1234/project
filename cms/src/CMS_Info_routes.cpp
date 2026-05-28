#include "../include/CMS_server.h"
#include "../../common/Common_routes.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;
using namespace std;

crow::response CMS_server::route_machine_id(const crow::request& req) {
    try {
        auto atm = resolve(req);
        auto r   = atm_.get(atm.ATM_ip, atm.port, Route::Info::ID);
        return format_response(r);
    } catch (const exception& e) {
        return crow::response(400, json({{"error", e.what()}}).dump());
    }
}

crow::response CMS_server::route_machine_uptime(const crow::request& req) {
    try {
        auto atm = resolve(req);
        auto r   = atm_.get(atm.ATM_ip, atm.port, Route::Info::UpTime);
        return format_response(r);
    } catch (const exception& e) {
        return crow::response(400, json({{"error", e.what()}}).dump());
    }
}

crow::response CMS_server::route_machine_info(const crow::request& req) {
    try {
        auto atm = resolve(req);
        auto r   = atm_.get(atm.ATM_ip, atm.port, Route::Info::AllInfo);
        return format_response(r);
    } catch (const exception& e) {
        return crow::response(400, json({{"error", e.what()}}).dump());
    }
}