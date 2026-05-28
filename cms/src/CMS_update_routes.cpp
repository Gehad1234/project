#include "../include/CMS_server.h"
#include "../../common/Common_routes.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;
using namespace std;

crow::response CMS_server::route_init_update(const crow::request& req) {
    try {
        auto atm = resolve(req);
        auto r   = atm_.post(atm.ATM_ip, atm.port, Route::Update::InitUpdate);
        return format_response(r);
    } catch (const exception& e) {
        return crow::response(400, json({{"error", e.what()}}).dump());
    }
}

crow::response CMS_server::route_current_files(const crow::request& req) {
    try {
        auto atm = resolve(req);
        auto r   = atm_.get(atm.ATM_ip, atm.port, Route::Update::CurrentFiles);
        return format_response(r);
    } catch (const exception& e) {
        return crow::response(400, json({{"error", e.what()}}).dump());
    }
}

crow::response CMS_server::route_upload_files(const crow::request& req) {
    try {
        auto atm  = resolve(req);
        string meta = req.get_header_value("Metadata");
        if (meta.empty()) meta = "{}";
        vector<char> zip_body(req.body.begin(), req.body.end());
        auto r = atm_.post_multipart(atm.ATM_ip, atm.port,
                                     Route::Update::UploadFiles,
                                     zip_body, meta);
        return format_response(r);
    } catch (const exception& e) {
        return crow::response(400, json({{"error", e.what()}}).dump());
    }
}

crow::response CMS_server::route_upload_and_update(const crow::request& req) {
    try {
        auto atm  = resolve(req);
        string meta = req.get_header_value("Metadata");
        if (meta.empty()) meta = "{}";
        vector<char> zip_body(req.body.begin(), req.body.end());
        auto r = atm_.post_multipart(atm.ATM_ip, atm.port,
                                     Route::Update::UploadAndUpdate,
                                     zip_body, meta);
        return format_response(r);
    } catch (const exception& e) {
        return crow::response(400, json({{"error", e.what()}}).dump());
    }
}



