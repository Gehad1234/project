#include "../include/CMS_server.h"
#include "../../common/Common_routes.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;
using namespace std;

CMS_server::CMS_server(uint16_t port) : port(port), db("ATMs.db") {
    db.create_tables();
}

ATM_Rec CMS_server::resolve(const crow::request& req) {
    const char* id_str = req.url_params.get("id");
    if (!id_str)
        throw runtime_error("Missing 'id' parameter");
    return db.get_ATM_by_id(stoi(id_str));
}

vector<ATM_Rec> CMS_server::resolve_all(const crow::request& req) {
    const char* id_str = req.url_params.get("id");
    if (id_str)
        return {db.get_ATM_by_id(stoi(id_str))};
    return db.get_all_ATMs();
}

crow::response CMS_server::format_response(const CMS_ATM_result& result) {
    if (!result.ok())
        return crow::response(500, json({{"error", result.error}}).dump());
    return crow::response(result.http_code, result.body);
}

void CMS_server::run() {

    app.route_dynamic(Route::cut::send_file)
        .methods(crow::HTTPMethod::Post)
        ([this](const crow::request& req) {
            return route_cut_send_file(req);
        });

    app.route_dynamic(Route::Info::ID)
        .methods(crow::HTTPMethod::Get)
        ([this](const crow::request& req) {
            return route_machine_id(req);
        });

    app.route_dynamic(Route::Info::UpTime)
        .methods(crow::HTTPMethod::Get)
        ([this](const crow::request& req) {
            return route_machine_uptime(req);
        });

    app.route_dynamic(Route::Info::AllInfo)
        .methods(crow::HTTPMethod::Get)
        ([this](const crow::request& req) {
            return route_machine_info(req);
        });

    app.route_dynamic(Route::Info::FullInfo)
        .methods(crow::HTTPMethod::Get)
        ([this](const crow::request& req) {
            return route_machine_info(req);
        });

    app.route_dynamic(Route::Update::InitUpdate)
        .methods(crow::HTTPMethod::Get)
        ([this](const crow::request& req) {
            return route_init_update(req);
        });

    app.route_dynamic(Route::Update::CurrentFiles)
        .methods(crow::HTTPMethod::Get)
        ([this](const crow::request& req) {
            return route_current_files(req);
        });

    app.route_dynamic(Route::Update::UploadFiles)
        .methods(crow::HTTPMethod::Post)
        ([this](const crow::request& req) {
            return route_upload_files(req);
        });

    app.route_dynamic(Route::Update::UploadAndUpdate)
        .methods(crow::HTTPMethod::Post)
        ([this](const crow::request& req) {
            return route_upload_and_update(req);
        });

    app.route_dynamic("/atms")
        .methods(crow::HTTPMethod::Get)
        ([this](const crow::request&) {
            json arr = json::array();
            for (auto& a : db.get_all_ATMs()) {
                arr.push_back({
                    {"id",         a.id},
                    {"machine_id", a.machine_id},
                    {"status",     a.status},
                    {"location",   a.location},
                    {"ip_address", a.ATM_ip},
                    {"port",       a.port}
                });
            }
            return crow::response(200, arr.dump());
        });

    app.route_dynamic("/atms")
        .methods(crow::HTTPMethod::Post)
        ([this](const crow::request& req) {
            auto body = json::parse(req.body, nullptr, false);
            if (body.is_discarded())
                return crow::response(400, R"({"error":"bad json"})");
            ATM_Rec r{};
            r.machine_id = body.value("machine_id", "");
            r.ATM_ip     = body.value("ip_address", "");
            r.location   = body.value("location",   "");
            r.status     = "offline";
            r.port       = body.value("port", 8080);
            if (r.machine_id.empty() || r.ATM_ip.empty())
                return crow::response(400, R"({"error":"machine_id and ip_address required"})");
            db.upsert_ATM(r);
            return crow::response(200, R"({"status":"registered"})");
        });

    app.port(port).multithreaded().run();
}
