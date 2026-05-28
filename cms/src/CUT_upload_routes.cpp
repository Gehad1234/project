#include "../include/CMS_server.h"
#include "../include/CMS_Logger.h"
#include "../../common/Common_routes.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
using json = nlohmann::json;
using namespace std;
namespace fs = std::filesystem;

crow::response CMS_server::route_cut_send_file(const crow::request& req) {
    if (req.body.empty())
        return crow::response(400, json({{"error", "Empty request body"}}).dump());

    string fname = req.get_header_value("File-Name");
    if (fname.empty()) fname = "update.zip";

    string meta = req.get_header_value("Metadata");
    if (meta.empty()) meta = "{}";

    fs::create_directories("./storage");
    string file_path = "./storage/" + fname;

    ofstream outfile(file_path, ios::binary);
    if (!outfile) {
        CMS_Logger::error("route_cut_send_file", "Failed to save file: " + file_path);
        return crow::response(500, json({{"error", "Failed to save file on CMS"}}).dump());
    }
    outfile.write(req.body.data(), req.body.size());
    outfile.close();

    ofstream metafile(file_path + ".meta.json");
    if (metafile) metafile << meta;

    vector<ATM_Rec> atms;
    try {
        atms = resolve_all(req);
    } catch (const exception& e) {
        CMS_Logger::error("route_cut_send_file", e.what());
        return crow::response(400, json({{"error", e.what()}}).dump());
    }

    if (atms.empty())
        return crow::response(404, json({{"error", "No ATMs registered"}}).dump());

    vector<char> zip_body(req.body.begin(), req.body.end());
    json results = json::array();

    for (const auto& atm : atms) {
        db.set_ATM_status(atm.id, "updating");

        auto r = atm_.post_multipart(
            atm.ATM_ip, atm.port,
            Route::Update::UploadAndUpdate,
            zip_body, meta, fname          // fname passed as filename
        );

        string new_status = r.ok() ? "updated" : "error";
        db.set_ATM_status(atm.id, new_status);
        CMS_Logger::update_event(atm, r, new_status);

        results.push_back({
            {"id",            atm.id},
            {"machine_id",    atm.machine_id},
            {"location",      atm.location},
            {"ATM_ip",        atm.ATM_ip},
            {"port",          atm.port},
            {"status",        new_status},
            {"http_code",     r.http_code},
            {"response_body", r.body},
            {"error",         r.error}
        });
    }

    return crow::response(200, json({
        {"status",  "done"},
        {"file",    fname},
        {"targets", results}
    }).dump());
}
