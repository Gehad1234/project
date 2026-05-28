#include "../include/ATMs_db.h"
#include <stdexcept>
using namespace std;

ATMsDB::ATMsDB(const string& db_path) {
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK)
        throw runtime_error("Failed to open database: " + db_path);
    exec("PRAGMA journal_mode=WAL;");
}

ATMsDB::~ATMsDB() {
    if (db_) sqlite3_close(db_);
}

void ATMsDB::exec(const string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        string msg = err ? err : "Unknown error";
        sqlite3_free(err);
        throw runtime_error("SQL error: " + msg);
    }
}

void ATMsDB::create_tables() {
    exec(R"(
        CREATE TABLE IF NOT EXISTS ATMs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_id TEXT UNIQUE NOT NULL,
            status     TEXT NOT NULL DEFAULT 'offline',
            location   TEXT NOT NULL DEFAULT '',
            ATM_ip     TEXT NOT NULL,
            port       INTEGER NOT NULL DEFAULT 8080
        );
    )");
}

void ATMsDB::upsert_ATM(const ATM_Rec& atm) {
    const string sql = R"(
        INSERT INTO ATMs (machine_id, status, location, ATM_ip, port)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(machine_id) DO UPDATE SET
            status   = excluded.status,
            location = excluded.location,
            ATM_ip   = excluded.ATM_ip,
            port     = excluded.port;
    )";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        throw runtime_error("Failed to prepare upsert statement");

    sqlite3_bind_text(stmt, 1, atm.machine_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, atm.status.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, atm.location.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, atm.ATM_ip.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 5, atm.port);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw runtime_error("Failed to execute upsert");
    }
    sqlite3_finalize(stmt);
}

ATM_Rec ATMsDB::get_ATM_by_id(int id) {
    const string sql = R"(
        SELECT id, machine_id, status, location, ATM_ip, port
        FROM ATMs WHERE id = ?;
    )";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        throw runtime_error("Failed to prepare select statement");

    sqlite3_bind_int(stmt, 1, id);

    ATM_Rec atm{};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        atm.id         = sqlite3_column_int (stmt, 0);
        atm.machine_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        atm.status     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        atm.location   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        atm.ATM_ip     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        atm.port       = sqlite3_column_int (stmt, 5);
    } else {
        sqlite3_finalize(stmt);
        throw runtime_error("ATM not found with id: " + to_string(id));
    }
    sqlite3_finalize(stmt);
    return atm;
}

vector<ATM_Rec> ATMsDB::get_all_ATMs() {
    const string sql = R"(
        SELECT id, machine_id, status, location, ATM_ip, port
        FROM ATMs;
    )";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        throw runtime_error("Failed to prepare select all statement");

    vector<ATM_Rec> atms;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ATM_Rec atm{};
        atm.id         = sqlite3_column_int (stmt, 0);
        atm.machine_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        atm.status     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        atm.location   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        atm.ATM_ip     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        atm.port       = sqlite3_column_int (stmt, 5);
        atms.push_back(atm);
    }
    sqlite3_finalize(stmt);
    return atms;
}

void ATMsDB::set_ATM_status(int id, const string& status) {
    const string sql = "UPDATE ATMs SET status = ? WHERE id = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        throw runtime_error("Failed to prepare status update");

    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 2, id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw runtime_error("Failed to update status");
    }
    sqlite3_finalize(stmt);
}