#include "include/logger.h"

static std::ofstream logFile;

void initLogger() {
    logFile.open("logs/awilix.log", std::ios::app);

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    logFile << "\n[AWILIX] " << std::ctime(&now);
}

void alertUser(struct event *e)
{
    if (!e->blocked)
        return;

    std::string tty = "/proc/" + std::to_string(e->ppid) + "/fd/1";
    std::ofstream userTerm(tty);

    if (userTerm)
    {
        __u32 ip = e->ip;
        unsigned char *b = (unsigned char *)&ip;

        std::string ip_str = std::to_string(b[0]) + "." +
                             std::to_string(b[1]) + "." +
                             std::to_string(b[2]) + "." +
                             std::to_string(b[3]);

        userTerm << "\n[AWILIX] ⚠ Suspicious connection blocked!\n";
        userTerm << "[AWILIX] Process: " << e->comm << " (PID " << e->pid << ")\n";
        userTerm << "[AWILIX] Attempted to connect to: " << ip_str << ":" << ntohs(e->port);
        userTerm << "\n[AWILIX] This has been logged to logs/awilix.log\n";
    }
}

void createLog(struct event *e)
{
    __u32 ip = e->ip;
    unsigned char *b = (unsigned char *)&ip;

    std::string ip_str = std::to_string(b[0]) + "." +
                         std::to_string(b[1]) + "." +
                         std::to_string(b[2]) + "." +
                         std::to_string(b[3]);

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string timestamp = std::ctime(&now);
    timestamp.pop_back(); // remove trailing newline from ctime

    logFile << "{\n";
    logFile << "  \"timestamp\": \"" << timestamp << "\",\n";
    logFile << "  \"event\": \"" << (e->blocked ? "BLOCKED" : "ALLOWED") << "\",\n";
    logFile << "  \"pid\": " << e->pid << ",\n";
    logFile << "  \"process\": \"" << e->comm << "\",\n";
    logFile << "  \"destination_ip\": \"" << ip_str << "\",\n";
    logFile << "  \"destination_port\": " << ntohs(e->port) << "\n";
    logFile << "}\n";
    logFile.flush();
}