#include <filesystem>
#include <string>
#include <iostream>
#include <cctype>
#include <algorithm>
#include <fstream>
#include <unordered_set>
#include <vector>

void cleanPids(std::unordered_set<std::string> &pids)
{
    std::vector<std::string> dead;
    for (const std::string &pid : pids)
    {
        if (!std::filesystem::is_directory("/proc/" + pid))
        {
            dead.push_back(pid);
        }
    }

    for (const std::string &pid : dead)
    {
        pids.erase(pid);
        std::cout << "[REMOVED] PID " << pid << std::endl;
    }
}

std::string readCmdline(std::string &pid)
{
    std::ifstream file("/proc/" + pid + "/cmdline");

    if (file)
    {
        std::stringstream buf;
        buf << file.rdbuf();
        std::string content = buf.str();

        if (!content.empty())
        {
            std::replace(content.begin(), content.end(), '\0', ' ');

            return content;
        }

        return "";
    }

    return "";
}

void scanProc(std::unordered_set<std::string> &pids)
{
    for (const auto &entry : std::filesystem::directory_iterator("/proc"))
    {
        std::string pid = entry.path().filename();

        if (std::all_of(pid.begin(), pid.end(), ::isdigit))
        {
            if (pids.find(pid) != pids.end())
            {
                continue;
            }

            std::string content = readCmdline(pid);

            if (!content.empty() && content.find("npm install") != std::string::npos)
            {

                pids.insert(pid);
                std::cout << "[DETECTED] PID " << pid << ": " << content << std::endl;
            }
        }
    }
}

int main()
{
    std::unordered_set<std::string> pids = {};

    while (true)
    {
        cleanPids(pids);
        scanProc(pids);
    }

    return 0;
}