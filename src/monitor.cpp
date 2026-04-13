#include "include/monitor.h"

std::string getParentPid(const std::string &pid)
{
    std::ifstream file("/proc/" + pid + "/stat");
    if (file)
    {
        std::stringstream buf;
        buf << file.rdbuf();
        std::string content = buf.str();

        if (!content.empty())
        {
            size_t closingPnt = content.find(')');
            if (closingPnt == std::string::npos)
                return "";

            std::istringstream iss(content.substr(closingPnt + 1));
            std::string state, ppid;
            iss >> state >> ppid;

            return ppid;
        }

        return "";
    }

    return "";
}

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

std::string readCmdline(const std::string &pid)
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

void scanProc(std::unordered_set<std::string> &pids, struct probes_bpf *skel)
{
    for (const auto &entry : std::filesystem::directory_iterator("/proc"))
    {
        std::string pid = entry.path().filename();

        if (std::all_of(pid.begin(), pid.end(), ::isdigit))
        {
            checkPid(pid, pids, skel);
        }
    }
}

void checkPid(const std::string &pid, std::unordered_set<std::string> &pids, struct probes_bpf *skel)
{
    if (pids.find(pid) != pids.end())
        return;

    // check if child of watched process
    std::string ppid = getParentPid(pid);
    if (!ppid.empty() && pids.find(ppid) != pids.end())
    {
        __u32 pid_num = std::stoul(pid);
        __u8 val = 1;
        bpf_map__update_elem(skel->maps.watched_pids, &pid_num, sizeof(pid_num), &val, sizeof(val), BPF_ANY);
        pids.insert(pid);
        std::cout << "[CHILD] PID " << pid << " (parent: " << ppid << ")" << std::endl;
        return;
    }

    // check if npm install
    std::string content = readCmdline(pid);
    if (!content.empty() && content.find("npm install") != std::string::npos)
    {
        __u32 pid_num = std::stoul(pid);
        __u8 val = 1;
        bpf_map__update_elem(skel->maps.watched_pids, &pid_num, sizeof(pid_num), &val, sizeof(val), BPF_ANY);
        pids.insert(pid);
        std::cout << "[DETECTED] PID " << pid << ": " << content << std::endl;
    }
}