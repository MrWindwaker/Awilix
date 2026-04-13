#include <unistd.h>
#include <mutex>
#include <thread>

#include "include/monitor.h"
#include "include/events.h"
#include "include/allowlist.h"
#include "include/netlink.h"
#include "include/logger.h"

struct probes_bpf *loadBpf()
{
    struct probes_bpf *skel = probes_bpf__open();
    if (!skel)
    {
        std::cerr << "[ERROR] Failed to open BPF skeleton" << std::endl;
        return nullptr;
    }

    if (probes_bpf__load(skel))
    {
        std::cerr << "[ERROR] Failed to load BPF skeleton" << std::endl;
        probes_bpf__destroy(skel);
        return nullptr;
    }

    if (probes_bpf__attach(skel))
    {
        std::cerr << "[ERROR] Failed to attach BPF skeleton" << std::endl;
        probes_bpf__destroy(skel);
        return nullptr;
    }

    std::cerr << "[AWILIX] eBPF probe attached" << std::endl;
    return skel;
}

int main()
{
    std::unordered_set<std::string> pids = {};
    initLogger();
    probes_bpf *skel = loadBpf();

    populateAllowlist(skel);

    int sock = initNetlink();
    int subs = subscribeNetlink(sock);

    if (!skel)
    {
        std::cerr << "[ERROR] Failed to load eBPF, exiting" << std::endl;
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handleEvent, nullptr, nullptr);
    std::mutex pidsMutex;

    if (sock < 0)
    {
        std::cerr << "[ERROR] Failed to init netlink" << std::endl;
        return 1;
    }

    if (subs < 0)
    {
        std::cerr << "[ERROR] Failed to init netlink" << std::endl;
        return 1;
    }

    std::thread netlinkThread([&]()
                              { listenNetlink(sock, [&](int pid)
                                              {std::lock_guard<std::mutex> lock(pidsMutex);checkPid(std::to_string(pid), pids, skel); }); });

    while (true)
    {
        ring_buffer__poll(rb, 100);
        {
            std::lock_guard<std::mutex> lock(pidsMutex);
            cleanPids(pids);
            scanProc(pids, skel);
        }
    }

    return 0;
}