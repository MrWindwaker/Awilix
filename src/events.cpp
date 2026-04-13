#include "include/events.h"
#include "include/logger.h"

int handleEvent(void *ctx, void *data, size_t size)
{
    struct event *e = (struct event *)data;

    __u32 ip = e->ip;
    unsigned char *ip_bytes = (unsigned char *)&ip;

    std::string destination = std::to_string(ip_bytes[0]) + "." + std::to_string(ip_bytes[1]) + "." + std::to_string(ip_bytes[2]) + "." + std::to_string(ip_bytes[3]) + ":" + std::to_string(ntohs(e->port));

    if (isAllowed(e->ip))
        std::cout << "[ALLOWED] PID " << e->pid << " (" << e->comm << ") -> " << destination << std::endl;
    else
    {
        std::cout << "[BLOCKED]" << e->pid << " (" << e->comm << ") -> " << destination << std::endl;
        createLog(e);
        alertUser(e);
    }

    return 0;
}
