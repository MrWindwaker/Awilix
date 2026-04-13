#include "allowlist.h"

bool isAllowed(__u32 ip)
{
    unsigned char *ip_bytes = (unsigned char *)&ip;

    if (ip_bytes[0] == 104 && ip_bytes[1] == 16)
        return true;

    if (ip_bytes[0] == 100 && ip_bytes[1] == 100 && ip_bytes[2] == 100 && ip_bytes[3] == 100)
        return true;

    return false;
}