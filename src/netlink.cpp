#include "netlink.h"

int initNetlink() {
    int sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if(sock < 0){
        return -1;
    }

    struct sockaddr_nl addr = {};
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = CN_IDX_PROC;
    addr.nl_pid = getpid();

    if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) <0){
        return -1;
    }

    return sock;
}

int subscribeNetlink(int sock)
{
    char buffer[sizeof(struct nlmsghdr) + sizeof(struct cn_msg)+ sizeof(enum proc_cn_mcast_op)] = {};

    struct nlmsghdr *nlhdr = (struct nlmsghdr *)buffer;
    struct cn_msg *cnmsg = (struct cn_msg *)(nlhdr + 1);
    enum proc_cn_mcast_op *op = (enum proc_cn_mcast_op *)(cnmsg + 1);

    nlhdr->nlmsg_len = sizeof(buffer);
    nlhdr->nlmsg_type = NLMSG_DONE;
    nlhdr->nlmsg_flags = 0;

    cnmsg->id.idx = CN_IDX_PROC;
    cnmsg->id.val = CN_VAL_PROC;
    cnmsg->len = sizeof(enum proc_cn_mcast_op);

    *op = PROC_CN_MCAST_LISTEN;

    if (send(sock, buffer, sizeof(buffer), 0) < 0)
        return -1;

    return 0;
}

void listenNetlink(int sock, std::function<void(int)> callback) {
    char buffer[4096] = {};

    while (true) {
        int len = recv(sock, buffer, sizeof(buffer), 0);
        if(len < 0)
            break;

        struct nlmsghdr *nlhdr = (struct nlmsghdr *)buffer;
        struct cn_msg *cnmsg = (struct cn_msg *)(nlhdr + 1);
        struct proc_event *event = (struct proc_event *)cnmsg->data;

        if (event->what == PROC_EVENT_EXEC) {
            int pid = event->event_data.exec.process_pid;
            callback(pid);
        }
    }
}