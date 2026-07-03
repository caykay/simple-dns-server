#include "client.h"
#include <cerrno>
#include <cstdio>
#include <sys/socket.h>
#include <unistd.h>

udp_client::udp_client(sa_family_t family, int type, int protocol)
{
    s_ = socket(family, type, protocol);
}

udp_client::~udp_client() { close(); }

int udp_client::close()
{
    printf("%s\n", __func__);
    return ::close(s_);
}

int udp_client::sendto(const void *buf, size_t len, int flags,
                       const struct sockaddr *dest_addr, socklen_t addrlen)
{
    if (!is_open())
    {
        printf("%s: invalid socket\n", __func__);
        return -1;
    }
    ssize_t bytes_sent = ::sendto(s_, buf, len, flags, dest_addr, addrlen);
    if (bytes_sent < 0)
    {
        // Check if the system dropped it because the transmit queue was full
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            printf("Packet dropped: Local send buffer is full. Try again "
                   "later.\n");
            // Handle backoff, queueing, or skipping the frame here
        }
        else
        {
            printf("Failed to send due to a critical error: %s",
                   gai_strerror(errno));
        }
    }
    else
    {
        printf("Successfully queued %zd bytes for transmission.\n", bytes_sent);
    }
    return bytes_sent;
}
