#include "server.h"
#include "shared.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace
{
bool parse_udp_body(const char *buf, size_t len) { return false; }
} // namespace

namespace server
{
int start_server(std::promise<void> on_server_init)
{
    int err;
    addrinfo hints, *result;
    SOCKET udp_socket;
    sockaddr_in *server_addr, client_addr;
    ZERO_MEM(&client_addr, sizeof(client_addr));

    ZERO_MEM(&hints, sizeof(hints));
    hints = {.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV,
             .ai_family = AF_INET,
             .ai_socktype = SOCK_DGRAM,
             .ai_protocol = IPPROTO_UDP};

    err = getaddrinfo(LOOPBACK_ADDR, UDP_PORT_STR, &hints, &result);
    if (err != 0)
    {
        printf("Error getting addr. err: %s\n", gai_strerror(err));
        freeaddrinfo(result);
        return 1;
    }

    server_addr = (sockaddr_in *)(result->ai_addr);
    // open server socket
    udp_socket = socket(result->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket == INVALID_SOCKET)
    {
        printf("Error creating a socket. err: %s\n", gai_strerror(errno));
        freeaddrinfo(result);
        return 1;
    }

    // bind addr to socket
    err = bind(udp_socket, result->ai_addr, result->ai_addrlen);
    if (err != 0)
    {
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(result->ai_family, &server_addr->sin_addr, ipstr,
                  INET_ADDRSTRLEN);
        printf("Error binding socket addr %s:%s. err: %s\n", ipstr,
               UDP_PORT_STR, gai_strerror(err));
        freeaddrinfo(result);
        return 1;
    }

    on_server_init.set_value(); // notify main thread

    {
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(result->ai_family, &server_addr->sin_addr, ipstr,
                  INET_ADDRSTRLEN);
        printf("UDP Server started at: %s:%s\n", ipstr, UDP_PORT_STR);
    }

    sockaddr_in client;
    socklen_t client_len = 0;

    // wait for udp packets
    while (true)
    {
        char buf[MAX_BUF + 1]; // account for null terminator
        ssize_t returned_bytes = recvfrom(udp_socket, buf, MAX_BUF, 0,
                                          (sockaddr *)&client, &client_len);
        if (returned_bytes >= 0)
        {
            printf("Received %zd bytes of data\n", returned_bytes);
            buf[returned_bytes] = '\0';
            // read byte
            printf("Data:\n%s\n", buf);
        }
        else
        {
            printf("server encountered an error : %s\n", gai_strerror(errno));
            break;
        }
    }

    close(udp_socket);
    freeaddrinfo(result);
    return 0;
}
} // namespace server
