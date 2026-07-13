#include "udp_dns_server.h"
#include "dns.h"
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
size_t read_dns_name(const char *buf, size_t len, dns::dns_query_t &query)
{
    size_t bytes_read = 0, name_size = 0; // name_size also counts '.'
    // read label length byte
    uint8_t label_len = 0;
    do
    {
        /**
         * Little endian byte conversion is not performed because:
         * label length and ascii characters are single byte lengthed
         * hence no network byte order swapping is needed as data fits
         * a single byte when being sent over
         */
        char label[LABEL_SIZE_MAX];
        memcpy(&label_len, buf + bytes_read, sizeof(uint8_t));
        if (label_len < 1)
            continue; // go to "while" terminate
        bytes_read++; // skip the field length byte
        memcpy(label, buf + bytes_read, label_len);
        label[label_len] = '\0';
        name_size +=
            snprintf(&query.q_name[name_size], sizeof(query.q_name) - name_size,
                     "%s%s", (name_size > 0 ? "." : ""), label);
        bytes_read += label_len;
    } while (label_len > 0);
    bytes_read++; // account for training 0x00 byte
    // read type
    memcpy(&query.q_type, buf + bytes_read, sizeof(query.q_type));
    bytes_read += sizeof(query.q_type);
    // read class
    memcpy(&query.q_class, buf + bytes_read, sizeof(query.q_class));
    bytes_read += sizeof(query.q_class);
    // must convert to little endian since on mac / unix
    query.q_type = (dns::rr_type_t)ntohs((uint16_t)query.q_type);
    query.q_class = (dns::class_t)ntohs((uint16_t)query.q_class);
    return bytes_read;
}
bool parse_dns(const char *buf, size_t len, dns::dns_payload_t *payload)
{
    // udp payload must at least comprise the dns header size and also < 512 as
    // per dns RFCs smallest valid dns header is 12 bytes and content header is
    // at least 5 bytes: 2 bytes for type 2 bytes for class 1 byte for root
    // domain name ('.')
    if (len < 17 && len > 512)
        return false;
    // parse the dns header first
    memcpy(&payload->header, buf, sizeof(payload->header));
    dns::to_host_byte_order(payload->header);
    // TODO: testing only, this should be removed later
    char out[512];
    size_t written = 0;
    written = payload->header.to_string(out, sizeof(out));
    if (!dns::is_valid_header(payload->header))
    {
        printf("Invalid dns payload\n");
        ZERO_MEM(payload, sizeof(dns::dns_payload_t));
        return false;
    }
    size_t query_len = read_dns_name(buf + 12, len - 12, payload->query);
    payload->query.to_string(out + written, sizeof(out) - written);
    printf("dns payload:\n%s", out);
    return true;
}
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
            dns::dns_payload_t dns;
            parse_dns(buf, returned_bytes, &dns);
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
