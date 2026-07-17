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
size_t print_dns(const dns::dns_payload_t &payload)
{
    char out[513];
    ZERO_MEM(out, 513);
    size_t bytes_written = payload.to_string(out, sizeof(out));
    printf("%s", out);
    return bytes_written;
}

size_t parse_query_field(const char *buf, size_t len, dns::dns_query_t &query)
{
    size_t bytes_read = 0; // name_size also counts '.'
    // read label length byte
    uint8_t label_len = 0;
    query.q_name.length = 0;
    do
    {
        /**
         * Little endian byte conversion is not performed because:
         * label length and ascii characters are single byte lengthed
         * hence no network byte order swapping is needed as data fits
         * a single byte when being sent over
         */
        char label[LABEL_SIZE_MAX];
        ZERO_MEM(label, LABEL_SIZE_MAX);
        memcpy(&label_len, buf + bytes_read, sizeof(uint8_t));
        if (label_len < 1)
            continue; // go to "while" terminate
        bytes_read++; // skip the field length byte
        memcpy(label, buf + bytes_read, label_len);
        query.q_name.length +=
            snprintf(&query.q_name.labels[query.q_name.length],
                     DNS_MAX_NAME_LEN - query.q_name.length, "%s%s",
                     (query.q_name.length > 0 ? "." : ""), label);
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

/**
 * lightweight as it only cares about the question query (QDCOUNT)
 */
bool parse_dns_request(const char *buf, size_t len, dns::dns_payload_t *payload)
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
    if (!dns::is_valid_header(payload->header))
    {
        printf("Invalid dns payload\n");
        ZERO_MEM(payload, sizeof(dns::dns_payload_t));
        return false;
    }
    parse_query_field(buf + 12, len - 12, payload->query);
    // everything else is ignored
    return true;
}

void handle_dns_request(const dns::dns_payload_t &req, dns::dns_payload_t &res)
{
    // assume res is empty
    res.header.transaction_id = req.header.transaction_id;
    res.header.qdcount = req.header.qdcount;
    res.header.arcount = 0;
    res.header.ancount = 1;
    res.header.flags =
        DNS_FLAGS_QR_RESPONSE | DNS_FLAGS_AD_SET | DNS_FLAGS_RCODE_NOERROR;

    res.query = req.query;

    dns::dns_answer_t ans;
    ans.r_type = dns::rr_type_t::A;
    ans.r_class = dns::class_t::IN;
    ans.ttl = 15 * 60; // 15 minutes
    ans.data.length = snprintf(ans.data.labels, DNS_MAX_NAME_LEN, "127.0.0.1");

    memcpy(&res.answers[0], &ans, sizeof(dns::dns_answer_t));
}

/**
 * send a dns response to clien
 */
ssize_t send_dns_response(SOCKET sock, dns::dns_payload_t &res, int flags,
                          const sockaddr_in *dest_addr, socklen_t addrlen)
{
    dns::to_network_byte_order(res);
    const int max_len = 512;
    char buf[max_len];
    size_t index = 0, len = 0;
    memcpy(buf + len, &res.header, sizeof(dns::dns_header_t));
    len += sizeof(dns::dns_header_t);
    len += res.query.copy_bytes(buf + len, max_len - len);
    for (int i = 0; i < res.header.ancount; i++)
    {
        len += res.answers[i].copy_bytes(buf + len, max_len - len);
    }
    return sendto(sock, buf, len, flags, (sockaddr *)dest_addr, addrlen);
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
            printf("\nReceived %zd bytes of data\n", returned_bytes);
            buf[returned_bytes] = '\0';
            // read byte
            printf("Data:\n");
            dns::dns_payload_t req = {0};
            dns::dns_payload_t res = {0};
            parse_dns_request(buf, returned_bytes, &req);
            printf("DNS request: \n");
            print_dns(req);
            if (dns::is_valid_header(req.header))
            {
                handle_dns_request(req, res);
                printf("Sending DNS response: \n");
                print_dns(res);
                int flags = 0;
                // send response
                // ssize_t sent_bytes = send_dns_response(udp_socket, res,
                // flags,
                //                                        &client, client_len);
            }
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
