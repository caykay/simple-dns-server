#include <cstddef>
#include <cstdint>
#include <cstdio>

#define MAX_QUERY_COUNT 1
#define MAX_ANS_COUNT 30
#define DNS_MAX_NAME_LEN 256 // 255 bytes + 1 null-terminator

#define DNS_FLAGS_QR_QUERY 0x0000
#define DNS_FLAGS_QR_RESPONSE 0x8000
#define DNS_FLAGS_OPCODE_QUERY 0x0000
// mask with FLAGS_OPCODE_MASK to isolate or clear OPCODE flag bits
// & FLAGS_OPCODE_MASK to isolate
// | FLAGS_OPCODE_MASK to clear
#define DNS_FLAGS_OPCODE_MASK 0x7800
// Authoritative Answer
#define DNS_FLAGS_AA 0x0400, // 1 = Responding server owns the zone
// DNSSEC
#define DNS_FLAGS_AD_SET 0x0020
// Response Codes (Mask with 0x000F to isolate)
#define DNS_FLAGS_RCODE_MASK 0x000F
#define DNS_FLAGS_RCODE_NOERROR 0x0000  // Success
#define DNS_FLAGS_RCODE_FORMERR 0x0001  // Format Error
#define DNS_FLAGS_RCODE_SERVFAIL 0x0002 // Server Failure
#define DNS_FLAGS_RCODE_NXDOMAIN 0x0003 // Domain Name Error (Does not exist)
#define DNS_FLAGS_RCODE_NOTIMP 0x0004   // Not Implemented
#define DNS_FLAGS_RCODE_REFUSED 0x0005  // Query Refused

namespace dns
{
enum class rr_type_t : uint16_t // record type (both QTYPE in query and TYPE ans
                                // record)
{
    A = 0x0001,
    NS = 0x0002,
    CNAME = 0x0005,
    AAAA = 0x001C,
    HTTPS = 0x0041
};

enum class class_t : uint16_t // for both QCLASS (query) and CLASS (record)
{
    IN = 0x0001,
    CH = 0x0003,
    HS = 0x0004,
    NONE = 0x00FE,
    ANY = 0x00FF
};

// Shared across query + every RR — always a domain name (or IP address)
struct dns_name_t
{
    char labels[DNS_MAX_NAME_LEN]; // decompressed, dot-separated
    uint8_t length;                // includes dot count
    size_t to_network_bytes(void *buf, size_t len) const;
};

struct dns_query_t
{
    dns_name_t q_name; // domain name
    rr_type_t
        q_type; // DNS query record type (i.e. A for ipv4 or AAAA for ipv6)
    class_t q_class;
    size_t
    copy_bytes(void *buf,
               size_t len) const; // copy *this total bytes accounting for
                                  // q_name (i.e. ignoring null-terminators)
    size_t to_string(char *buf, size_t len) const;
};

struct dns_answer_t
{
    rr_type_t r_type; // DNS reponse record type
    class_t r_class;
    uint32_t ttl; // in seconds
    uint16_t data_len;
    dns_name_t data;
    const size_t
    copy_bytes(void *buf,
               size_t len) const; // copy *this total bytes accounting for
                                  // q_name (i.e. ignoring null-terminators)
    size_t to_string(char *buf, size_t len) const;
};

/**
 * rr - resource record
 */

/** DNS HEADER **/
struct dns_header_t
{
    uint16_t transaction_id; // must be unsigned for hex representation (prevent
                             // 32 bit int promotion)
    uint16_t flags;          // must be unsigned for hex representation
    uint16_t qdcount;        // Question count - typically one for udp
    uint16_t ancount;        // number of Answers resource records
    uint16_t nscount;        // number of Authoritative resource records
    uint16_t
        arcount; // number of resource records in the Additional records section
    size_t bytes_len() const;
    size_t to_string(char *buf, size_t len) const;
};

struct dns_payload_t // as a udp payload
{
    dns_header_t header;
    /** DNS BODY **/
    dns_query_t query; // dns over udp playload is limited to 1 query per packet
    dns_answer_t
        answers[MAX_ANS_COUNT]; // assuming or expecting 16 - 24 answer range,
                                // but it could be more than this
    size_t to_string(char *buf, size_t len) const;
};

void to_host_byte_order(dns_header_t &hdr);
void to_host_byte_order(dns_query_t &q);
void to_network_byte_order(dns_answer_t &ans);
void to_network_byte_order(dns_payload_t &payload);

bool is_valid_header(dns_header_t &hdr);
} // namespace dns
