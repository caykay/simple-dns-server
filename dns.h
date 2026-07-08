#include <cstddef>
#include <cstdint>
#include <cstdio>

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

enum class dns_flags_t : uint16_t
{
    FLAGS_QR_RESPONSE = 0x8000,

    FLAGS_OPCODE_QUERY = 0x0000,
    // mask with FLAGS_OPCODE_MASK to isolate or clear OPCODE flag bits
    // & FLAGS_OPCODE_MASK to isolate
    // | FLAGS_OPCODE_MASK to clear
    FLAGS_OPCODE_MASK = 0x7800,

    // Authoritative Answer
    FLAGS_AA = 0x0400, // 1 = Responding server owns the zone

    // Response Codes (Mask with 0x000F to isolate)
    FLAGS_RCODE_MASK = 0x000F,
    FLAGS_RCODE_NOERROR = 0x0000,  // Success
    FLAGS_RCODE_FORMERR = 0x0001,  // Format Error
    FLAGS_RCODE_SERVFAIL = 0x0002, // Server Failure
    FLAGS_RCODE_NXDOMAIN = 0x0003, // Domain Name Error (Does not exist)
    FLAGS_RCODE_NOTIMP = 0x0004,   // Not Implemented
    FLAGS_RCODE_REFUSED = 0x0005   // Query Refused
};

struct dns_query_t
{
    char q_name[256]; // domain name
    rr_type_t
        q_type; // DNS query record type (i.e. A for ipv4 or AAAA for ipv6)
    class_t q_class;
    size_t to_string(char *buf, size_t len) const;
};

struct dns_answer_t
{
    char r_name[256]; // can probably be optimized to a ptr of
                      // dns_query_t::q_name
    rr_type_t r_type; // DNS reponse record type
    class_t r_class;
    uint32_t ttl; // in seconds
    uint16_t data_len;
    char data[256];
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
    size_t to_string(char *buf, size_t len) const;
};

struct dns_payload_t // as a udp payload
{
    dns_header_t header;
    /** DNS BODY **/
    dns_query_t query; // dns over udp playload is limited to 1 query per packet
    dns_answer_t answers[30]; // assuming or expecting 16 - 24 answer range, but
                              // it could be more than this
    void to_string(char *buf, size_t len) const;
};

void to_network_byte_order(dns_header_t &hdr);
void to_network_byte_order(dns_query_t &q);
void to_network_byte_order(dns_answer_t &r);
void to_network_byte_order(dns_payload_t &payload);

bool is_valid_header(dns_header_t &hdr);
} // namespace dns
