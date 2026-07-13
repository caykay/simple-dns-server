#include "dns.h"

#include <arpa/inet.h>

#define HDR_FIELD_STR_LEN 10

namespace
{
size_t to_string(dns::rr_type_t type, char *buf, size_t len)
{
    static constexpr const char *fmt = "%s";
    switch (type)
    {
    case dns::rr_type_t::A:
        return snprintf(buf, len, fmt, "A");
    case dns::rr_type_t::NS:
        return snprintf(buf, len, fmt, "NS");
    case dns::rr_type_t::CNAME:
        return snprintf(buf, len, fmt, "CNAME");
    case dns::rr_type_t::AAAA:
        return snprintf(buf, len, fmt, "AAAA");
    case dns::rr_type_t::HTTPS:
        return snprintf(buf, len, fmt, "HTTPS");
    }
}

size_t to_string(dns::class_t rrclass, char *buf, size_t len)
{
    static constexpr const char *fmt = "%s";
    switch (rrclass)
    {
    case dns::class_t::IN:
        return snprintf(buf, len, fmt, "IN");
    case dns::class_t::CH:
        return snprintf(buf, len, fmt, "CH");
    case dns::class_t::HS:
        return snprintf(buf, len, fmt, "HS");
    case dns::class_t::NONE:
        return snprintf(buf, len, fmt, "NONE");
    case dns::class_t::ANY:
        return snprintf(buf, len, fmt, "ANY");
    }
}
} // namespace

namespace dns
{
size_t dns_header_t::to_string(char *buf, size_t len) const
{
    static constexpr const char *fmt =
        "trans_id:0x%04x, flags:0x%04x, QDCOUNT:%hu, "
        "ANCOUNT:%hu, NSCOUNT:%hu, ARCOUNT:%hu\n";
    return snprintf(buf, len, fmt, transaction_id, flags, qdcount, ancount,
                    nscount, arcount);
}

size_t dns_query_t::to_string(char *buf, size_t len) const
{
    static constexpr const char *fmt = "Name: %s, type:%s, class:%s\n";
    char rrtype[HDR_FIELD_STR_LEN];
    char rrclass[HDR_FIELD_STR_LEN];
    ::to_string(q_type, rrtype, HDR_FIELD_STR_LEN);
    ::to_string(q_class, rrclass, HDR_FIELD_STR_LEN);
    return snprintf(buf, len, fmt, q_name, rrtype, rrclass);
}

size_t dns_answer_t::to_string(char *buf, size_t len) const
{
    static constexpr const char *fmt =
        "Name: %s, type:%s, class:%s, ttl:%hu, len:%hu, Data:%s\n";
    char rrtype[HDR_FIELD_STR_LEN];
    char rrclass[HDR_FIELD_STR_LEN];
    ::to_string(r_type, rrtype, HDR_FIELD_STR_LEN);
    ::to_string(r_class, rrclass, HDR_FIELD_STR_LEN);
    return snprintf(buf, len, fmt, r_name, rrtype, rrclass, ttl, data_len,
                    data);
}

bool is_valid_header(dns_header_t &hdr)
{
    if (hdr.qdcount != 1)
        return false;
    // validate flags
    // 1. check QR bit (whether or not it's a response)
    bool is_query = (hdr.flags >> 15) == DNS_FLAGS_QR_QUERY;
    if (is_query)
    {
        if ((hdr.nscount + hdr.ancount) >= 1 && hdr.arcount > 1)
            return false;
    }
    else
        return false; // server only supports the qr_query bit flag
    // 2. validate op code (only accept queries)
    if ((hdr.flags & DNS_FLAGS_OPCODE_MASK) != DNS_FLAGS_OPCODE_QUERY)
    {
        printf("%s: Invalid opcode", __func__);
        return false;
    }

    return true;
}

void to_host_byte_order(dns_header_t &hdr)
{
    hdr.transaction_id = ntohs(hdr.transaction_id);
    hdr.flags = ntohs(hdr.flags);
    hdr.qdcount = ntohs(hdr.qdcount);
    hdr.ancount = ntohs(hdr.ancount);
    hdr.nscount = ntohs(hdr.nscount);
    hdr.arcount = ntohs(hdr.arcount);
}

void to_host_byte_order(dns_query_t &q)
{
    q.q_type = (rr_type_t)ntohs((uint16_t)q.q_type);
    q.q_class = (class_t)ntohs((uint16_t)q.q_class);
}
} // namespace dns
