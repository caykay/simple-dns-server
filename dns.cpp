#include "dns.h"
#include "shared.h"

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>

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
size_t dns_name_t::write(const char *buf, size_t len)
{
    uint8_t label_len = 0;
    memcpy(&label_len, buf, sizeof(uint8_t));
    uint8_t offset = 0;
    while (label_len > 0)
    {
        label_len++; // include the label len byte;
        memcpy(bytes + offset, buf + offset, label_len);
        offset += label_len;
        memcpy(&label_len, buf + offset, sizeof(uint8_t));
    }
    bytes[offset] = 0x00;
    length = offset + 1; // include the 0x00 trailing byte
    return length;
}

size_t dns_name_t::to_string(char *buf, size_t len) const
{
    uint8_t label_len = 0;
    memcpy(&label_len, bytes, sizeof(uint8_t));
    size_t written = 0, offset = 0;
    while (label_len > 0)
    {
        char label[LABEL_SIZE_MAX];
        ZERO_MEM(label, LABEL_SIZE_MAX);
        offset++; // skip label_len byte
        memcpy(label, bytes + offset, label_len);
        written +=
            snprintf(buf + written, len, "%s%s", written > 0 ? "." : "", label);
        offset += label_len;
        memcpy(&label_len, bytes + offset, sizeof(uint8_t));
    }
    return written;
}

size_t dns_header_t::copy_bytes(uint8_t *buf, size_t len) const
{
    if (len < DNS_MAX_HEADER_LEN)
        return 0;
    memcpy(buf, &transaction_id, DNS_MAX_HEADER_LEN);
    return DNS_MAX_HEADER_LEN;
}

size_t dns_header_t::to_string(char *buf, size_t len) const
{
    static constexpr const char *fmt =
        "trans_id:0x%04x, flags:0x%04x, QDCOUNT:%hu, "
        "ANCOUNT:%hu, NSCOUNT:%hu, ARCOUNT:%hu\n";
    return snprintf(buf, len, fmt, transaction_id, flags, qdcount, ancount,
                    nscount, arcount);
}

size_t dns_query_t::copy_bytes(uint8_t *buf, size_t len) const
{
    if (len < (q_name.length + sizeof(uint16_t) * 2))
        return 0;
    size_t count = 0;
    memcpy(buf, q_name.bytes, q_name.length);
    count += q_name.length;
    memcpy(buf + count, &q_class, sizeof(uint16_t));
    count += sizeof(uint16_t);
    memcpy(buf + count, &q_type, sizeof(uint16_t));
    count += sizeof(uint16_t);
    return count;
}

size_t dns_query_t::to_string(char *buf, size_t len) const
{
    static constexpr const char *fmt = "Name: %s, type:%s, class:%s\n";
    char rrtype[HDR_FIELD_STR_LEN];
    char rrclass[HDR_FIELD_STR_LEN];
    ::to_string(q_type, rrtype, HDR_FIELD_STR_LEN);
    ::to_string(q_class, rrclass, HDR_FIELD_STR_LEN);
    // name
    char name[DNS_MAX_NAME_LEN];
    q_name.to_string(name, DNS_MAX_NAME_LEN);
    return snprintf(buf, len, fmt, name, rrtype, rrclass);
}

size_t dns_answer_t::copy_bytes(uint8_t *buf, size_t len) const
{
    size_t count = 0;
    const size_t bytes_before_data = sizeof(uint16_t) * 3 + sizeof(uint32_t);
    if (len < (bytes_before_data + data.length))
        return 0;
    memcpy(buf, &r_type, bytes_before_data);
    count += bytes_before_data;
    memcpy(buf + count, data.bytes, data.length);
    count += data.length;
    return count;
}

size_t dns_answer_t::to_string(char *buf, size_t len) const
{
    static constexpr const char *fmt =
        "type:%s, class:%s, ttl:%hu, len:%hu, Data:%s\n";
    char rrtype[HDR_FIELD_STR_LEN];
    char rrclass[HDR_FIELD_STR_LEN];
    ::to_string(r_type, rrtype, HDR_FIELD_STR_LEN);
    ::to_string(r_class, rrclass, HDR_FIELD_STR_LEN);

    char name[DNS_MAX_NAME_LEN];
    data.to_string(name, DNS_MAX_NAME_LEN);

    return snprintf(buf, len, fmt, rrtype, rrclass, ttl, data.length, name);
}

size_t dns_payload_t::copy_bytes(uint8_t *buf, size_t len,
                                 uint16_t ancount) const
{
    // guard against endian converted answer count
    if (ancount > MAX_ANS_COUNT)
        return 0;
    size_t count = 0;
    count += header.copy_bytes(buf, len);
    count += query.copy_bytes(buf + count, len - count);
    for (int i = 0; i < ancount; i++)
    {
        if (header.ancount == 1)
        {
            // lightweight: only write a pointer byte to question's name

            // 0xc0 is ptr marker; 0x0c 12 byte offset from dns payload begin
            // (i.e. after hader) char ptr allows us to bypass endianness (the
            // following bytes are in network byte order)
            char ptr[] = "0xc00c";
            memcpy(buf + count, ptr, sizeof(uint16_t));
            count += sizeof(uint16_t);
            count += answers[i].copy_bytes(buf + count, len - count);
        }
    }
    return count;
}

size_t dns_payload_t::to_string(char *buf, size_t len) const
{
    size_t bytes_written = 0;
    bytes_written += header.to_string(buf, len);
    bytes_written += query.to_string(buf + bytes_written, len - bytes_written);
    for (int i = 0; i < header.ancount; i++)
    {
        bytes_written +=
            answers[i].to_string(buf + bytes_written, len - bytes_written);
    }
    return bytes_written;
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

void to_network_byte_order(dns_answer_t &ans)
{
    ans.data_len = htons(ans.data_len);
    ans.r_type = (rr_type_t)htons((uint16_t)ans.r_type);
    ans.r_class = (class_t)htons((uint16_t)ans.r_class);
    ans.ttl = htons(ans.ttl);
}

void to_network_byte_order(dns_payload_t &payload, uint16_t ans_count)
{
    // nthos and hton do the same thing, it's just semantic ordering
    to_host_byte_order(payload.query);
    to_host_byte_order(payload.header);
    for (int i = 0; i < ans_count; i++)
    {
        to_network_byte_order(payload.answers[i]);
    }
}
} // namespace dns
