// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "enr_codec.hpp"

#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/sentry/common/crypto/ecdsa_signature.hpp>
#include <silkworm/sentry/discovery/common/node_address.hpp>

namespace silkworm::sentry::discovery::enr {

static Bytes decode_rlp_bytes(rlp::RlpByteView data, const char* key) {
    ByteView from = data.data;
    Bytes value;
    auto result = rlp::decode(from, value);
    if (!result)
        throw DecodingException(result.error(), std::string("EnrCodec: failed to decode ") + key);
    return value;
}

static rlp::RlpBytes encode_rlp_bytes(ByteView bytes) {
    Bytes data;
    rlp::encode(data, bytes);
    return rlp::RlpBytes{std::move(data)};
}

template <UnsignedIntegral T>
static T decode_rlp_num_value(rlp::RlpByteView data, const char* key) {
    ByteView from = data.data;
    T value;
    auto result = rlp::decode<T>(from, value);
    if (!result)
        throw DecodingException(result.error(), std::string("EnrCodec: failed to decode ") + key);
    return value;
}

template <UnsignedIntegral T>
static rlp::RlpBytes encode_rlp_num_value(T value) {
    Bytes data;
    rlp::encode<T>(data, value);
    return rlp::RlpBytes{std::move(data)};
}

static rlp::RlpBytes string_to_rlp_bytes(std::string_view s) {
    return encode_rlp_bytes(ByteView{reinterpret_cast<const uint8_t*>(s.data()), s.size()});
}

template <class TKey, class TValue>
static std::optional<TValue> map_get(const std::map<TKey, TValue>& entries, const TKey& key) {
    return (entries.count(key) > 0) ? std::optional{entries.at(key)} : std::nullopt;
}

static std::optional<Bytes> copy_rlp_data(std::optional<rlp::RlpByteView> data) {
    return data ? std::optional<Bytes>{Bytes{data->data}} : std::nullopt;
}

static std::optional<NodeAddress> try_decode_node_address(
    const std::map<std::string, const rlp::RlpByteView>& entries_data,
    const char* ip_key,
    const char* port_disc_key,
    const char* port_rlpx_key) {
    if (!entries_data.contains(ip_key) || !entries_data.contains(port_disc_key))
        return std::nullopt;

    auto ip = ip_address_from_bytes(decode_rlp_bytes(entries_data.at(ip_key), ip_key));
    if (!ip)
        throw std::runtime_error("EnrCodec: invalid IP address");

    auto port_disc = decode_rlp_num_value<uint16_t>(entries_data.at(port_disc_key), port_disc_key);

    uint16_t port_rlpx = 0;
    if (entries_data.contains(port_rlpx_key)) {
        port_rlpx = decode_rlp_num_value<uint16_t>(entries_data.at(port_rlpx_key), port_rlpx_key);
    }

    return NodeAddress{
        *ip,
        port_disc,
        port_rlpx,
    };
}

static bool is_valid_signature(const std::vector<rlp::RlpByteView>& items, const EccPublicKey& public_key) {
    if (items.empty())
        return false;
    Bytes signature = decode_rlp_bytes(items[0], "signature");

    std::span<const rlp::RlpByteView> content_items{items.begin() + 1, items.size() - 1};
    Bytes content;
    rlp::encode(content, content_items);

    auto content_hash = keccak256(content);
    return crypto::ecdsa_signature::verify(ByteView{content_hash.bytes}, signature, public_key);
}

static Bytes sign(const std::vector<rlp::RlpBytes>& items, ByteView private_key) {
    if (items.empty())
        return Bytes{};

    std::span<const rlp::RlpBytes> content_items{items.begin() + 1, items.size() - 1};
    Bytes content;
    rlp::encode(content, content_items);

    auto content_hash = keccak256(content);
    return crypto::ecdsa_signature::sign(ByteView{content_hash.bytes}, private_key);
}

EnrRecord EnrCodec::decode(ByteView data) {
    std::vector<rlp::RlpByteView> items;
    auto decode_result = rlp::decode(data, items, rlp::Leftover::kAllow);
    if (!decode_result)
        throw DecodingException(decode_result.error(), "EnrCodec: failed to decode RLP");
    if (items.size() < 6)
        throw std::runtime_error("EnrCodec: not enough RLP list items");
    if (items.size() % 2)
        items.pop_back();

    auto& seq_num_data = items[1];
    auto seq_num = decode_rlp_num_value<uint64_t>(seq_num_data, "seq_num");

    std::map<std::string, const rlp::RlpByteView> entries_data;
    for (size_t i = 2; i < items.size(); i += 2) {
        auto key_data = decode_rlp_bytes(items[i], "key");
        std::string key{reinterpret_cast<char*>(key_data.data()), key_data.size()};
        entries_data.emplace(key, items[i + 1]);
    }

    if (!entries_data.contains("id"))
        throw std::runtime_error("EnrCodec: missing required 'id' key");
    if (decode_rlp_bytes(entries_data.at("id"), "id") != Bytes{'v', '4'})
        throw std::runtime_error("EnrCodec: unsupported ID scheme");

    if (!entries_data.contains("secp256k1"))
        throw std::runtime_error("EnrCodec: missing required 'secp256k1' key");
    auto public_key = EccPublicKey::deserialize_std(decode_rlp_bytes(entries_data.at("secp256k1"), "secp256k1"));

    if (!is_valid_signature(items, public_key))
        throw std::runtime_error("EnrCodec: invalid signature");

    auto node_address_v4 = try_decode_node_address(entries_data, "ip", "udp", "tcp");
    auto node_address_v6 = try_decode_node_address(entries_data, "ip6", "udp6", "tcp6");

    return EnrRecord{
        std::move(public_key),
        seq_num,
        std::move(node_address_v4),
        std::move(node_address_v6),
        copy_rlp_data(map_get(entries_data, std::string("eth"))),
        copy_rlp_data(map_get(entries_data, std::string("eth2"))),
        copy_rlp_data(map_get(entries_data, std::string("attnets"))),
    };
}

Bytes EnrCodec::encode(const EnrRecord& record, const EccKeyPair& key_pair) {
    std::map<std::string, rlp::RlpBytes> entries;
    entries.emplace("id", string_to_rlp_bytes("v4"));
    entries.emplace("secp256k1", encode_rlp_bytes(key_pair.public_key().serialized_std(/* is_compressed = */ true)));

    if (record.address_v4) {
        entries.emplace("ip", encode_rlp_bytes(ip_address_to_bytes(record.address_v4->endpoint.address())));
        entries.emplace("udp", encode_rlp_num_value(record.address_v4->endpoint.port()));
        if (record.address_v4->port_rlpx) {
            entries.emplace("tcp", encode_rlp_num_value(record.address_v4->port_rlpx));
        }
    }

    if (record.address_v6) {
        entries.emplace("ip6", encode_rlp_bytes(ip_address_to_bytes(record.address_v6->endpoint.address())));
        entries.emplace("udp6", encode_rlp_num_value(record.address_v6->endpoint.port()));
        if (record.address_v6->port_rlpx) {
            entries.emplace("tcp6", encode_rlp_num_value(record.address_v6->port_rlpx));
        }
    }

    if (record.eth1_fork_id_data) {
        entries.emplace("eth", rlp::RlpBytes{*record.eth1_fork_id_data});
    }

    if (record.eth2_fork_id_data) {
        entries.emplace("eth2", rlp::RlpBytes{*record.eth2_fork_id_data});
    }

    if (record.eth2_attestation_subnets_data) {
        entries.emplace("attnets", rlp::RlpBytes{*record.eth2_attestation_subnets_data});
    }

    std::vector<rlp::RlpBytes> items = {
        rlp::RlpBytes{Bytes{rlp::kEmptyStringCode}},  // signature placeholder
        encode_rlp_num_value(record.seq_num),
    };

    for (auto& [key, entry_data] : entries) {
        items.push_back(string_to_rlp_bytes(key));
        items.push_back(std::move(entry_data));
    }

    // set signature
    Bytes signature = sign(items, key_pair.private_key());
    items[0] = encode_rlp_bytes(signature);

    Bytes data;
    rlp::encode(data, items);
    return data;
}

}  // namespace silkworm::sentry::discovery::enr
