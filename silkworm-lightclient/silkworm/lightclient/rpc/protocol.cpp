/*
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "protocol.hpp"

#include <algorithm>

#include <silkworm/common/log.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/lightclient/rpc/varint.hpp>
#include <silkworm/lightclient/snappy/snappy_codec.hpp>

namespace silkworm::cl::sentinel {

//! The maximum size of packet length in bytes
constexpr std::size_t kMaxLengthSize{10};

//! The size of response fork digest in bytes
constexpr std::size_t kForkDigestSize{4};

Bytes encode_and_write(const ::ssz::Container& object) {
    // Create prefix for packet length
    Bytes length_buffer{kMaxLengthSize, '\0'};
    const auto length_size = encode_varint(object.get_ssz_size(), length_buffer);

    // Marshal object into message using SSZ and snap it
    const auto payload = object.serialize();
    Bytes compressed_payload = snappy::compress({payload.data(), payload.size()});

    // Put together length + payload
    Bytes protocol_packet;
    protocol_packet.reserve(kMaxLengthSize + object.get_ssz_size());
    protocol_packet.append(length_buffer.data(), length_size);
    protocol_packet.append(compressed_payload.data(), compressed_payload.size());

    return protocol_packet;
}

bool decode_and_read(ByteView data, ::ssz::Container& object) {
    if (data.size() < kForkDigestSize) {
        log::Error() << "decode_and_read: data size too short: " << to_hex(data);
        return false;
    }

    Bytes fork_digest_buffer{kForkDigestSize, '\0'};
    std::copy(data.cbegin(), data.cbegin() + kForkDigestSize, fork_digest_buffer.begin());
    // TODO(canepat) check fork digest matches: compute_fork_digest(fork_version, genesis_validators_root)

    return decode_and_read_no_context(data.substr(kForkDigestSize), object);
}

bool decode_and_read_no_context(ByteView data, ::ssz::Container& object) {
    // Extract prefix for packet length
    std::size_t encoded_length;
    const std::size_t length_size = decode_varint(data, encoded_length);

    if (encoded_length != object.get_ssz_size()) {
        log::Error() << "decode_and_read_no_context: encoded length " << encoded_length
                     << " does not match expected " << object.get_ssz_size();
        return false;
    }

    // Unsnap the message and then unmarshall using SSZ
    Bytes payload = snappy::decompress(data.substr(length_size));
    const bool ok = object.deserialize(payload.cbegin(), payload.cend());
    if (!ok) {
        log::Error() << "decode_and_read_no_context: cannot unmarshal message " << to_hex(payload);
        return false;
    }

    return true;
}

}  // namespace silkworm::cl::sentinel
