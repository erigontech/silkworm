// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "storage_codecs.hpp"

namespace silkworm::db::state {

static_assert(sizeof(StorageAddressAndLocation) == kAddressLength + kHashLength);

datastore::kvdb::Slice StorageAddressAndLocationKVDBEncoder::encode() {
    ByteView data{reinterpret_cast<uint8_t*>(&value), sizeof(StorageAddressAndLocation)};
    return datastore::kvdb::to_slice(data);
}

ByteView StorageAddressAndLocationSnapshotsCodec::encode_word() {
    return ByteView{reinterpret_cast<uint8_t*>(&value), sizeof(StorageAddressAndLocation)};
}

void StorageAddressAndLocationKVDBEncoder::decode(datastore::kvdb::Slice slice) {
    codec.address.decode(slice);
    slice.remove_prefix(kAddressLength);
    codec.location_hash.decode(slice);
    value = {codec.address.value, codec.location_hash.value};
}

void StorageAddressAndLocationSnapshotsCodec::decode_word(Word& input_word) {
    codec.address.decode_word(input_word);
    auto input_word_remaining = input_word.substr(kAddressLength);
    codec.location_hash.decode_word(input_word_remaining);
    value = {codec.address.value, codec.location_hash.value};
}

}  // namespace silkworm::db::state
