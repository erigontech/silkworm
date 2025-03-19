/*
   Copyright 2024 The Silkworm Authors

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
