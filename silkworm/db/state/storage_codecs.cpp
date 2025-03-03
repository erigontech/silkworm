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

datastore::kvdb::Slice StorageAddressAndLocationKVDBEncoder::encode() {
    // TODO: this extra copy could be avoided if encoders are able to contain a reference
    encoder.address.value = value.address;
    encoder.location_hash.value = value.location_hash;

    data.clear();
    data.reserve(kAddressLength + kHashLength);
    data.append(datastore::kvdb::from_slice(encoder.address.encode()));
    data.append(datastore::kvdb::from_slice(encoder.location_hash.encode()));
    return datastore::kvdb::to_slice(data);
}

ByteView StorageAddressAndLocationSnapshotsCodec::encode_word() {
    // TODO: this extra copy could be avoided if encoders are able to contain a reference
    codec.address.value = value.address;
    codec.location_hash.value = value.location_hash;

    word.clear();
    word.reserve(kAddressLength + kHashLength);
    word.append(codec.address.encode_word());
    word.append(codec.location_hash.encode_word());
    return word;
}

void StorageAddressAndLocationSnapshotsCodec::decode_word(Bytes& input_word) {
    codec.address.decode_word(input_word);
    auto input_word_remaining = input_word.substr(kAddressLength);
    codec.location_hash.decode_word(input_word_remaining);
    value = {codec.address.value, codec.location_hash.value};
}

}  // namespace silkworm::db::state
