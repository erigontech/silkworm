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

#pragma once

#include "codec.hpp"
#include "raw_codec.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TEncoder, EncoderConcept TTimestampEncoder>
class KVTSKeyEncoder : public Encoder {
  public:
    struct {
        TEncoder key;
        TTimestampEncoder timestamp;
    } value;

    explicit KVTSKeyEncoder(bool has_large_values)
        : has_large_values_{has_large_values} {}
    ~KVTSKeyEncoder() override = default;

    Slice encode() override {
        data_.clear();
        if (has_large_values_) {
            // encode as key + timestamp
            data_.append(from_slice(value.key.encode()));
            data_.append(from_slice(value.timestamp.encode()));
            return to_slice(data_);
        }
        return value.key.encode();
    }

  private:
    bool has_large_values_;
    Bytes data_;
};

template <EncoderConcept TEncoder, EncoderConcept TTimestampEncoder>
class KVTSValueEncoder : public Encoder {
  public:
    struct {
        TEncoder value;
        TTimestampEncoder timestamp;
    } value;

    explicit KVTSValueEncoder(bool has_large_values)
        : has_large_values_{has_large_values} {}
    ~KVTSValueEncoder() override = default;

    Slice encode() override {
        data_.clear();
        if (has_large_values_) {
            return value.value.encode();
        }
        // encode as timestamp + value
        data_.append(from_slice(value.timestamp.encode()));
        data_.append(from_slice(value.value.encode()));
        return to_slice(data_);
    }

  private:
    bool has_large_values_;
    Bytes data_;
};

static_assert(EncoderConcept<KVTSKeyEncoder<RawEncoder<Bytes>, RawEncoder<Bytes>>>);
static_assert(EncoderConcept<KVTSValueEncoder<RawEncoder<Bytes>, RawEncoder<Bytes>>>);

template <DecoderConcept TDecoder, DecoderConcept TTimestampDecoder, size_t kEncodedTimestampSize>
class KVTSKeyDecoder : public Decoder {
  public:
    struct {
        TDecoder key;
        TTimestampDecoder timestamp;
    } value;

    explicit KVTSKeyDecoder(bool has_large_values)
        : has_large_values_{has_large_values} {}
    ~KVTSKeyDecoder() override = default;

    void decode(Slice data) override {
        if (has_large_values_) {
            // decode as key + timestamp
            SILKWORM_ASSERT(data.size() >= kEncodedTimestampSize);
            value.key.decode(to_slice(from_slice(data).substr(0, data.size() - kEncodedTimestampSize)));
            value.timestamp.decode(to_slice(from_slice(data).substr(data.size() - kEncodedTimestampSize, kEncodedTimestampSize)));
        } else {
            value.key.decode(data);
        }
    }

  private:
    bool has_large_values_;
};

template <DecoderConcept TDecoder, DecoderConcept TTimestampDecoder, size_t kEncodedTimestampSize>
class KVTSValueDecoder : public Decoder {
  public:
    struct {
        TDecoder value;
        TTimestampDecoder timestamp;
    } value;

    explicit KVTSValueDecoder(bool has_large_values)
        : has_large_values_{has_large_values} {}
    ~KVTSValueDecoder() override = default;

    void decode(Slice slice) override {
        if (has_large_values_) {
            value.value.decode(slice);
        } else {
            // decode as timestamp + value
            SILKWORM_ASSERT(slice.size() >= kEncodedTimestampSize);
            value.timestamp.decode(to_slice(from_slice(slice).substr(0, kEncodedTimestampSize)));
            value.value.decode(to_slice(from_slice(slice).substr(kEncodedTimestampSize)));
        }
    }

  private:
    bool has_large_values_;
};

static_assert(DecoderConcept<KVTSKeyDecoder<RawDecoder<Bytes>, RawDecoder<Bytes>, sizeof(uint64_t)>>);
static_assert(DecoderConcept<KVTSValueDecoder<RawDecoder<Bytes>, RawDecoder<Bytes>, sizeof(uint64_t)>>);

}  // namespace silkworm::datastore::kvdb
