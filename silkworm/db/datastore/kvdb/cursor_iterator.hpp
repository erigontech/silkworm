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

#include <iterator>
#include <memory>
#include <utility>

#include "codec.hpp"
#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

class CursorIterator {
  public:
    using value_type = std::pair<std::shared_ptr<Decoder>, std::shared_ptr<Decoder>>;
    using iterator_category [[maybe_unused]] = std::input_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;

    CursorIterator() = default;

    CursorIterator(
        std::shared_ptr<ROCursor> cursor,
        MoveOperation move_op,
        std::shared_ptr<Decoder> key_decoder,
        std::shared_ptr<Decoder> value_decoder)
        : cursor_{std::move(cursor)},
          move_op_{move_op},
          decoders_{std::move(key_decoder), std::move(value_decoder)} {
        decode(cursor_->current(false));
    }

    value_type operator*() const { return decoders_; }
    const value_type* operator->() const { return &decoders_; }

    CursorIterator operator++(int) { return std::exchange(*this, ++CursorIterator{*this}); }
    CursorIterator& operator++() {
        decode(cursor_->move(move_op_, false));
        return *this;
    }

    friend bool operator!=(const CursorIterator& lhs, const CursorIterator& rhs) = default;
    friend bool operator==(const CursorIterator& lhs, const CursorIterator& rhs);

  private:
    void decode(const CursorResult& result);
    std::shared_ptr<ROCursor> cursor_;
    MoveOperation move_op_;
    value_type decoders_;
};

template <DecoderConcept TKeyDecoder, DecoderConcept TValueDecoder>
class CursorKVIterator {
  public:
    using value_type_owned = std::pair<decltype(TKeyDecoder::value), decltype(TValueDecoder::value)>;
    using value_type = std::pair<decltype(TKeyDecoder::value)&, decltype(TValueDecoder::value)&>;
    using iterator_category [[maybe_unused]] = std::input_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;

    CursorKVIterator() = default;

    explicit CursorKVIterator(CursorIterator it)
        : it_{std::move(it)} {}

    static CursorKVIterator make(std::unique_ptr<ROCursor> cursor, MoveOperation move_op) {
        return CursorKVIterator{CursorIterator{std::move(cursor), move_op, std::make_shared<TKeyDecoder>(), std::make_shared<TValueDecoder>()}};
    }

    value_type operator*() const { return value(); }

    value_type_owned move_value() const {
        value_type value = this->value();
        return {std::move(value.first), std::move(value.second)};
    }

    CursorKVIterator operator++(int) { return std::exchange(*this, ++CursorKVIterator{*this}); }
    CursorKVIterator& operator++() {
        ++it_;
        return *this;
    }

    friend bool operator!=(const CursorKVIterator& lhs, const CursorKVIterator& rhs) = default;
    friend bool operator==(const CursorKVIterator& lhs, const CursorKVIterator& rhs) = default;

  private:
    value_type value() const {
        Decoder& base_key_decoder = *(it_->first);
        Decoder& base_value_decoder = *(it_->second);
        // dynamic_cast is safe if TKeyDecoder was used when creating the CursorIterator
        auto& key_decoder = dynamic_cast<TKeyDecoder&>(base_key_decoder);
        // dynamic_cast is safe if TValueDecoder was used when creating the CursorIterator
        auto& key_value_decoder = dynamic_cast<TValueDecoder&>(base_value_decoder);
        return {key_decoder.value, key_value_decoder.value};
    }

    CursorIterator it_;
};

template <DecoderConcept TKeyDecoder>
class CursorKeysIterator {
  public:
    using value_type = decltype(TKeyDecoder::value);
    using iterator_category [[maybe_unused]] = std::input_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;

    CursorKeysIterator() = default;

    explicit CursorKeysIterator(CursorIterator it)
        : it_{std::move(it)} {}

    static CursorKeysIterator make(std::unique_ptr<ROCursor> cursor, MoveOperation move_op) {
        return CursorKeysIterator{CursorIterator{std::move(cursor), move_op, std::make_shared<TKeyDecoder>(), {}}};
    }

    reference operator*() const { return value(); }
    pointer operator->() const { return &value(); }

    CursorKeysIterator operator++(int) { return std::exchange(*this, ++CursorKeysIterator{*this}); }
    CursorKeysIterator& operator++() {
        ++it_;
        return *this;
    }

    friend bool operator!=(const CursorKeysIterator& lhs, const CursorKeysIterator& rhs) = default;
    friend bool operator==(const CursorKeysIterator& lhs, const CursorKeysIterator& rhs) = default;

  private:
    value_type& value() const {
        Decoder& base_key_decoder = *(it_->first);
        // dynamic_cast is safe if TKeyDecoder was used when creating the CursorIterator
        auto& key_decoder = dynamic_cast<TKeyDecoder&>(base_key_decoder);
        return key_decoder.value;
    }

    CursorIterator it_;
};

template <DecoderConcept TValueDecoder>
class CursorValuesIterator {
  public:
    using value_type = decltype(TValueDecoder::value);
    using iterator_category [[maybe_unused]] = std::input_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;

    CursorValuesIterator() = default;

    explicit CursorValuesIterator(CursorIterator it)
        : it_{std::move(it)} {}

    static CursorValuesIterator make(std::unique_ptr<ROCursor> cursor, MoveOperation move_op) {
        return CursorValuesIterator{CursorIterator{std::move(cursor), move_op, {}, std::make_shared<TValueDecoder>()}};
    }

    reference operator*() const { return value(); }
    pointer operator->() const { return &value(); }

    CursorValuesIterator operator++(int) { return std::exchange(*this, ++CursorValuesIterator{*this}); }
    CursorValuesIterator& operator++() {
        ++it_;
        return *this;
    }

    friend bool operator!=(const CursorValuesIterator& lhs, const CursorValuesIterator& rhs) = default;
    friend bool operator==(const CursorValuesIterator& lhs, const CursorValuesIterator& rhs) = default;

  private:
    value_type& value() const {
        Decoder& base_value_decoder = *(it_->second);
        // dynamic_cast is safe if TValueDecoder was used when creating the CursorIterator
        auto& value_decoder = dynamic_cast<TValueDecoder&>(base_value_decoder);
        return value_decoder.value;
    }

    CursorIterator it_;
};

}  // namespace silkworm::datastore::kvdb
