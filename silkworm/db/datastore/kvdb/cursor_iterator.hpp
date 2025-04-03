// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <iterator>
#include <memory>
#include <utility>

#include "codec.hpp"
#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

class CursorMoveIterator {
  public:
    using value_type = std::shared_ptr<ROCursor>;
    using iterator_category [[maybe_unused]] = std::input_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;

    CursorMoveIterator() = default;

    CursorMoveIterator(
        std::shared_ptr<ROCursor> cursor,
        MoveOperation move_op)
        : cursor_{std::move(cursor)},
          move_op_{move_op} {}

    const value_type& operator*() const { return cursor_; }
    const value_type* operator->() const { return &cursor_; }

    CursorMoveIterator operator++(int) { return std::exchange(*this, ++CursorMoveIterator{*this}); }
    CursorMoveIterator& operator++() {
        if (((move_op_ == MoveOperation::get_current) && cursor_->eof()) || !cursor_->move(move_op_, false)) {
            cursor_.reset();
        }
        return *this;
    }

    friend bool operator!=(const CursorMoveIterator& it, const std::default_sentinel_t&) {
        return !!it.cursor_;
    }
    friend bool operator==(const CursorMoveIterator& it, const std::default_sentinel_t&) {
        return !it.cursor_;
    }
    friend bool operator!=(const std::default_sentinel_t&, const CursorMoveIterator& it) {
        return !!it.cursor_;
    }
    friend bool operator==(const std::default_sentinel_t&, const CursorMoveIterator& it) {
        return !it.cursor_;
    }

  private:
    std::shared_ptr<ROCursor> cursor_;
    MoveOperation move_op_{MoveOperation::next};
};

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
    MoveOperation move_op_{MoveOperation::next};
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

    static CursorKVIterator make(
        std::unique_ptr<ROCursor> cursor,
        MoveOperation move_op,
        std::function<TKeyDecoder()> key_decoder_factory,
        std::function<TValueDecoder()> value_decoder_factory) {
        return CursorKVIterator{CursorIterator{std::move(cursor), move_op, std::make_shared<TKeyDecoder>(key_decoder_factory()), std::make_shared<TValueDecoder>(value_decoder_factory())}};
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

    static CursorKeysIterator make(
        std::unique_ptr<ROCursor> cursor,
        MoveOperation move_op,
        std::function<TKeyDecoder()> key_decoder_factory) {
        return CursorKeysIterator{CursorIterator{std::move(cursor), move_op, std::make_shared<TKeyDecoder>(key_decoder_factory()), {}}};
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

    static CursorValuesIterator make(
        std::unique_ptr<ROCursor> cursor,
        MoveOperation move_op,
        std::function<TValueDecoder()> value_decoder_factory) {
        return CursorValuesIterator{CursorIterator{std::move(cursor), move_op, {}, std::make_shared<TValueDecoder>(value_decoder_factory())}};
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
