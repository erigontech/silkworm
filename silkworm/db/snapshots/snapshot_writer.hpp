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

#include <concepts>
#include <filesystem>
#include <iterator>
#include <memory>

#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/db/snapshots/seg/compressor.hpp>

#include "snapshot_word_serializer.hpp"

namespace silkworm::snapshots {

class SnapshotFileWriter {
  public:
    class Iterator {
      public:
        using value_type = std::shared_ptr<SnapshotWordSerializer>;
        using iterator_category = std::output_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = void;

        Iterator(
            seg::Compressor::Iterator it,
            std::shared_ptr<SnapshotWordSerializer> serializer)
            : it_(it), serializer_(std::move(serializer)) {}

        Iterator& operator*() { return *this; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            ++it_;
            return *this;
        }

        Iterator& operator=(const value_type& value);

        std::shared_ptr<SnapshotWordSerializer> serializer() const { return serializer_; }

      private:
        seg::Compressor::Iterator it_;
        std::shared_ptr<SnapshotWordSerializer> serializer_;
    };

    static_assert(std::output_iterator<Iterator, typename Iterator::value_type>);

    explicit SnapshotFileWriter(
        SnapshotPath path,
        const std::filesystem::path& tmp_dir_path);

    SnapshotFileWriter(SnapshotFileWriter&&) = default;
    SnapshotFileWriter& operator=(SnapshotFileWriter&&) = default;

    [[nodiscard]] SnapshotPath path() const { return path_; }

    Iterator out(std::shared_ptr<SnapshotWordSerializer> serializer);

    static void flush(SnapshotFileWriter writer);

  private:
    SnapshotPath path_;
    seg::Compressor compressor_;
};

template <SnapshotWordSerializerConcept TWordSerializer>
class SnapshotWriter {
  public:
    class Iterator {
      public:
        using value_type = decltype(TWordSerializer::value);
        using iterator_category = std::output_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = void;

        explicit Iterator(SnapshotFileWriter::Iterator it)
            : it_(std::move(it)) {}

        Iterator& operator*() { return *this; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            ++it_;
            return *this;
        }

        Iterator& operator=(value_type value) {
            *it_ = set_value(std::move(value));
            return *this;
        }

      private:
        SnapshotFileWriter::Iterator::value_type set_value(value_type value) {
            SnapshotWordSerializer& base_serializer = *it_.serializer();
            // dynamic_cast is safe because TWordSerializer was used when creating the Iterator
            auto& s = dynamic_cast<TWordSerializer&>(base_serializer);
            s.value = std::move(value);
            return it_.serializer();
        }

        SnapshotFileWriter::Iterator it_;
    };

    static_assert(std::output_iterator<Iterator, typename Iterator::value_type>);

    using WordDeserializer = TWordSerializer;

    SnapshotWriter(SnapshotFileWriter& snapshot) : snapshot_(snapshot) {}

    Iterator out() {
        return Iterator{snapshot_.out(std::make_shared<TWordSerializer>())};
    }

  private:
    SnapshotFileWriter& snapshot_;
};

template <class TSnapshotWriter>
concept SnapshotWriterConcept = std::same_as<TSnapshotWriter, SnapshotWriter<typename TSnapshotWriter::WordDeserializer>> ||
                                std::derived_from<TSnapshotWriter, SnapshotWriter<typename TSnapshotWriter::WordDeserializer>>;

}  // namespace silkworm::snapshots
