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

#include "index_builder.hpp"

#include <silkworm/infra/common/log.hpp>

#include "rec_split/rec_split.hpp"
#include "rec_split/rec_split_seq.hpp"

namespace silkworm::snapshots {

using RecSplitSettings = rec_split::RecSplitSettings;
using RecSplit8 = rec_split::RecSplit8;

IndexInputDataQuery::Iterator& IndexInputDataQuery::Iterator::operator++() {
    auto next = query_->next_iterator(impl_);
    impl_ = next.first;
    entry_ = next.second;
    return *this;
}

bool operator==(const IndexInputDataQuery::Iterator& lhs, const IndexInputDataQuery::Iterator& rhs) {
    return (lhs.query_ == rhs.query_) &&
           lhs.query_->equal_iterators(lhs.impl_, rhs.impl_);
}

static IndexInputDataQuery::Iterator::value_type decompressor_index_query_entry(seg::Decompressor::Iterator& it) {
    return {
        .key_data = *it,
        .value = it.current_word_offset(),
    };
}

IndexInputDataQuery::Iterator DecompressorIndexInputDataQuery::begin() {
    auto decompressor = std::make_shared<seg::Decompressor>(segment_path_.path(), segment_region_);

    auto impl_it = std::make_shared<IteratorImpl>(IteratorImpl{decompressor, decompressor->begin()});
    return IndexInputDataQuery::Iterator{this, impl_it, decompressor_index_query_entry(impl_it->it)};
}

IndexInputDataQuery::Iterator DecompressorIndexInputDataQuery::end() {
    auto impl_it = std::make_shared<IteratorImpl>(IteratorImpl{{}, seg::Decompressor::Iterator::make_end()});
    return IndexInputDataQuery::Iterator{this, impl_it, decompressor_index_query_entry(impl_it->it)};
}

size_t DecompressorIndexInputDataQuery::keys_count() {
    seg::Decompressor decompressor{segment_path_.path(), segment_region_};
    return decompressor.words_count();
}

std::pair<std::shared_ptr<void>, IndexInputDataQuery::Iterator::value_type>
DecompressorIndexInputDataQuery::next_iterator(std::shared_ptr<void> it_impl) {
    auto& it_impl_ref = *reinterpret_cast<IteratorImpl*>(it_impl.get());
    // check if not already at the end
    if (it_impl_ref.decompressor) {
        ++it_impl_ref.it;
        if (it_impl_ref.it == it_impl_ref.decompressor->end()) {
            it_impl_ref.decompressor.reset();
        }
    }
    return {it_impl, decompressor_index_query_entry(it_impl_ref.it)};
}

bool DecompressorIndexInputDataQuery::equal_iterators(
    std::shared_ptr<void> lhs_it_impl,
    std::shared_ptr<void> rhs_it_impl) const {
    auto lhs = reinterpret_cast<IteratorImpl*>(lhs_it_impl.get());
    auto rhs = reinterpret_cast<IteratorImpl*>(rhs_it_impl.get());
    return (lhs->decompressor == rhs->decompressor) &&
           (!lhs->decompressor || (lhs->it == rhs->it));
}

void IndexBuilder::build() {
    SILK_TRACE << "IndexBuilder::build path: " << descriptor_.index_file.path() << " start";

    RecSplitSettings rec_split_settings{
        .keys_count = query_->keys_count(),
        .bucket_size = kBucketSize,
        .index_path = descriptor_.index_file.path(),
        .base_data_id = descriptor_.base_data_id,
        .double_enum_index = descriptor_.double_enum_index,
        .less_false_positives = descriptor_.less_false_positives,
    };
    RecSplit8 rec_split1{rec_split_settings, rec_split::seq_build_strategy(descriptor_.etl_buffer_size)};

    rec_split1.build_without_collisions([&](RecSplit8& rec_split) {
        uint64_t i{0};
        for (auto& entry : *query_) {
            auto key = descriptor_.key_factory ? descriptor_.key_factory->make(entry.key_data, i) : Bytes{entry.key_data};
            rec_split.add_key(key, entry.value);
            ++i;
        }
    });

    SILK_TRACE << "IndexBuilder::build path: " << descriptor_.index_file.path() << " end";
}

}  // namespace silkworm::snapshots
