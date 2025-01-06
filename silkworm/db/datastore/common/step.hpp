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

#include <silkworm/core/common/base.hpp>
#include <silkworm/infra/common/ensure.hpp>

#include "timestamp.hpp"

namespace silkworm::datastore {

//! Scale factor to convert from-to block number values in block snapshot file names
inline constexpr size_t kStepSizeForBlockSnapshots = 1'000;

//! Scale factor to convert from-to txn id values in temporal snapshot file names
inline constexpr size_t kStepSizeForTemporalSnapshots = 1'562'500;  // = 100M / 64

struct Step {
    size_t value;

    explicit Step(size_t value1) : value(value1) {}
    friend bool operator==(const Step&, const Step&) = default;
    bool operator<(const Step& other) const { return this->value < other.value; }
    bool operator<=(const Step& other) const { return this->value <= other.value; }
    std::string to_string() const { return std::to_string(value) + "st"; }

    BlockNum to_block_num() const { return value * kStepSizeForBlockSnapshots; }
    static Step from_block_num(BlockNum block_num) {
        return Step{static_cast<size_t>(block_num / kStepSizeForBlockSnapshots)};
    }

    TxnId to_txn_id() const { return value * kStepSizeForTemporalSnapshots; }
    static Step from_txn_id(TxnId txn_id) {
        return Step{static_cast<size_t>(txn_id / kStepSizeForTemporalSnapshots)};
    }
};

struct StepRange {
    Step start;
    Step end;

    StepRange(Step start1, Step end1) : start(start1), end(end1) {
        ensure(start <= end, "StepRange: end before start");
    }
    friend bool operator==(const StepRange&, const StepRange&) = default;
    bool contains(Step x) const { return (start <= x) && (x < end); }
    bool contains_range(StepRange range) const { return (start <= range.start) && (range.end <= end); }
    size_t size() const { return end.value - start.value; }
    std::string to_string() const { return std::string("[") + start.to_string() + ", " + end.to_string() + ")"; }

    BlockNumRange to_block_num_range() const { return {start.to_block_num(), end.to_block_num()}; }
    static StepRange from_block_num_range(BlockNumRange range) {
        return {Step::from_block_num(range.start), Step::from_block_num(range.end + kStepSizeForBlockSnapshots - 1)};
    }

    TxnIdRange to_txn_id_range() const { return {start.to_txn_id(), end.to_txn_id()}; }
    static StepRange from_txn_id_range(TxnIdRange range) {
        return {Step::from_txn_id(range.start), Step::from_txn_id(range.end + kStepSizeForTemporalSnapshots - 1)};
    }
};

struct StepToTimestampConverter {
    virtual ~StepToTimestampConverter() = default;
    virtual Step step_from_timestamp(Timestamp t) const = 0;
    virtual Timestamp timestamp_from_step(Step s) const = 0;
    virtual StepRange step_range_from_timestamp_range(TimestampRange range) const = 0;
    virtual TimestampRange timestamp_range_from_step_range(StepRange range) const = 0;
};

struct StepToBlockNumConverter : public StepToTimestampConverter {
    ~StepToBlockNumConverter() override = default;
    Step step_from_timestamp(Timestamp t) const override {
        return Step::from_block_num(t);
    }
    Timestamp timestamp_from_step(Step s) const override {
        return s.to_block_num();
    }
    StepRange step_range_from_timestamp_range(TimestampRange range) const override {
        return StepRange::from_block_num_range({range.start, range.end});
    }
    TimestampRange timestamp_range_from_step_range(StepRange range) const override {
        auto r = range.to_block_num_range();
        return {r.start, r.end};
    }
};

struct StepToTxnIdConverter : public StepToTimestampConverter {
    ~StepToTxnIdConverter() override = default;
    Step step_from_timestamp(Timestamp t) const override {
        return Step::from_txn_id(t);
    }
    Timestamp timestamp_from_step(Step s) const override {
        return s.to_txn_id();
    }
    StepRange step_range_from_timestamp_range(TimestampRange range) const override {
        return StepRange::from_txn_id_range({range.start, range.end});
    }
    TimestampRange timestamp_range_from_step_range(StepRange range) const override {
        auto r = range.to_txn_id_range();
        return {r.start, r.end};
    }
};

}  // namespace silkworm::datastore
