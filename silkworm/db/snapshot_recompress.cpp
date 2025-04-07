// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <stdexcept>

#include <silkworm/infra/common/directories.hpp>

#include "blocks/bodies/body_segment.hpp"
#include "blocks/headers/header_segment.hpp"
#include "blocks/schema_config.hpp"
#include "blocks/transactions/txn_segment.hpp"
#include "datastore/snapshots/common/snapshot_path.hpp"

namespace silkworm::snapshots {

using namespace segment;

template <class TSegmentReader, class TSegmentWriter>
void copy_reader_to_writer(const SegmentFileReader& file_reader, SegmentFileWriter& file_writer) {
    TSegmentReader reader{file_reader};
    TSegmentWriter writer{file_writer};
    std::copy(reader.begin(), reader.end(), writer.out());
}

void snapshot_file_recompress(const std::filesystem::path& path) {
    auto path_opt = SnapshotPath::parse(path);
    if (!path_opt) throw std::runtime_error{"bad snapshot path"};

    SegmentFileReader file_reader{*path_opt};

    auto out_path = path;
    out_path.replace_extension("seg2");
    TemporaryDirectory tmp_dir;
    SegmentFileWriter file_writer{*SnapshotPath::parse(out_path), tmp_dir.path()};

    auto schema = db::blocks::make_blocks_repository_schema();
    auto names = schema.entity_name_by_path(*path_opt);
    if (!names) throw std::runtime_error{"unsupported snapshot type"};
    datastore::EntityName name = names->second;
    {
        if (name == db::blocks::kHeaderSegmentName)
            copy_reader_to_writer<HeaderSegmentReader, HeaderSegmentWriter>(file_reader, file_writer);
        else if (name == db::blocks::kBodySegmentName)
            copy_reader_to_writer<BodySegmentReader, BodySegmentWriter>(file_reader, file_writer);
        else if (name == db::blocks::kTxnSegmentName)
            copy_reader_to_writer<TransactionSegmentReader, TransactionSegmentWriter>(file_reader, file_writer);
        else
            throw std::runtime_error{"invalid snapshot type"};
    }

    SegmentFileWriter::flush(std::move(file_writer));
}

}  // namespace silkworm::snapshots
