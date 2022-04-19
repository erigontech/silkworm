
#ifndef SILKWORM_STAGE_H
#define SILKWORM_STAGE_H

#include <silkworm/downloader/internals/types.hpp>

namespace silkworm {

// todo: use IStage from stagedsync module when it will have support for returning unwind_point and bad_block
class Stage {
  public:
    struct Result {
        enum Status { Unspecified, Done, DoneAndUpdated, UnwindNeeded, SkipTx, Error } status;
        std::optional<BlockNum> current_point;
        std::optional<BlockNum> unwind_point;
        std::optional<Hash> bad_block;
    };

    virtual Result forward(bool first_sync) = 0;
    virtual Result unwind_to(BlockNum new_height, Hash bad_block) = 0;
};

}

#endif  // SILKWORM_STAGE_H
