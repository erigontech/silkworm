/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_STATE_DELTA_H_
#define SILKWORM_STATE_DELTA_H_

#include <evmc/evmc.hpp>
#include <silkworm/state/object.hpp>

namespace silkworm {

class IntraBlockState;

namespace state {

// Delta is a revertable change made to IntraBlockState.
class Delta {
 public:
  Delta(const Delta&) = delete;
  Delta& operator=(const Delta&) = delete;

  virtual ~Delta() = default;

  virtual void revert(IntraBlockState& state) = 0;

 protected:
  Delta() = default;
};

// Account created.
class CreateDelta : public Delta {
 public:
  CreateDelta(evmc::address address);

  void revert(IntraBlockState& state) override;

 private:
  evmc::address address_;
};

// Account updated.
class UpdateDelta : public Delta {
 public:
  UpdateDelta(evmc::address address, state::Object previous);

  void revert(IntraBlockState& state) override;

 private:
  evmc::address address_;
  state::Object previous_;
};

// Account recorded for self-destruction.
class SuicideDelta : public Delta {
 public:
  SuicideDelta(evmc::address address);

  void revert(IntraBlockState& state) override;

 private:
  evmc::address address_;
};

// Account touched.
class TouchDelta : public Delta {
 public:
  TouchDelta(evmc::address address);

  void revert(IntraBlockState& state) override;

 private:
  evmc::address address_;
};

// Storage updated.
class StorageChangeDelta : public Delta {
 public:
  StorageChangeDelta(evmc::address address, evmc::bytes32 key, evmc::bytes32 previous);

  void revert(IntraBlockState& state) override;

 private:
  evmc::address address_;
  evmc::bytes32 key_;
  evmc::bytes32 previous_;
};

class StorageWipeDelta : public Delta {
 public:
  StorageWipeDelta(evmc::address address, state::Storage storage);

  void revert(IntraBlockState& state) override;

 private:
  evmc::address address_;
  state::Storage storage_;
};
}  // namespace state
}  // namespace silkworm

#endif  // SILKWORM_STATE_DELTA_H_
