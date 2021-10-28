/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_STATE_DELTA_HPP_
#define SILKWORM_STATE_DELTA_HPP_

#include <silkworm/common/base.hpp>
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

        virtual void revert(IntraBlockState& state) noexcept = 0;

      protected:
        Delta() = default;
    };

    // Account created.
    class CreateDelta : public Delta {
      public:
        explicit CreateDelta(const evmc::address& address) noexcept;

        void revert(IntraBlockState& state) noexcept override;

      private:
        evmc::address address_;
    };

    // Account updated.
    class UpdateDelta : public Delta {
      public:
        UpdateDelta(const evmc::address& address, const Object& previous) noexcept;

        void revert(IntraBlockState& state) noexcept override;

      private:
        evmc::address address_;
        Object previous_;
    };

    // Account balance updated.
    // UpdateBalanceDelta is a special case of the more general UpdateDelta. It occupies less memory than UpdateDelta.
    class UpdateBalanceDelta : public Delta {
      public:
        UpdateBalanceDelta(const evmc::address& address, const intx::uint256& previous) noexcept;

        void revert(IntraBlockState& state) noexcept override;

      private:
        evmc::address address_;
        intx::uint256 previous_;
    };

    // Account recorded for self-destruction.
    class SuicideDelta : public Delta {
      public:
        explicit SuicideDelta(const evmc::address& address) noexcept;

        void revert(IntraBlockState& state) noexcept override;

      private:
        evmc::address address_;
    };

    // Account touched.
    class TouchDelta : public Delta {
      public:
        explicit TouchDelta(const evmc::address& address) noexcept;

        void revert(IntraBlockState& state) noexcept override;

      private:
        evmc::address address_;
    };

    // Storage value changed.
    class StorageChangeDelta : public Delta {
      public:
        StorageChangeDelta(const evmc::address& address, const evmc::bytes32& key,
                           const evmc::bytes32& previous) noexcept;

        void revert(IntraBlockState& state) noexcept override;

      private:
        evmc::address address_;
        evmc::bytes32 key_;
        evmc::bytes32 previous_;
    };

    // Entire storage deleted.
    class StorageWipeDelta : public Delta {
      public:
        StorageWipeDelta(const evmc::address& address, Storage storage) noexcept;

        void revert(IntraBlockState& state) noexcept override;

      private:
        evmc::address address_;
        Storage storage_;
    };

    // Storage created.
    class StorageCreateDelta : public Delta {
      public:
        explicit StorageCreateDelta(const evmc::address& address) noexcept;

        void revert(IntraBlockState& state) noexcept override;

      private:
        evmc::address address_;
    };

    // Storage accessed (see EIP-2929).
    class StorageAccessDelta : public Delta {
      public:
        StorageAccessDelta(const evmc::address& address, const evmc::bytes32& key) noexcept;

        void revert(IntraBlockState& state) noexcept override;

      private:
        evmc::address address_;
        evmc::bytes32 key_;
    };

    // Account accessed (see EIP-2929).
    class AccountAccessDelta : public Delta {
      public:
        explicit AccountAccessDelta(const evmc::address& address) noexcept;

        void revert(IntraBlockState& state) noexcept override;

      private:
        evmc::address address_;
    };

}  // namespace state
}  // namespace silkworm

#endif  // SILKWORM_STATE_DELTA_HPP_
