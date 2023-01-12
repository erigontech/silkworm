/*  beacon_block.cpp
 *
 *  This file is part of Mammon.
 *  mammon is a greedy and selfish ETH consensus client.
 *
 *  Copyright (c) 2021 - Reimundo Heluani (potuz) potuz@potuz.net
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "beacon_block.hpp"

#include "silkworm/lightclient/ssz/ssz/ssz.hpp"

/*
namespace eth {
// cppcheck-suppress unusedFunction
void BeaconBlockBody::randao_reveal(BLSSignature &&s) { randao_reveal_ = s; }
// cppcheck-suppress unusedFunction
void BeaconBlockBody::eth1_data(Eth1Data &&data) { eth1_data_ = data; }
// cppcheck-suppress unusedFunction
void BeaconBlockBody::graffiti(Bytes32 &&g) { graffiti_ = g; }
// cppcheck-suppress unusedFunction
void BeaconBlockBody::proposer_slashings(ListFixedSizedParts<ProposerSlashing> &&p) {
    proposer_slashings_ = p;
}
// cppcheck-suppress unusedFunction
void BeaconBlockBody::attester_slashings(ListVariableSizedParts<AttesterSlashing> &&a) {
    attester_slashings_ = a;
}
// cppcheck-suppress unusedFunction
void BeaconBlockBody::attestations(ListVariableSizedParts<Attestation> &&a) { attestations_ = a; }
// cppcheck-suppress unusedFunction
void BeaconBlockBody::deposits(ListFixedSizedParts<Deposit> &&d) { deposits_ = d; }
// cppcheck-suppress unusedFunction
void BeaconBlockBody::voluntary_exits(ListFixedSizedParts<SignedVoluntaryExit> &&s) { voluntary_exits_ = s; }

// cppcheck-suppress unusedFunction
void BeaconBlock::slot(Slot &&s) { slot_ = s; }
// cppcheck-suppress unusedFunction
void BeaconBlock::proposer_index(ValidatorIndex &&idx) { proposer_index_ = idx; }
// cppcheck-suppress unusedFunction
void BeaconBlock::parent_root(Root &&r) { parent_root_ = r; }
// cppcheck-suppress unusedFunction
void BeaconBlock::state_root(Root &&r) { state_root_ = r; }
// cppcheck-suppress unusedFunction
void BeaconBlock::body(BeaconBlockBody &&b) { body_ = b; }
}  // namespace eth
*/
