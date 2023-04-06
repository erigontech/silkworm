/*
   Copyright 2023 The Silkworm Authors

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

#include <blst.h>

#include <iomanip>
#include <iostream>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/util.hpp>

// TODO(yperbasis) Switch to std::format when Apple Clang has it
void print_blst_fp(const blst_fp& fp) {
    std::cout << "{";
    std::cout << "0x" << std::setfill('0') << std::setw(16) << std::hex << fp.l[0] << ", ";
    std::cout << "0x" << std::setfill('0') << std::setw(16) << std::hex << fp.l[1] << ", ";
    std::cout << "0x" << std::setfill('0') << std::setw(16) << std::hex << fp.l[2] << ", ";
    std::cout << "\n   ";
    std::cout << "0x" << std::setfill('0') << std::setw(16) << std::hex << fp.l[3] << ", ";
    std::cout << "0x" << std::setfill('0') << std::setw(16) << std::hex << fp.l[4] << ", ";
    std::cout << "0x" << std::setfill('0') << std::setw(16) << std::hex << fp.l[5] << "}";
}

int main() {
    using namespace silkworm;

    // KZG_SETUP_G2[1], see
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#trusted-setup
    static const Bytes kKzgSetupG2_1{*from_hex(
        "99aca9fb2f7760cecb892bf7262c176b334824f5727f680bba701a33e322cb6667531410dfc7c8e4321a3f0ea8af48cb1436638a2093123f046f0f504cc2a864825542873edbbc5d7ed17af125a4f2cf6433c6f4f61b81173726981dd989761d")};

    SILKWORM_ASSERT(kKzgSetupG2_1.length() == 96);

    blst_p2_affine g2_affine;
    SILKWORM_ASSERT(blst_p2_uncompress(&g2_affine, kKzgSetupG2_1.data()) == BLST_SUCCESS);
    blst_p2 out;
    blst_p2_from_affine(&out, &g2_affine);

    // TODO(C++23) std::print
    std::cout << "{{";
    print_blst_fp(out.x.fp[0]);
    std::cout << ",\n  ";
    print_blst_fp(out.x.fp[1]);
    std::cout << "}},\n{{";
    print_blst_fp(out.y.fp[0]);
    std::cout << ",\n  ";
    print_blst_fp(out.y.fp[1]);
    std::cout << "}},\n{{";
    print_blst_fp(out.z.fp[0]);
    std::cout << ",\n  ";
    print_blst_fp(out.z.fp[1]);
    std::cout << "}}" << std::endl;
}
