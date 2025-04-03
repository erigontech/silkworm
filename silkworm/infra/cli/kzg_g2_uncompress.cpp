// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    // https://github.com/ethereum/consensus-specs/blob/dev/presets/mainnet/trusted_setups/trusted_setup_4096.json
    static const Bytes kKzgSetupG2{*from_hex(
        "b5bfd7dd8cdeb128843bc287230af38926187075cbfbefa81009a2ce615ac53d2914e5870cb452d2afaaab24f3499f72185cbfee53492714734429b7b38608e23926c911cceceac9a36851477ba4c60b087041de621000edc98edada20c1def2")};

    SILKWORM_ASSERT(kKzgSetupG2.size() == 96);

    blst_p2_affine g2_affine;
    SILKWORM_ASSERT(blst_p2_uncompress(&g2_affine, kKzgSetupG2.data()) == BLST_SUCCESS);
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
    std::cout << "}}\n";
}
