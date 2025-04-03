// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "bootnodes.hpp"

#include <vector>

#include <silkworm/core/chain/config.hpp>

// TODO(yperbasis): add polygon boot nodes

namespace silkworm::sentry::discovery {

enum class NetworkId : uint64_t {
    kMainnet = *kKnownChainNameToId.find("mainnet"sv),
    kHolesky = *kKnownChainNameToId.find("holesky"sv),
    kSepolia = *kKnownChainNameToId.find("sepolia"sv),
};

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Ethereum network.
std::vector<EnodeUrl> kMainnetBootnodes = {
    // Ethereum Foundation Go Bootnodes
    EnodeUrl{"enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303"},  // bootnode-aws-ap-southeast-1-001
    EnodeUrl{"enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303"},    // bootnode-aws-us-east-1-001
    EnodeUrl{"enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303"},  // bootnode-hetzner-hel
    EnodeUrl{"enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303"},  // bootnode-hetzner-fsn
};

std::vector<EnodeUrl> kHoleskyBootnodes = {
    EnodeUrl{"enode://ac906289e4b7f12df423d654c5a962b6ebe5b3a74cc9e06292a85221f9a64a6f1cfdd6b714ed6dacef51578f92b34c60ee91e9ede9c7f8fadc4d347326d95e2b@146.190.13.128:30303"},
    EnodeUrl{"enode://a3435a0155a3e837c02f5e7f5662a2f1fbc25b48e4dc232016e1c51b544cb5b4510ef633ea3278c0e970fa8ad8141e2d4d0f9f95456c537ff05fdf9b31c15072@178.128.136.233:30303"},
};

// SepoliaBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Sepolia test network.
std::vector<EnodeUrl> kSepoliaBootnodes = {
    // EF DevOps
    EnodeUrl{"enode://4e5e92199ee224a01932a377160aa432f31d0b351f84ab413a8e0a42f4f36476f8fb1cbe914af0d9aef0d51665c214cf653c651c4bbd9d5550a934f241f1682b@138.197.51.181:30303"},  // sepolia-bootnode-1-nyc3
    EnodeUrl{"enode://143e11fb766781d22d92a2e33f8f104cddae4411a122295ed1fdb6638de96a6ce65f5b7c964ba3763bba27961738fef7d3ecc739268f3e5e771fb4c87b6234ba@146.190.1.103:30303"},   // sepolia-bootnode-1-sfo3
    EnodeUrl{"enode://8b61dc2d06c3f96fddcbebb0efb29d60d3598650275dc469c22229d3e5620369b0d3dedafd929835fe7f489618f19f456fe7c0df572bf2d914a9f4e006f783a9@170.64.250.88:30303"},   // sepolia-bootnode-1-syd1
    EnodeUrl{"enode://10d62eff032205fcef19497f35ca8477bea0eadfff6d769a147e895d8b2b8f8ae6341630c645c30f5df6e67547c03494ced3d9c5764e8622a26587b083b028e8@139.59.49.206:30303"},   // sepolia-bootnode-1-blr1
    EnodeUrl{"enode://9e9492e2e8836114cc75f5b929784f4f46c324ad01daf87d956f98b3b6c5fcba95524d6e5cf9861dc96a2c8a171ea7105bb554a197455058de185fa870970c7c@138.68.123.152:30303"},  // sepolia-bootnode-1-ams3

    // from https://github.com/erigontech/erigon/issues/6134#issuecomment-1354923418
    EnodeUrl{"enode://8ae4559db1b1e160be8cc46018d7db123ed6d03fbbfe481da5ec05f71f0aa4d5f4b02ad059127096aa994568706a0d02933984083b87c5e1e3de2b7692444d37@35.161.233.158:46855"},
    EnodeUrl{"enode://d0b3b290422f35ec3e68356f3a4cdf9c661f71a868110670e31441a5021d7abd0440ae8dfb9360aafdd0198f177863361e3a7a7eb5e1a3e26575bf1ac3ef4ab3@162.19.136.65:48264"},
    EnodeUrl{"enode://d64624bda3cdb65d542c90757a4a661cfe9dddf8328bdb1ea97a8d70fad287c360f0101c492d8fd6ab30d79160a3bf148cacfd68f5d2e47eab0b709516419304@51.195.63.10:30040"},
    EnodeUrl{"enode://c7df835939e027325c6bba926220fae5912a33c83d96b3eef8ef445c98083f3191788581c9a0e8f74cadb0b13229b847f5c1ebd315b22bcf11faf6468020eb48@54.163.51.157:30303"},
    EnodeUrl{"enode://da0609bad3afcab9b93175a41a2d621d07aa7ff6c134a00792d4541f0ce8d30d8f3c51bb37a47573508a0bf18865b04066af2a661edf1d3a3d8d133fc1031aa0@88.151.101.14:45192"},
    EnodeUrl{"enode://7a4534d392c59369eae6befa56ac670476d9edc16597cf53c92bbefa6e741b6b0b9e6822cab12afb09123e03ca1131026fbef145adec429fe2e50182dfb650a5@94.130.18.108:31312"},
    EnodeUrl{"enode://db6fa13b63a885440de581ee3fc8df9c6a590326b39fc5ccba7991707ee0cebac306211f7eca5270a350201a3132511f2338481edd81f3dc819c2a1c60419cf2@65.21.89.157:30303"},
    EnodeUrl{"enode://fcf03e9404cace34c60e4eed374ef9a779471014319b3346352fbc2f992a399af6517486e8e65a4ab55f4645fe55420bbea1cddc13a4af4df63b0f731915c6a6@13.125.238.49:46173"},
    EnodeUrl{"enode://8b973816278fdd56966709e4794c7ccce1f256eaa9165a6b013b991a9bdf3886a8f2d23af50ee723a5614a9fe9d197252b803b4455a87ab2468e128f7b06e0ca@172.104.107.145:30303"},
    EnodeUrl{"enode://5a1fb15f826a213d3ef4adb9be47ab58b2240ea05df0d760a244f04762b0847dcb08276b1284f726c22eea30fce0c601cf121b81bac0c151f1b3b4ad00d1482a@34.159.55.147:51262"},
    EnodeUrl{"enode://560928dd14819f88113586726e452b16bbc694ed4144ddadd6290053e7f3fc66bfad13add6889f7d8f37e0c21ccbb6948eb8899c8b30743f4b45a3081f1efed8@34.138.254.5:29888"},
    EnodeUrl{"enode://69a13b575b8c5278431409e9f7db36e7218667ae286bfb65a72dfec9201b2c5bbbe2797a1babbdf17a7bf7ca68fa3fbe1554612637eb1b2425fa975e1bccb54c@35.223.41.3:30303"},
    EnodeUrl{"enode://66158b31eecff939f220b291d2b448edbfe94f1d4c992d9395b5d476e55e54b5abd11d3ee44daf1e18ee27b910ef99cdf6f19775eb4820ebe4f77d7aa948e3b6@51.195.63.10:55198"},
    EnodeUrl{"enode://bf94acbd51170bf075cacb9f149b21ff46354d659ab434a0d40688f776e1e1556bc62be2dc2867ba513844268c0dc8240099a6b60efe1713fbc25da7fdeb6ff1@3.82.105.139:30303"},
    EnodeUrl{"enode://41329e5ceb51cdddbe6a475db00b682505768b71ff8ee37d2d3500ca1b78918f9fad57d6006dd9f79cd418437dbcf87ec2fd58d60710f925cb17da05a51197cf@65.21.34.60:30303"},
    EnodeUrl{"enode://4e5e92199ee224a01932a377160aa432f31d0b351f84ab413a8e0a42f4f36476f8fb1cbe914af0d9aef0d51665c214cf653c651c4bbd9d5550a934f241f1682b@138.197.51.181:30303"},
    EnodeUrl{"enode://143e11fb766781d22d92a2e33f8f104cddae4411a122295ed1fdb6638de96a6ce65f5b7c964ba3763bba27961738fef7d3ecc739268f3e5e771fb4c87b6234ba@146.190.1.103:30303"},
    EnodeUrl{"enode://8b61dc2d06c3f96fddcbebb0efb29d60d3598650275dc469c22229d3e5620369b0d3dedafd929835fe7f489618f19f456fe7c0df572bf2d914a9f4e006f783a9@170.64.250.88:30303"},
    EnodeUrl{"enode://10d62eff032205fcef19497f35ca8477bea0eadfff6d769a147e895d8b2b8f8ae6341630c645c30f5df6e67547c03494ced3d9c5764e8622a26587b083b028e8@139.59.49.206:30303"},
    EnodeUrl{"enode://9e9492e2e8836114cc75f5b929784f4f46c324ad01daf87d956f98b3b6c5fcba95524d6e5cf9861dc96a2c8a171ea7105bb554a197455058de185fa870970c7c@138.68.123.152:30303"},
};

std::span<EnodeUrl> bootnodes(uint64_t network_id) {
    switch (static_cast<NetworkId>(network_id)) {
        case NetworkId::kMainnet:
            return std::span<EnodeUrl>{kMainnetBootnodes.data(), kMainnetBootnodes.size()};
        case NetworkId::kHolesky:
            return std::span<EnodeUrl>{kHoleskyBootnodes.data(), kHoleskyBootnodes.size()};
        case NetworkId::kSepolia:
            return std::span<EnodeUrl>{kSepoliaBootnodes.data(), kSepoliaBootnodes.size()};
        default:
            return std::span<EnodeUrl>{};
    }
}

}  // namespace silkworm::sentry::discovery
