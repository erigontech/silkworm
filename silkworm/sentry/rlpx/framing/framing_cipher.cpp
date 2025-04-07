// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "framing_cipher.hpp"

#include <stdexcept>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/sentry/common/crypto/xor.hpp>
#include <silkworm/sentry/rlpx/crypto/aes.hpp>
#include <silkworm/sentry/rlpx/crypto/sha3_hasher.hpp>

namespace silkworm::sentry::rlpx::framing {

using namespace crypto;
using namespace silkworm::sentry::crypto;
using KeyMaterial = FramingCipher::KeyMaterial;
using MACHasher = crypto::Sha3Hasher;

class FramingCipherImpl {
  public:
    FramingCipherImpl(const KeyMaterial& key_material, Bytes aes_secret, Bytes mac_secret);

    Bytes encrypt_frame(Bytes frame_data);
    size_t decrypt_header(ByteView header_cipher_text, ByteView header_mac);
    Bytes decrypt_frame(ByteView frame_cipher_text, ByteView frame_mac, size_t frame_size);

  private:
    static void init_mac_hashers(
        const KeyMaterial& key_material,
        ByteView mac_secret,
        MACHasher& egress_mac_hasher,
        MACHasher& ingress_mac_hasher);

    Bytes header_mac(MACHasher& hasher, ByteView header_cipher_text);
    Bytes frame_mac(MACHasher& hasher, ByteView frame_cipher_text);
    static Bytes serialize_frame_size(size_t size);
    static size_t deserialize_frame_size(ByteView data);

    Bytes aes_secret_;
    Bytes mac_secret_;
    AESCipher mac_seed_cipher_;
    AESCipher egress_data_cipher_;
    AESCipher ingress_data_cipher_;
    MACHasher egress_mac_hasher_;
    MACHasher ingress_mac_hasher_;
};

FramingCipherImpl::FramingCipherImpl(const KeyMaterial& key_material, Bytes aes_secret, Bytes mac_secret)
    : aes_secret_(std::move(aes_secret)),
      mac_secret_(std::move(mac_secret)),
      mac_seed_cipher_(mac_secret_, std::nullopt, AESCipher::Direction::kEncrypt),
      egress_data_cipher_(aes_secret_, Bytes(kAESBlockSize, 0), AESCipher::Direction::kEncrypt),
      ingress_data_cipher_(aes_secret_, Bytes(kAESBlockSize, 0), AESCipher::Direction::kDecrypt) {
    init_mac_hashers(key_material, mac_secret_, egress_mac_hasher_, ingress_mac_hasher_);
}

static Bytes keccak256(ByteView data1, ByteView data2) {
    Sha3Hasher hasher;
    hasher.update(data1);
    hasher.update(data2);
    return hasher.hash();
}

static void make_secrets(const KeyMaterial& key_material, Bytes& aes_secret, Bytes& mac_secret) {
    auto& ephemeral_secret = key_material.ephemeral_shared_secret;
    Bytes nonce_hash = keccak256(key_material.recipient_nonce, key_material.initiator_nonce);
    Bytes shared_secret = keccak256(ephemeral_secret, nonce_hash);
    aes_secret = keccak256(ephemeral_secret, shared_secret);
    mac_secret = keccak256(ephemeral_secret, aes_secret);
}

void FramingCipherImpl::init_mac_hashers(
    const KeyMaterial& key_material,
    ByteView mac_secret,
    MACHasher& egress_mac_hasher,
    MACHasher& ingress_mac_hasher) {
    auto initiator_nonce = key_material.initiator_nonce;
    xor_bytes(initiator_nonce, mac_secret);

    auto recipient_nonce = key_material.recipient_nonce;
    xor_bytes(recipient_nonce, mac_secret);

    auto& initiator_hasher = key_material.is_initiator ? egress_mac_hasher : ingress_mac_hasher;
    auto& recipient_hasher = key_material.is_initiator ? ingress_mac_hasher : egress_mac_hasher;

    initiator_hasher.update(recipient_nonce);
    initiator_hasher.update(key_material.initiator_first_message_data);

    recipient_hasher.update(initiator_nonce);
    recipient_hasher.update(key_material.recipient_first_message_data);
}

Bytes FramingCipherImpl::header_mac(MACHasher& hasher, ByteView header_cipher_text) {
    SILKWORM_ASSERT(header_cipher_text.size() >= kAESBlockSize);

    auto hash = hasher.hash();
    auto header_mac_seed = mac_seed_cipher_.encrypt(ByteView(hash.data(), kAESBlockSize));
    xor_bytes(header_mac_seed, header_cipher_text);
    hasher.update(header_mac_seed);

    auto header_hash = hasher.hash();
    header_hash.resize(kAESBlockSize);
    return header_hash;
}

Bytes FramingCipherImpl::frame_mac(MACHasher& hasher, ByteView frame_cipher_text) {
    hasher.update(frame_cipher_text);

    auto hash = hasher.hash();
    auto frame_mac_seed = mac_seed_cipher_.encrypt(ByteView(hash.data(), kAESBlockSize));
    xor_bytes(frame_mac_seed, hash);
    hasher.update(frame_mac_seed);

    auto header_hash = hasher.hash();
    header_hash.resize(kAESBlockSize);
    return header_hash;
}

Bytes FramingCipherImpl::serialize_frame_size(size_t size) {
    Bytes data(sizeof(uint32_t), 0);
    endian::store_big_u32(data.data(), static_cast<uint32_t>(size));
    return data.substr(1);
}

size_t FramingCipherImpl::deserialize_frame_size(ByteView data) {
    if (data.size() < sizeof(uint32_t) - 1)
        throw std::runtime_error("rlpx::framing::FramingCipher: frame size data is too short");
    Bytes data1(sizeof(uint32_t), 0);
    std::copy(data.cbegin(), data.cbegin() + (data1.size() - 1), data1.begin() + 1);
    return endian::load_big_u32(data1.data());
}

Bytes FramingCipherImpl::encrypt_frame(Bytes frame_data) {
    Bytes header_data;
    rlp::encode(header_data, 0u, 0u);

    Bytes header;
    header.reserve(kAESBlockSize);
    header += serialize_frame_size(frame_data.size());
    header += header_data;

    header.resize(kAESBlockSize, 0);
    Bytes header_cipher_text = egress_data_cipher_.encrypt(header);
    Bytes header_mac = this->header_mac(egress_mac_hasher_, header_cipher_text);

    frame_data.resize(aes_round_up_to_block_size(frame_data.size()), 0);
    Bytes frame_cipher_text = egress_data_cipher_.encrypt(frame_data);
    Bytes frame_mac = this->frame_mac(egress_mac_hasher_, frame_cipher_text);

    Bytes data;
    data.reserve(
        header_cipher_text.size() +
        header_mac.size() +
        frame_cipher_text.size() +
        frame_mac.size());
    data.append(header_cipher_text);
    data.append(header_mac);
    data.append(frame_cipher_text);
    data.append(frame_mac);
    return data;
}

size_t FramingCipherImpl::decrypt_header(ByteView header_cipher_text, ByteView header_mac) {
    Bytes expected_header_mac = this->header_mac(ingress_mac_hasher_, header_cipher_text);
    if (header_mac != expected_header_mac)
        throw std::runtime_error("rlpx::framing::FramingCipher: invalid header MAC");

    Bytes header = ingress_data_cipher_.decrypt(header_cipher_text);
    return deserialize_frame_size(header);
}

Bytes FramingCipherImpl::decrypt_frame(ByteView frame_cipher_text, ByteView frame_mac, size_t frame_size) {
    SILKWORM_ASSERT(frame_cipher_text.size() >= frame_size);

    Bytes expected_frame_mac = this->frame_mac(ingress_mac_hasher_, frame_cipher_text);
    if (frame_mac != expected_frame_mac)
        throw std::runtime_error("rlpx::framing::FramingCipher: invalid frame MAC");

    Bytes frame_data = ingress_data_cipher_.decrypt(frame_cipher_text);
    frame_data.resize(frame_size);
    return frame_data;
}

FramingCipher::FramingCipher(const KeyMaterial& key_material) {
    Bytes aes_secret, mac_secret;
    make_secrets(key_material, aes_secret, mac_secret);
    impl_ = std::make_unique<FramingCipherImpl>(key_material, aes_secret, mac_secret);
}

FramingCipher::~FramingCipher() = default;

FramingCipher::FramingCipher(FramingCipher&& other) noexcept
    : impl_(std::move(other.impl_)) {}

FramingCipher& FramingCipher::operator=(FramingCipher&& other) noexcept {
    this->impl_ = std::move(other.impl_);
    return *this;
}

Bytes FramingCipher::encrypt_frame(Bytes frame_data) {
    return impl_->encrypt_frame(std::move(frame_data));
}

size_t FramingCipher::header_size() {
    // cipher text and MAC
    return kAESBlockSize * 2;
}

size_t FramingCipher::decrypt_header(ByteView data) {
    if (data.size() < FramingCipher::header_size())
        throw std::runtime_error("rlpx::framing::FramingCipher: header size data is too short");
    return impl_->decrypt_header(
        ByteView{data.data(), kAESBlockSize},
        ByteView{data.data() + kAESBlockSize, kAESBlockSize});
}

size_t FramingCipher::frame_size(size_t header_frame_size) {
    // cipher text and MAC
    return aes_round_up_to_block_size(header_frame_size) + kAESBlockSize;
}

Bytes FramingCipher::decrypt_frame(ByteView data, size_t header_frame_size) {
    if (data.size() < FramingCipher::frame_size(header_frame_size))
        throw std::runtime_error("rlpx::framing::FramingCipher: frame size data is too short");
    return impl_->decrypt_frame(
        ByteView{data.data(), data.size() - kAESBlockSize},
        ByteView{data.data() + data.size() - kAESBlockSize, kAESBlockSize},
        header_frame_size);
}

}  // namespace silkworm::sentry::rlpx::framing
