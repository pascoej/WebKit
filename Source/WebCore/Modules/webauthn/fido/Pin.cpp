// Copyright 2019 The Chromium Authors. All rights reserved.
// Copyright (C) 2019 Apple Inc. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "config.h"
#include "Pin.h"

#if ENABLE(WEB_AUTHN)

#include "CBORReader.h"
#include "CBORWriter.h"
#include "CryptoAlgorithmAESCBC.h"
#include "CryptoAlgorithmAesCbcCfbParams.h"
#include "CryptoAlgorithmECDH.h"
#include "CryptoAlgorithmHKDF.h"
#include "CryptoAlgorithmHkdfParams.h"
#include "CryptoAlgorithmHMAC.h"
#include "CryptoKeyAES.h"
#include "CryptoKeyEC.h"
#include "CryptoKeyHMAC.h"
#include "CryptoKeyRaw.h"
#include "DeviceResponseConverter.h"
#include "ExceptionOr.h"
#include "WebAuthenticationConstants.h"
#include "WebAuthenticationUtils.h"
#if HAVE(SWIFT_CPP_INTEROP)
#include <pal/PALSwift.h>
#endif
#include <pal/crypto/CryptoDigest.h>

namespace fido {
using namespace WebCore;
using CBOR = cbor::CBORValue;

namespace pin {
using namespace cbor;

// hasAtLeastFourCodepoints returns true if |pin| contains
// four or more code points. This reflects the "4 Unicode characters"
// requirement in CTAP2.
static bool hasAtLeastFourCodepoints(const String& pin)
{
    return pin.length() >= 4;
}

// makePinAuth returns `LEFT(HMAC-SHA-256(secret, data), 16)`.
static Vector<uint8_t> makePinAuth(const CryptoKeyHMAC& key, const Vector<uint8_t>& data)
{
    auto result = CryptoAlgorithmHMAC::platformSign(key, data);
    ASSERT(!result.hasException());
    auto pinAuth = result.releaseReturnValue();
    pinAuth.shrink(16);
    return pinAuth;
}

std::optional<CString> validateAndConvertToUTF8(const String& pin)
{
    if (!hasAtLeastFourCodepoints(pin))
        return std::nullopt;
    auto result = pin.utf8();
    if (result.length() < kMinBytes || result.length() > kMaxBytes)
        return std::nullopt;
    return result;
}

// encodePINCommand returns a CTAP2 PIN command for the operation |subcommand|.
// Additional elements of the top-level CBOR map can be added with the optional
// |addAdditional| callback.
static Vector<uint8_t> encodePinCommand(Subcommand subcommand, Function<void(CBORValue::MapValue*)> addAdditional = nullptr)
{
    CBORValue::MapValue map;
    map.emplace(static_cast<int64_t>(RequestKey::kProtocol), kProtocolVersion);
    map.emplace(static_cast<int64_t>(RequestKey::kSubcommand), static_cast<int64_t>(subcommand));

    if (addAdditional)
        addAdditional(&map);

    auto serializedParam = CBORWriter::write(CBORValue(WTFMove(map)));
    ASSERT(serializedParam);

    Vector<uint8_t> cborRequest({ static_cast<uint8_t>(CtapRequestCommand::kAuthenticatorClientPin) });
    cborRequest.appendVector(*serializedParam);
    return cborRequest;
}

RetriesResponse::RetriesResponse() = default;

std::optional<RetriesResponse> RetriesResponse::parse(const Vector<uint8_t>& inBuffer)
{
    auto decodedMap = decodeResponseMap(inBuffer);
    if (!decodedMap)
        return std::nullopt;
    const auto& responseMap = decodedMap->getMap();

    auto it = responseMap.find(CBORValue(static_cast<int64_t>(ResponseKey::kRetries)));
    if (it == responseMap.end() || !it->second.isUnsigned())
        return std::nullopt;

    RetriesResponse ret;
    ret.retries = static_cast<uint64_t>(it->second.getUnsigned());
    return ret;
}

KeyAgreementResponse::KeyAgreementResponse(Ref<CryptoKeyEC>&& peerKey)
    : peerKey(WTFMove(peerKey))
{
}

KeyAgreementResponse::~KeyAgreementResponse() = default;
KeyAgreementResponse::KeyAgreementResponse(KeyAgreementResponse&&) = default;
KeyAgreementResponse& KeyAgreementResponse::operator=(KeyAgreementResponse&&) = default;

std::optional<KeyAgreementResponse> KeyAgreementResponse::parse(const Vector<uint8_t>& inBuffer)
{
    auto decodedMap = decodeResponseMap(inBuffer);
    if (!decodedMap)
        return std::nullopt;
    const auto& responseMap = decodedMap->getMap();

    // The ephemeral key is encoded as a COSE structure.
    auto it = responseMap.find(CBORValue(static_cast<int64_t>(ResponseKey::kKeyAgreement)));
    if (it == responseMap.end() || !it->second.isMap())
        return std::nullopt;
    const auto& coseKey = it->second.getMap();

    return parseFromCOSE(coseKey);
}

std::optional<KeyAgreementResponse> KeyAgreementResponse::parseFromCOSE(const CBORValue::MapValue& coseKey)
{
    // The COSE key must be a P-256 point. See
    // https://tools.ietf.org/html/rfc8152#section-7.1
    for (const auto& pair : Vector<std::pair<int64_t, int64_t>>({
        { static_cast<int64_t>(COSE::kty), static_cast<int64_t>(COSE::EC2) },
        { static_cast<int64_t>(COSE::alg), static_cast<int64_t>(COSE::ECDH256) },
        { static_cast<int64_t>(COSE::crv), static_cast<int64_t>(COSE::P_256) },
    })) {
        auto it = coseKey.find(CBORValue(pair.first));
        if (it == coseKey.end() || !it->second.isInteger() || it->second.getInteger() != pair.second)
            return std::nullopt;
    }

    // See https://tools.ietf.org/html/rfc8152#section-13.1.1
    const auto& xIt = coseKey.find(CBORValue(static_cast<int64_t>(COSE::x)));
    const auto& yIt = coseKey.find(CBORValue(static_cast<int64_t>(COSE::y)));
    if (xIt == coseKey.end() || yIt == coseKey.end() || !xIt->second.isByteString() || !yIt->second.isByteString())
        return std::nullopt;

    const auto& x = xIt->second.getByteString();
    const auto& y = yIt->second.getByteString();
    auto peerKey = CryptoKeyEC::importRaw(CryptoAlgorithmIdentifier::ECDH, "P-256"_s, encodeRawPublicKey(x, y), true, CryptoKeyUsageDeriveBits);
    if (!peerKey)
        return std::nullopt;

    return KeyAgreementResponse(peerKey.releaseNonNull());
}

cbor::CBORValue::MapValue encodeCOSEPublicKey(const Vector<uint8_t>& rawPublicKey)
{
    ASSERT(rawPublicKey.size() == 65);
    auto x = rawPublicKey.subvector(1, ES256FieldElementLength);
    auto y = rawPublicKey.subvector(1 + ES256FieldElementLength, ES256FieldElementLength);

    cbor::CBORValue::MapValue publicKeyMap;
    publicKeyMap[cbor::CBORValue(COSE::kty)] = cbor::CBORValue(COSE::EC2);
    publicKeyMap[cbor::CBORValue(COSE::alg)] = cbor::CBORValue(COSE::ECDH256);
    publicKeyMap[cbor::CBORValue(COSE::crv)] = cbor::CBORValue(COSE::P_256);
    publicKeyMap[cbor::CBORValue(COSE::x)] = cbor::CBORValue(WTFMove(x));
    publicKeyMap[cbor::CBORValue(COSE::y)] = cbor::CBORValue(WTFMove(y));

    return publicKeyMap;
}

TokenResponse::TokenResponse(Ref<WebCore::CryptoKeyHMAC>&& token)
    : m_token(WTFMove(token))
{
}

std::optional<TokenResponse> TokenResponse::parse(const WebCore::CryptoKeyAES& sharedKey, const Vector<uint8_t>& inBuffer)
{
    auto decodedMap = decodeResponseMap(inBuffer);
    if (!decodedMap)
        return std::nullopt;
    const auto& responseMap = decodedMap->getMap();

    auto it = responseMap.find(CBORValue(static_cast<int64_t>(ResponseKey::kPinToken)));
    if (it == responseMap.end() || !it->second.isByteString())
        return std::nullopt;
    const auto& encryptedToken = it->second.getByteString();

    auto tokenResult = CryptoAlgorithmAESCBC::platformDecrypt({ }, sharedKey, encryptedToken, CryptoAlgorithmAESCBC::Padding::No);
    if (tokenResult.hasException())
        return std::nullopt;
    auto token = tokenResult.releaseReturnValue();

    auto tokenKey = CryptoKeyHMAC::importRaw(token.size() * 8, CryptoAlgorithmIdentifier::SHA_256, WTFMove(token), true, CryptoKeyUsageSign);
    ASSERT(tokenKey);

    return TokenResponse(tokenKey.releaseNonNull());
}

Vector<uint8_t> TokenResponse::pinAuth(const Vector<uint8_t>& clientDataHash) const
{
    return makePinAuth(m_token, clientDataHash);
}

const Vector<uint8_t>& TokenResponse::token() const
{
    return m_token->key();
}

Vector<uint8_t> encodeAsCBOR(const RetriesRequest&)
{
    return encodePinCommand(Subcommand::kGetRetries);
}

Vector<uint8_t> encodeAsCBOR(const KeyAgreementRequest&)
{
    return encodePinCommand(Subcommand::kGetKeyAgreement);
}

static Vector<uint8_t> deriveProtocolSharedSecret(PINUVAuthProtocol protocol, const Vector<uint8_t>& ecdhResult)
{
    Vector<uint8_t> sharedSecret;
    if (protocol == PINUVAuthProtocol::kPinProtocol1) {
        // For Protocol 1, use SHA-256
        auto sharedKeyDigest = PAL::CryptoDigest::create(PAL::CryptoDigest::Algorithm::SHA_256);
        sharedKeyDigest->addBytes(ecdhResult.span());
        sharedSecret = sharedKeyDigest->computeHash();
    } else if (protocol == PINUVAuthProtocol::kPinProtocol2) {
        // For Protocol 2, use HKDF to generate HMAC key || AES key
        sharedSecret.reserveInitialCapacity(64);

        auto hkdfKey = CryptoKeyRaw::create(CryptoAlgorithmIdentifier::HKDF, Vector<uint8_t>(ecdhResult), CryptoKeyUsageDeriveBits);

        // HMAC key: HKDF-SHA-256(salt=32 zeros, IKM=Z, L=32, info="CTAP2 HMAC key")
        CryptoAlgorithmHkdfParams hmacHkdfParams;
        hmacHkdfParams.hashIdentifier = CryptoAlgorithmIdentifier::SHA_256;
        Vector<uint8_t> hkdfSalt(32, 0);
        Vector<uint8_t> hmacKeyInfo({ 'C','T','A','P','2',' ','H','M','A','C',' ','k','e','y' });
        hmacHkdfParams.salt = toBufferSource(hkdfSalt.span());
        hmacHkdfParams.info = toBufferSource(hmacKeyInfo.span());

        auto hmacKeyMaterial = CryptoAlgorithmHKDF::deriveBits(hmacHkdfParams, hkdfKey.get(), 32 * 8);
        if (hmacKeyMaterial.hasException())
            return { };
        sharedSecret.appendVector(hmacKeyMaterial.releaseReturnValue());

        // AES key: HKDF-SHA-256(salt=32 zeros, IKM=Z, L=32, info="CTAP2 AES key")
        CryptoAlgorithmHkdfParams aesHkdfParams;
        aesHkdfParams.hashIdentifier = CryptoAlgorithmIdentifier::SHA_256;
        Vector<uint8_t> aesKeyInfo({ 'C','T','A','P','2',' ','A','E','S',' ','k','e','y' });
        aesHkdfParams.salt = toBufferSource(hkdfSalt.span());
        aesHkdfParams.info = toBufferSource(aesKeyInfo.span());

        auto aesKeyMaterial = CryptoAlgorithmHKDF::deriveBits(aesHkdfParams, hkdfKey.get(), 32 * 8);
        if (aesKeyMaterial.hasException())
            return { };
        sharedSecret.appendVector(aesKeyMaterial.releaseReturnValue());
    } else {
        return { };
    }
    return sharedSecret;
}

std::optional<TokenRequest> TokenRequest::tryCreate(PINUVAuthProtocol protocol, const CString& pin, const CryptoKeyEC& peerKey)
{
    // The following implements Section 5.5.4 Getting sharedSecret from Authenticator.
    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingSharedSecret
    // 1. Generate a P256 key pair.
    auto keyPairResult = CryptoKeyEC::generatePair(CryptoAlgorithmIdentifier::ECDH, "P-256"_s, true, CryptoKeyUsageDeriveBits);
    ASSERT(!keyPairResult.hasException());
    auto keyPair = keyPairResult.releaseReturnValue();

    // 2. Use ECDH to compute the shared secret, then apply protocol-specific KDF.
    auto sharedKeyResult = CryptoAlgorithmECDH::platformDeriveBits(downcast<CryptoKeyEC>(*keyPair.privateKey), peerKey);
    if (!sharedKeyResult)
        return std::nullopt;

    auto sharedSecret = deriveProtocolSharedSecret(protocol, *sharedKeyResult);
    if (sharedSecret.isEmpty())
        return std::nullopt;

    // For Protocol 2, sharedSecret is 64 bytes: 32 bytes HMAC key + 32 bytes AES key
    // Need to extract the AES key portion appropriately
    Vector<uint8_t> aesKeyMaterial;
    if (protocol == PINUVAuthProtocol::kPinProtocol2) {
        ASSERT(sharedSecret.size() == 64);
        aesKeyMaterial = Vector<uint8_t>(sharedSecret.span().subspan(32, 32));
    } else {
        // For Protocol 1, the entire sharedSecret is used as AES key
        aesKeyMaterial = sharedSecret;
    }

    auto sharedKey = CryptoKeyAES::importRaw(CryptoAlgorithmIdentifier::AES_CBC, WTFMove(aesKeyMaterial), true, CryptoKeyUsageEncrypt | CryptoKeyUsageDecrypt);
    ASSERT(sharedKey);

    // The following encodes the public key of the above key pair into COSE format.
    auto rawPublicKeyResult = downcast<CryptoKeyEC>(*keyPair.publicKey).exportRaw();
    ASSERT(!rawPublicKeyResult.hasException());
    auto coseKey = encodeCOSEPublicKey(rawPublicKeyResult.returnValue());

    // The following calculates a SHA-256 digest of the PIN, and shrink to the left 16 bytes.
    auto pinDigest = PAL::CryptoDigest::create(PAL::CryptoDigest::Algorithm::SHA_256);
    pinDigest->addBytes(byteCast<uint8_t>(pin.span()));
    auto pinHash = pinDigest->computeHash();
    pinHash.shrink(16);

    return TokenRequest(sharedKey.releaseNonNull(), WTFMove(coseKey), WTFMove(pinHash));
}

TokenRequest::TokenRequest(Ref<WebCore::CryptoKeyAES>&& sharedKey, cbor::CBORValue::MapValue&& coseKey, Vector<uint8_t>&& pinHash)
    : m_sharedKey(WTFMove(sharedKey))
    , m_coseKey(WTFMove(coseKey))
    , m_pinHash(WTFMove(pinHash))
{
}

SetPinRequest::SetPinRequest(Ref<WebCore::CryptoKeyAES>&& sharedKey, cbor::CBORValue::MapValue&& coseKey, Vector<uint8_t>&& newPinEnc, Vector<uint8_t>&& pinUvAuthParam)
    : m_sharedKey(WTFMove(sharedKey))
    , m_coseKey(WTFMove(coseKey))
    , m_newPinEnc(WTFMove(newPinEnc))
    , m_pinUvAuthParam(WTFMove(pinUvAuthParam))
{
}

const Vector<uint8_t>& SetPinRequest::pinAuth() const
{
    return m_pinUvAuthParam;
}

std::optional<SetPinRequest> SetPinRequest::tryCreate(PINUVAuthProtocol protocol, const String& inputPin, const WebCore::CryptoKeyEC& peerKey)
{
    std::optional<CString> newPin = validateAndConvertToUTF8(inputPin);
    if (!newPin)
        return std::nullopt;

    // The following implements Section 5.5.4 Getting sharedSecret from Authenticator.
    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingSharedSecret
    // 1. Generate a P256 key pair.
    auto keyPairResult = CryptoKeyEC::generatePair(CryptoAlgorithmIdentifier::ECDH, "P-256"_s, true, CryptoKeyUsageDeriveBits);
    ASSERT(!keyPairResult.hasException());
    auto keyPair = keyPairResult.releaseReturnValue();

    auto sharedKeyResult = CryptoAlgorithmECDH::platformDeriveBits(downcast<CryptoKeyEC>(*keyPair.privateKey), peerKey);
    if (!sharedKeyResult)
        return std::nullopt;

    auto sharedSecret = deriveProtocolSharedSecret(protocol, *sharedKeyResult);
    if (sharedSecret.isEmpty())
        return std::nullopt;

    // For Protocol 2, sharedSecret is 64 bytes: 32 bytes HMAC key + 32 bytes AES key
    // Need to split them appropriately
    Vector<uint8_t> hmacKeyMaterial, aesKeyMaterial;
    if (protocol == PINUVAuthProtocol::kPinProtocol2) {
        ASSERT(sharedSecret.size() == 64);
        hmacKeyMaterial = Vector<uint8_t>(sharedSecret.span().first(32));
        aesKeyMaterial = Vector<uint8_t>(sharedSecret.span().subspan(32, 32));
    } else {
        // For Protocol 1, the entire sharedSecret is used as AES key
        hmacKeyMaterial = sharedSecret;
        aesKeyMaterial = sharedSecret;
    }

    auto sharedKey = CryptoKeyAES::importRaw(CryptoAlgorithmIdentifier::AES_CBC, WTFMove(aesKeyMaterial), true, CryptoKeyUsageEncrypt | CryptoKeyUsageDecrypt);
    ASSERT(sharedKey);

    // The following encodes the public key of the above key pair into COSE format.
    auto rawPublicKeyResult = downcast<CryptoKeyEC>(*keyPair.publicKey).exportRaw();
    ASSERT(!rawPublicKeyResult.hasException());
    auto coseKey = encodeCOSEPublicKey(rawPublicKeyResult.returnValue());

    const size_t minPaddedPinLength = 64;
    Vector<uint8_t> paddedPin;
    paddedPin.reserveInitialCapacity(minPaddedPinLength);
    paddedPin.append(inputPin.utf8().span());
    for (int i = paddedPin.size(); i < 64; i++)
        paddedPin.append('\0');

    auto hmacKey = CryptoKeyHMAC::importRaw(hmacKeyMaterial.size() * 8 /* lengthInBits */, CryptoAlgorithmIdentifier::SHA_256, WTFMove(hmacKeyMaterial), true, CryptoKeyUsageSign);

    auto newPinEnc = CryptoAlgorithmAESCBC::platformEncrypt({ }, *sharedKey, paddedPin, CryptoAlgorithmAESCBC::Padding::No);
    ASSERT(!newPinEnc.hasException());

    auto pinUvAuthParam = CryptoAlgorithmHMAC::platformSign(*hmacKey, newPinEnc.returnValue());
    ASSERT(!pinUvAuthParam.hasException());

    return SetPinRequest(sharedKey.releaseNonNull(), WTFMove(coseKey), newPinEnc.releaseReturnValue(), pinUvAuthParam.releaseReturnValue());
}

Vector<uint8_t> encodeAsCBOR(const TokenRequest& request)
{
    auto result = CryptoAlgorithmAESCBC::platformEncrypt({ }, request.sharedKey(), request.m_pinHash, CryptoAlgorithmAESCBC::Padding::No);
    ASSERT(!result.hasException());

    return encodePinCommand(Subcommand::kGetPinToken, [coseKey = WTFMove(request.m_coseKey), encryptedPin = result.releaseReturnValue()] (CBORValue::MapValue* map) mutable {
        map->emplace(static_cast<int64_t>(RequestKey::kKeyAgreement), WTFMove(coseKey));
        map->emplace(static_cast<int64_t>(RequestKey::kPinHashEnc), WTFMove(encryptedPin));
    });
}

Vector<uint8_t> encodeAsCBOR(const SetPinRequest& request)
{
    return encodePinCommand(Subcommand::kSetPin, [coseKey = WTFMove(request.m_coseKey), encryptedPin = request.m_newPinEnc, pinUvAuthParam = request.m_pinUvAuthParam] (CBORValue::MapValue* map) mutable {
        map->emplace(static_cast<int64_t>(RequestKey::kKeyAgreement), WTFMove(coseKey));
        map->emplace(static_cast<int64_t>(RequestKey::kNewPinEnc), WTFMove(encryptedPin));
        map->emplace(static_cast<int64_t>(RequestKey::kPinAuth), WTFMove(pinUvAuthParam));
    });
}

} // namespace pin
} // namespace fido

#endif // ENABLE(WEB_AUTHN)
