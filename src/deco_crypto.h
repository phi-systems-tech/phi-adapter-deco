#pragma once

// The envelope the Deco web UI wraps every call in, and nothing else.
//
// Login hands out two RSA public keys as hex modulus and exponent: one for the
// password, one for the signature. Every later body is AES-128-CBC under a key
// and IV the client picks itself (sixteen ASCII digits each, which is what the
// web UI does), and carries an RSA-encrypted signature that binds the MD5 of
// "admin" + password to a sequence number the router counts on.

#include <optional>
#include <string>
#include <string_view>

namespace phicore::deco::ipc {

/// PKCS#1 v1.5 under the key (hex modulus, hex exponent), in blocks of key
/// size - 11 bytes for input longer than one, hex out. Empty on a bad key.
std::string rsaEncryptHex(std::string_view modulusHex, std::string_view exponentHex,
                          std::string_view plain);

/// Sixteen random decimal digits: the Deco's AES key and IV are text.
std::string randomDigits16();

struct AesKey {
    std::string key;   ///< 16 bytes
    std::string iv;    ///< 16 bytes
};

/// AES-128-CBC with PKCS#7, base64 out.
std::string aesEncryptBase64(const AesKey &key, std::string_view plain);
/// The way back; nothing when the base64, the padding or the key is wrong.
std::optional<std::string> aesDecryptBase64(const AesKey &key, std::string_view base64);

std::string md5Hex(std::string_view text);

/// application/x-www-form-urlencoded for one value: everything but
/// unreserved characters percent-encoded (base64's + / = included).
std::string formEncode(std::string_view value);

std::string base64Encode(std::string_view bytes);
std::optional<std::string> base64Decode(std::string_view text);

} // namespace phicore::deco::ipc
