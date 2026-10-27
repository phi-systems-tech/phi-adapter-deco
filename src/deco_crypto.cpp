#include "deco_crypto.h"

#include <memory>
#include <random>
#include <vector>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

namespace phicore::deco::ipc {

namespace {

template <typename T, void (*Free)(T *)>
struct Deleter {
    void operator()(T *p) const { Free(p); }
};
using Bignum = std::unique_ptr<BIGNUM, Deleter<BIGNUM, BN_free>>;
using PKey = std::unique_ptr<EVP_PKEY, Deleter<EVP_PKEY, EVP_PKEY_free>>;
using PKeyCtx = std::unique_ptr<EVP_PKEY_CTX, Deleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, Deleter<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>>;
using ParamBld = std::unique_ptr<OSSL_PARAM_BLD, Deleter<OSSL_PARAM_BLD, OSSL_PARAM_BLD_free>>;
using Params = std::unique_ptr<OSSL_PARAM, Deleter<OSSL_PARAM, OSSL_PARAM_free>>;

Bignum fromHex(std::string_view hex)
{
    BIGNUM *bn = nullptr;
    const std::string text(hex);
    const int parsed = text.empty() ? 0 : BN_hex2bn(&bn, text.c_str());
    Bignum out(bn);
    // Only all of it: a key cut short is no key.
    if (parsed != static_cast<int>(text.size()))
        out.reset();
    return out;
}

PKey rsaPublicKey(std::string_view modulusHex, std::string_view exponentHex)
{
    const Bignum n = fromHex(modulusHex);
    const Bignum e = fromHex(exponentHex);
    if (!n || !e || BN_is_zero(n.get()) || BN_is_zero(e.get()))
        return {};
    ParamBld bld(OSSL_PARAM_BLD_new());
    if (!bld || !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, n.get())
        || !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, e.get()))
        return {};
    Params params(OSSL_PARAM_BLD_to_param(bld.get()));
    PKeyCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr));
    EVP_PKEY *key = nullptr;
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0
        || EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0)
        return {};
    return PKey(key);
}

std::string toHex(const unsigned char *data, std::size_t size)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 0x0f]);
    }
    return out;
}

} // namespace

std::string rsaEncryptHex(std::string_view modulusHex, std::string_view exponentHex,
                          std::string_view plain)
{
    const PKey key = rsaPublicKey(modulusHex, exponentHex);
    if (!key)
        return {};
    const int keyBytes = EVP_PKEY_get_size(key.get());
    const std::size_t step = static_cast<std::size_t>(keyBytes) - 11;
    if (keyBytes <= 11)
        return {};
    std::string out;
    std::vector<unsigned char> block(static_cast<std::size_t>(keyBytes));
    for (std::size_t at = 0; at < plain.size() || (at == 0 && plain.empty()); at += step) {
        const std::string_view piece = plain.substr(at, step);
        PKeyCtx ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
        std::size_t written = block.size();
        if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0
            || EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) <= 0
            || EVP_PKEY_encrypt(ctx.get(), block.data(), &written,
                                reinterpret_cast<const unsigned char *>(piece.data()), piece.size()) <= 0)
            return {};
        out += toHex(block.data(), written);
        if (plain.empty())
            break;
    }
    return out;
}

std::string randomDigits16()
{
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof bytes) != 1) {
        std::random_device device;
        for (unsigned char &b : bytes)
            b = static_cast<unsigned char>(device());
    }
    std::string out(16, '0');
    // The first digit is never 0, as in the web UI's own key.
    out[0] = static_cast<char>('1' + bytes[0] % 9);
    for (std::size_t i = 1; i < 16; ++i)
        out[i] = static_cast<char>('0' + bytes[i] % 10);
    return out;
}

std::string aesEncryptBase64(const AesKey &key, std::string_view plain)
{
    if (key.key.size() != 16 || key.iv.size() != 16)
        return {};
    CipherCtx ctx(EVP_CIPHER_CTX_new());
    std::string out(plain.size() + 16, '\0');
    int len = 0;
    int tail = 0;
    if (!ctx
        || EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr,
                              reinterpret_cast<const unsigned char *>(key.key.data()),
                              reinterpret_cast<const unsigned char *>(key.iv.data())) != 1
        || EVP_EncryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(out.data()), &len,
                             reinterpret_cast<const unsigned char *>(plain.data()),
                             static_cast<int>(plain.size())) != 1
        || EVP_EncryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(out.data()) + len, &tail) != 1)
        return {};
    out.resize(static_cast<std::size_t>(len + tail));
    return base64Encode(out);
}

std::optional<std::string> aesDecryptBase64(const AesKey &key, std::string_view base64)
{
    if (key.key.size() != 16 || key.iv.size() != 16)
        return std::nullopt;
    const std::optional<std::string> raw = base64Decode(base64);
    if (!raw || raw->empty() || raw->size() % 16 != 0)
        return std::nullopt;
    CipherCtx ctx(EVP_CIPHER_CTX_new());
    std::string out(raw->size() + 16, '\0');
    int len = 0;
    int tail = 0;
    if (!ctx
        || EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr,
                              reinterpret_cast<const unsigned char *>(key.key.data()),
                              reinterpret_cast<const unsigned char *>(key.iv.data())) != 1
        || EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(out.data()), &len,
                             reinterpret_cast<const unsigned char *>(raw->data()),
                             static_cast<int>(raw->size())) != 1
        || EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(out.data()) + len, &tail) != 1)
        return std::nullopt;
    out.resize(static_cast<std::size_t>(len + tail));
    return out;
}

std::string md5Hex(std::string_view text)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    if (EVP_Digest(text.data(), text.size(), digest, &size, EVP_md5(), nullptr) != 1)
        return {};
    return toHex(digest, size);
}

std::string formEncode(std::string_view value)
{
    static constexpr char kDigits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size() * 3);
    for (const char c : value) {
        const auto u = static_cast<unsigned char>(c);
        if ((u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z') || (u >= '0' && u <= '9')
            || u == '-' || u == '_' || u == '.' || u == '~') {
            out.push_back(c);
            continue;
        }
        out.push_back('%');
        out.push_back(kDigits[u >> 4]);
        out.push_back(kDigits[u & 0x0f]);
    }
    return out;
}

std::string base64Encode(std::string_view bytes)
{
    std::string out(4 * ((bytes.size() + 2) / 3) + 1, '\0');
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                                  reinterpret_cast<const unsigned char *>(bytes.data()),
                                  static_cast<int>(bytes.size()));
    out.resize(n > 0 ? static_cast<std::size_t>(n) : 0);
    return out;
}

std::optional<std::string> base64Decode(std::string_view text)
{
    std::string clean;
    clean.reserve(text.size());
    for (const char c : text)
        if (c != '\n' && c != '\r' && c != ' ')
            clean.push_back(c);
    if (clean.size() % 4 != 0)
        return std::nullopt;
    if (clean.empty())
        return std::string();
    std::string out(clean.size() / 4 * 3, '\0');
    const int n = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                                  reinterpret_cast<const unsigned char *>(clean.data()),
                                  static_cast<int>(clean.size()));
    if (n < 0)
        return std::nullopt;
    // EVP_DecodeBlock counts the padding as bytes; take them back off.
    std::size_t size = static_cast<std::size_t>(n);
    if (clean.back() == '=')
        --size;
    if (clean.size() >= 2 && clean[clean.size() - 2] == '=')
        --size;
    out.resize(size);
    return out;
}

} // namespace phicore::deco::ipc
