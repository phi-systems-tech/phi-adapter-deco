// The Deco's envelope and its answers, against shapes taken from the X55 in
// the test house (2026-10-26, values made up).

#include <phi/adapter/testing/check.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <memory>
#include <string>

#include "deco_crypto.h"
#include "deco_model.h"
#include "deco_schema.h"

using namespace phicore::deco::ipc;
namespace v1 = phicore::adapter::v1;

namespace {

void testAesRoundTrip()
{
    const AesKey key{"1234567890123456", "6543210987654321"};
    const std::string plain = R"({"operation":"read","params":{"device_mac":"AA-BB-CC-DD-EE-FF"}})";
    const std::string sealed = aesEncryptBase64(key, plain);
    PHI_CHECK(!sealed.empty());
    const auto opened = aesDecryptBase64(key, sealed);
    PHI_CHECK(opened && *opened == plain);
    PHI_CHECK(!aesDecryptBase64(AesKey{"0000000000000000", "6543210987654321"}, sealed).has_value()
              || *aesDecryptBase64(AesKey{"0000000000000000", "6543210987654321"}, sealed) != plain);
    PHI_CHECK(!aesDecryptBase64(key, "not base64!").has_value());
}

void testDigits()
{
    const std::string d = randomDigits16();
    PHI_CHECK(d.size() == 16 && d[0] != '0');
    for (const char c : d)
        PHI_CHECK(c >= '0' && c <= '9');
}

void testHashesAndEncodings()
{
    PHI_CHECK(md5Hex("admin") == "21232f297a57a5a743894a0e4a801fc3");
    PHI_CHECK(base64Encode("Living Room") == "TGl2aW5nIFJvb20=");
    PHI_CHECK(*base64Decode("TGl2aW5nIFJvb20=") == "Living Room");
    PHI_CHECK(*base64Decode("bHdpcDA=") == "lwip0");
    PHI_CHECK(formEncode("a+b/c=") == "a%2Bb%2Fc%3D");
}

// RSA as the router does it: PKCS#1 v1.5 with its public key, decrypted here
// with the private half to prove the blocks.
void testRsaBlocks()
{
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> gen(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr),
                                                                   EVP_PKEY_CTX_free);
    EVP_PKEY *raw = nullptr;
    PHI_CHECK(gen && EVP_PKEY_keygen_init(gen.get()) > 0);
    EVP_PKEY_CTX_set_rsa_keygen_bits(gen.get(), 512);
    PHI_CHECK(EVP_PKEY_generate(gen.get(), &raw) > 0);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw, EVP_PKEY_free);
    BIGNUM *n = nullptr;
    BIGNUM *e = nullptr;
    EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_RSA_E, &e);
    char *nHex = BN_bn2hex(n);
    char *eHex = BN_bn2hex(e);

    // Longer than one block (512 bit: 53 bytes per block), like the signature.
    const std::string plain = "k=1234567890123456&i=6543210987654321&h=21232f297a57a5a743894a0e4a801fc3&s=12345";
    const std::string hex = rsaEncryptHex(nHex, eHex, plain);
    PHI_CHECK_MSG(hex.size() == 2 * 64 * 2, "hex size %zu", hex.size());

    std::string decrypted;
    for (std::size_t at = 0; at < hex.size(); at += 128) {
        std::string block;
        for (std::size_t i = at; i < at + 128; i += 2)
            block.push_back(static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new(key.get(), nullptr),
                                                                       EVP_PKEY_CTX_free);
        EVP_PKEY_decrypt_init(ctx.get());
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING);
        unsigned char out[64];
        std::size_t outLen = sizeof out;
        PHI_CHECK(EVP_PKEY_decrypt(ctx.get(), out, &outLen, reinterpret_cast<const unsigned char *>(block.data()),
                                   block.size())
                  > 0);
        decrypted.append(reinterpret_cast<char *>(out), outLen);
    }
    PHI_CHECK(decrypted == plain);
    PHI_CHECK(rsaEncryptHex("zz", eHex, "x").empty());
    OPENSSL_free(nHex);
    OPENSSL_free(eHex);
    BN_free(n);
    BN_free(e);
}

void testDeviceList()
{
    const Json reply = Json::parse(R"({"error_code":0,"result":{"device_list":[
        {"mac":"3C-64-CF-86-50-F8","device_ip":"192.168.18.3","nickname":"Living Room","device_model":"X55",
         "role":"master","software_ver":"1.11.1 Build 26081714","hardware_ver":"1.0","inet_status":"online",
         "group_status":"connected"},
        {"mac":"3C-64-CF-86-51-00","device_ip":"192.168.18.6","nickname":"","device_model":"X55",
         "role":"slave","inet_status":"offline","group_status":"connected"},
        {"mac":"broken"}]}})");
    const auto nodes = parseDeviceList(reply);
    PHI_CHECK(nodes.size() == 2);
    PHI_CHECK(nodes[0].mac == "3c:64:cf:86:50:f8");
    PHI_CHECK(nodes[0].macDashed == "3C-64-CF-86-50-F8");
    PHI_CHECK(nodes[0].internet && nodes[0].meshConnected);
    PHI_CHECK(nodes[1].role == "slave" && !nodes[1].internet && nodes[1].meshConnected);
    const v1::Device d = buildNodeDevice(nodes[1]);
    PHI_CHECK(d.externalId() == "node-3c:64:cf:86:51:00");
    PHI_CHECK(d.name() == "Deco X55");
    PHI_CHECK(d.deviceClass() == v1::DeviceClass::Gateway);
    PHI_CHECK(d.ipv4() == "192.168.18.6");
}

void testClientList()
{
    const Json reply = Json::parse(R"({"error_code":0,"result":{"client_list":[
        {"mac":"D8-C8-0C-02-22-44","ip":"192.168.18.70","name":"bHdpcDA=","online":true,"wire_type":"wireless",
         "connection_type":"band2_4","client_type":"iot_device","interface":"iot"},
        {"mac":"AA-BB-CC-00-11-22","ip":"192.168.18.40","name":"TWFyaXVzIGlQaG9uZQ==","online":true,
         "wire_type":"wireless","connection_type":"band5","client_type":"phone","interface":"main"},
        {"mac":"AA-BB-CC-00-11-33","ip":"0.0.0.0","name":"not*base64","online":true,"wire_type":"wired",
         "connection_type":"wired","client_type":"Firewall","interface":"guest"},
        {"mac":"AA-BB-CC-00-11-44","name":"","online":true,"wire_type":"wireless","connection_type":"UNKNOWN",
         "client_type":"pc","interface":"main"}]}})");
    const auto clients = parseClientList(reply, "Living Room");
    PHI_CHECK(clients.size() == 4);
    PHI_CHECK(clients[0].mac == "d8:c8:0c:02:22:44" && clients[0].name == "lwip0");
    PHI_CHECK(clients[0].band == v1::WifiBand::Band24 && clients[0].type == v1::NetworkClientType::Iot);
    PHI_CHECK(clients[0].accessPoint == "Living Room");
    PHI_CHECK(clients[1].name == "Marius iPhone" && clients[1].type == v1::NetworkClientType::Phone);
    PHI_CHECK(clients[1].band == v1::WifiBand::Band5 && !clients[1].guest);
    PHI_CHECK(clients[2].name == "not*base64" && clients[2].ipv4.empty());
    PHI_CHECK(clients[2].band == v1::WifiBand::Wired && clients[2].guest);
    PHI_CHECK(clients[2].type == v1::NetworkClientType::Other);
    PHI_CHECK(clients[3].band == v1::WifiBand::Unknown && clients[3].type == v1::NetworkClientType::Computer);
}

void testSignalAndBlackList()
{
    const Json access = Json::parse(R"({"error_code":0,"result":{"client_list":[
        {"mac":"B8-16-5F-30-BB-C8","rssi_in_dbm_2g":39,"rssi_in_dbm_5g":0,"connection_type":"band2_4"},
        {"mac":"AA-BB-CC-00-11-22","rssi_in_dbm_2g":0,"rssi_in_dbm_5g":50,"connection_type":"band5"},
        {"mac":"AA-BB-CC-00-11-55","rssi_in_dbm_2g":0,"rssi_in_dbm_5g":0,"connection_type":"UNKNOWN"}]}})");
    const auto signal = parseClientSignal(access);
    PHI_CHECK(signal.size() == 2);
    PHI_CHECK(signal.at("b8:16:5f:30:bb:c8") == -56);
    PHI_CHECK(signal.at("aa:bb:cc:00:11:22") == -45);
    PHI_CHECK(marginToDbm(200) == 0 && marginToDbm(-20) == -100);

    PHI_CHECK(parseBlackList(Json::parse(R"({"error_code":0,"result":{"client_list":{}}})")).empty());
    const auto blocked = parseBlackList(Json::parse(
        R"({"error_code":0,"result":{"client_list":[{"mac":"D8-C8-0C-BB-66-3D","name":"eA=="},"AA-BB-CC-00-11-22"]}})"));
    PHI_CHECK(blocked.size() == 2 && blocked[0] == "d8:c8:0c:bb:66:3d" && blocked[1] == "aa:bb:cc:00:11:22");
    PHI_CHECK(dashedMac("d8:c8:0c:bb:66:3d") == "D8-C8-0C-BB-66-3D");
}

void testCapabilities()
{
    const v1::AdapterCapabilities caps = capabilities();
    PHI_CHECK(v1::hasFlag(caps.flags(), v1::AdapterCapability::NetworkClients));
    PHI_CHECK(caps.pairingStyles() == v1::PairingStyle::Listing);
    PHI_CHECK(caps.topologies() == v1::Topology::Local);
}

} // namespace

int main()
{
    testAesRoundTrip();
    testDigits();
    testHashesAndEncodings();
    testRsaBlocks();
    testDeviceList();
    testClientList();
    testSignalAndBlackList();
    testCapabilities();
    return phi::testing::report("deco_tests");
}
