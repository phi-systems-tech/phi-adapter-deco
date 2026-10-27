#pragma once

// What the Deco's answers say, and what phi-core is told about the nodes.
// Data, not behaviour: the clients go to the SDK's ClientTracker.

#include <map>
#include <string>
#include <vector>

#include "phi/adapter/sdk/network_clients.h"
#include "phi/adapter/v1/channel.h"
#include "phi/adapter/v1/device.h"

#include "deco_json.h"

namespace phicore::deco::ipc {

/// One Deco of the mesh (`device_list`).
struct DecoNode {
    std::string mac;   ///< aa:bb:cc:dd:ee:ff
    std::string macDashed;   ///< AA-BB-..., as the API wants it back
    std::string ip;
    std::string name;   ///< the nickname the household gave it
    std::string model;
    std::string role;   ///< master / slave
    std::string firmware;
    std::string hardware;
    bool internet = false;
    bool meshConnected = false;
};

inline constexpr const char kNodeChannelOnline[] = "online";
inline constexpr const char kNodeChannelClients[] = "clients";

std::vector<DecoNode> parseDeviceList(const Json &reply);

/// The online clients one node lists (`client_list` with its MAC), each with
/// that node as its access point.
std::vector<phicore::adapter::sdk::NetworkClientSighting> parseClientList(const Json &reply,
                                                                          const std::string &nodeName);

/// dBm per client MAC from `client_access`.
std::map<std::string, int> parseClientSignal(const Json &reply);

/// The blocked client MACs (`black_list`, operation list).
std::vector<std::string> parseBlackList(const Json &reply);

/// `client_access` reports the signal as a positive number (16-70 here, with
/// signal levels 2 and 3 above ~30): the margin over the radio's noise floor,
/// as Qualcomm drivers count it. dBm is that minus 95, the floor they assume.
int marginToDbm(int margin);

phicore::adapter::v1::NetworkClientType clientType(const std::string &deco);

/// Client names come base64-encoded; one that does not decode is kept as is.
std::string decodeName(const std::string &b64);

std::string nodeDeviceId(const DecoNode &node);
phicore::adapter::v1::Device buildNodeDevice(const DecoNode &node);
phicore::adapter::v1::ChannelList buildNodeChannels();
std::string nodeFingerprint(const DecoNode &node);

/// `AA-BB-CC-DD-EE-FF` from any spelling, for the API's writes.
std::string dashedMac(const std::string &mac);

} // namespace phicore::deco::ipc
