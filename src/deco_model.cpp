#include "deco_model.h"

#include <algorithm>
#include <cctype>

#include "deco_crypto.h"

namespace phicore::deco::ipc {

namespace sdk = phicore::adapter::sdk;
namespace v1 = phicore::adapter::v1;

namespace {

std::string lower(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

Json resultList(const Json &reply, const char *key)
{
    const Json list = jsonValue(jsonValue(reply, "result"), key);
    return list.is_array() ? list : Json::array();
}

bool validUtf8(const std::string &text)
{
    std::size_t i = 0;
    while (i < text.size()) {
        const auto c = static_cast<unsigned char>(text[i]);
        const std::size_t n = c < 0x80 ? 1 : (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xe ? 3 : (c >> 3) == 0x1e ? 4 : 0;
        if (n == 0 || i + n > text.size())
            return false;
        for (std::size_t k = 1; k < n; ++k)
            if ((static_cast<unsigned char>(text[i + k]) >> 6) != 0x2)
                return false;
        if (n == 1 && c < 0x20)
            return false;
        i += n;
    }
    return true;
}

v1::WifiBand band(const std::string &connectionType, const std::string &wireType)
{
    const std::string c = lower(connectionType);
    if (c == "band2_4")
        return v1::WifiBand::Band24;
    if (c == "band5" || c == "band5_1" || c == "band5_2")
        return v1::WifiBand::Band5;
    if (c == "band6")
        return v1::WifiBand::Band6;
    if (c == "wired" || lower(wireType) == "wired")
        return v1::WifiBand::Wired;
    // A wireless client the node did not put on a band ("UNKNOWN", common on
    // the satellites): wireless, band unknown.
    return v1::WifiBand::Unknown;
}

} // namespace

std::string dashedMac(const std::string &mac)
{
    std::string normal = sdk::ClientTracker::normalizedMac(mac);
    for (char &c : normal) {
        if (c == ':')
            c = '-';
        else
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return normal;
}

std::string decodeName(const std::string &b64)
{
    const std::optional<std::string> decoded = base64Decode(b64);
    if (!decoded || decoded->empty() || !validUtf8(*decoded))
        return b64;
    return *decoded;
}

int marginToDbm(int margin) { return std::clamp(margin - 95, -100, 0); }

v1::NetworkClientType clientType(const std::string &deco)
{
    const std::string t = lower(deco);
    if (t == "phone")
        return v1::NetworkClientType::Phone;
    if (t == "tablet")
        return v1::NetworkClientType::Tablet;
    if (t == "pc" || t == "laptop" || t == "computer")
        return v1::NetworkClientType::Computer;
    if (t == "tv")
        return v1::NetworkClientType::Tv;
    if (t == "game_console" || t == "console")
        return v1::NetworkClientType::Console;
    if (t == "iot_device" || t == "camera" || t == "smart_speaker" || t == "smart_home")
        return v1::NetworkClientType::Iot;
    // The app lets the household type its own ("Smart Washer", "Firewall").
    return t.empty() ? v1::NetworkClientType::Unknown : v1::NetworkClientType::Other;
}

std::vector<DecoNode> parseDeviceList(const Json &reply)
{
    std::vector<DecoNode> nodes;
    for (const Json &d : resultList(reply, "device_list")) {
        DecoNode node;
        node.macDashed = jsonString(d, "mac");
        node.mac = sdk::ClientTracker::normalizedMac(node.macDashed);
        if (node.mac.empty())
            continue;
        node.ip = jsonString(d, "device_ip");
        node.name = jsonString(d, "nickname");
        node.model = jsonString(d, "device_model");
        node.role = jsonString(d, "role");
        node.firmware = jsonString(d, "software_ver");
        node.hardware = jsonString(d, "hardware_ver");
        node.internet = jsonString(d, "inet_status") == "online";
        node.meshConnected = jsonString(d, "group_status") == "connected";
        nodes.push_back(std::move(node));
    }
    return nodes;
}

std::vector<sdk::NetworkClientSighting> parseClientList(const Json &reply, const std::string &nodeName)
{
    std::vector<sdk::NetworkClientSighting> out;
    for (const Json &c : resultList(reply, "client_list")) {
        sdk::NetworkClientSighting s;
        s.mac = sdk::ClientTracker::normalizedMac(jsonString(c, "mac"));
        if (s.mac.empty())
            continue;
        s.name = decodeName(jsonString(c, "name"));
        s.ipv4 = jsonString(c, "ip");
        if (s.ipv4 == "0.0.0.0")
            s.ipv4.clear();
        s.accessPoint = nodeName;
        s.band = band(jsonString(c, "connection_type"), jsonString(c, "wire_type"));
        s.type = clientType(jsonString(c, "client_type"));
        s.guest = jsonString(c, "interface") == "guest";
        s.online = !c.contains("online") || jsonBool(c, "online");
        out.push_back(std::move(s));
    }
    return out;
}

std::map<std::string, int> parseClientSignal(const Json &reply)
{
    std::map<std::string, int> out;
    for (const Json &c : resultList(reply, "client_list")) {
        const std::string mac = sdk::ClientTracker::normalizedMac(jsonString(c, "mac"));
        if (mac.empty())
            continue;
        const bool on5 = lower(jsonString(c, "connection_type")) == "band5";
        const int margin = jsonInt(c, on5 ? "rssi_in_dbm_5g" : "rssi_in_dbm_2g", 0);
        const int other = jsonInt(c, on5 ? "rssi_in_dbm_2g" : "rssi_in_dbm_5g", 0);
        const int best = margin > 0 ? margin : other;
        if (best > 0)
            out[mac] = marginToDbm(best);
    }
    return out;
}

std::vector<std::string> parseBlackList(const Json &reply)
{
    std::vector<std::string> out;
    const Json list = jsonValue(jsonValue(reply, "result"), "client_list");
    // Empty, it comes as {} rather than []; filled, entries are objects with
    // the MAC or the MACs themselves.
    if (!list.is_array())
        return out;
    for (const Json &entry : list) {
        const std::string raw = entry.is_string() ? entry.get<std::string>() : jsonString(entry, "mac");
        const std::string mac = sdk::ClientTracker::normalizedMac(raw);
        if (!mac.empty())
            out.push_back(mac);
    }
    return out;
}

std::string nodeDeviceId(const DecoNode &node) { return "node-" + node.mac; }

v1::Device buildNodeDevice(const DecoNode &node)
{
    v1::Device device;
    device.setExternalId(nodeDeviceId(node));
    device.setName(node.name.empty() ? "Deco " + node.model : node.name);
    device.setDeviceClass(v1::DeviceClass::Gateway);
    device.setManufacturer("TP-Link");
    device.setModel(node.model.empty() ? "Deco" : "Deco " + node.model);
    if (!node.firmware.empty())
        device.setFirmware(node.firmware);
    device.setMac(node.mac);
    if (!node.ip.empty())
        device.setIpv4(node.ip);
    Json meta = Json::object();
    meta["role"] = node.role;
    if (!node.hardware.empty())
        meta["hardware"] = node.hardware;
    device.setMetaJson(dump(meta));
    return device;
}

v1::ChannelList buildNodeChannels()
{
    v1::ChannelList channels;
    v1::Channel online;
    online.setExternalId(kNodeChannelOnline);
    online.setName("Online");
    online.setKind(v1::ChannelKind::ConnectivityStatus);
    online.setDataType(v1::ChannelDataType::Enum);
    online.setFlags(v1::kChannelFlagDefaultRead);
    channels.push_back(std::move(online));

    v1::Channel clients;
    clients.setExternalId(kNodeChannelClients);
    clients.setName("Clients");
    clients.setKind(v1::ChannelKind::Unknown);
    clients.setDataType(v1::ChannelDataType::Int);
    // A count per poll; a household that wants the curve turns history on.
    clients.setFlags(v1::kChannelFlagDefaultRead | v1::ChannelFlag::NoHistory);
    channels.push_back(std::move(clients));
    return channels;
}

std::string nodeFingerprint(const DecoNode &node)
{
    return node.mac + '\x1f' + node.name + '\x1f' + node.ip + '\x1f' + node.model + '\x1f' + node.firmware + '\x1f'
        + node.role;
}

} // namespace phicore::deco::ipc
