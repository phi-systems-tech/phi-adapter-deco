#include "deco_schema.h"

#include <utility>

#include "phi/adapter/sdk/network_clients.h"

namespace phicore::deco::ipc {

namespace sdk = phicore::adapter::sdk;
namespace v1 = phicore::adapter::v1;

namespace {

v1::AdapterConfigSection section()
{
    using Type = v1::AdapterConfigFieldType;
    using Flag = v1::AdapterConfigFieldFlag;
    v1::AdapterConfigSection out;
    out.setTitle("TP-Link Deco");
    out.setDescription("The main Deco's address and the owner password of the Deco app. The Deco takes one "
                       "admin session at a time: phi logs in for a few seconds per poll, and the app may "
                       "have to log in again while it does.");
    out.layout().setColumns(2);

    v1::AdapterConfigField host("host", Type::Hostname, "Main Deco", "IP address or name of the main Deco.");
    host.setFlags(Flag::Required);
    v1::AdapterConfigField password("password", Type::Password, "Owner password",
                                    "The password the Deco app's owner account logs in with.");
    password.setFlags(Flag::Required | Flag::Secret);
    v1::AdapterConfigField poll(kMetaPollIntervalS, Type::Integer, "Poll interval (s)",
                                "How often the clients are read.");
    poll.setDefaultValue(std::int64_t{kDefaultPollIntervalS}).setMinValue(kMinPollIntervalS).setMaxValue(600);
    poll.layout().setControlWidth(v1::AdapterConfigSize::Narrow);

    v1::AdapterConfigFieldList fields{host, password, poll};
    for (v1::AdapterConfigField &field : sdk::ClientTracker::configFields())
        fields.push_back(std::move(field));
    out.setFields(std::move(fields));
    return out;
}

} // namespace

v1::Utf8String displayName() { return "TP-Link Deco"; }
v1::Utf8String description() { return "TP-Link Deco mesh: its nodes and the network's clients"; }

v1::Utf8String iconSvg()
{
    return "<svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"Deco\">"
           "<rect x=\"6\" y=\"3\" width=\"12\" height=\"18\" rx=\"6\" fill=\"#f4f6f8\" stroke=\"#4acbd6\" stroke-width=\"1.5\"/>"
           "<circle cx=\"12\" cy=\"17\" r=\"1.2\" fill=\"#4acbd6\"/>"
           "</svg>";
}

v1::AdapterCapabilities capabilities()
{
    v1::AdapterCapabilities caps;
    caps.setRequired(v1::AdapterRequirement::Host | v1::AdapterRequirement::Password);
    caps.setFlags(v1::AdapterCapability::RequiresPolling | v1::AdapterCapability::NetworkClients
                  | v1::AdapterCapability::SupportsProbe | v1::AdapterCapability::SupportsDiscovery);
    // One login, the nodes, a logout: a wrong password counts as one try.
    caps.addFactoryAction({"probe", "Test connection", "Log in to the main Deco once and read its nodes."});
    // The web API on the main Deco; TP-Link's cloud is the app's business.
    caps.setTopologies(v1::Topology::Local);
    caps.setPairingStyles(v1::PairingStyle::Listing);
    return caps;
}

v1::AdapterConfigSchema configSchema()
{
    v1::AdapterConfigSchema schema;
    schema.setFactory(section());
    schema.setInstance(section());
    return schema;
}

} // namespace phicore::deco::ipc
