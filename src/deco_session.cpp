#include "deco_session.h"

#include <chrono>
#include <utility>

namespace phicore::deco::ipc {

namespace net = phicore::adapter::net;

namespace {

constexpr auto kTimeout = std::chrono::seconds(15);

// The two halves of an RSA key the router hands out as ["<n hex>", "<e hex>"].
bool keyPair(const Json &value, std::string *n, std::string *e)
{
    if (!value.is_array() || value.size() < 2 || !value[0].is_string() || !value[1].is_string())
        return false;
    *n = value[0].get<std::string>();
    *e = value[1].get<std::string>();
    return !n->empty() && !e->empty();
}

} // namespace

const char *outcomeName(DecoSession::Outcome outcome)
{
    switch (outcome) {
    case DecoSession::Outcome::Ok:
        return "ok";
    case DecoSession::Outcome::LoginRejected:
        return "login rejected";
    case DecoSession::Outcome::Unreachable:
        return "unreachable";
    case DecoSession::Outcome::Evicted:
        return "session taken over";
    case DecoSession::Outcome::Protocol:
        return "unexpected answer";
    }
    return "?";
}

DecoSession::DecoSession(phi::runtime::Loop &loop) : m_http(loop) {}
DecoSession::~DecoSession() = default;

void DecoSession::setEndpoint(std::string host, std::string caFile)
{
    m_host = std::move(host);
    m_caFile = std::move(caFile);
}

void DecoSession::setPassword(std::string password) { m_password = std::move(password); }

bool DecoSession::run(std::vector<Step> steps, std::function<void(Result)> done)
{
    if (m_running || m_host.empty())
        return false;
    m_running = true;
    m_steps = std::move(steps);
    m_done = std::move(done);
    m_result = {};
    m_stok.clear();
    m_cookie.clear();
    login();
    return true;
}

void DecoSession::cancel()
{
    m_http.cancel();
    m_running = false;
    m_steps.clear();
    m_done = nullptr;
}

void DecoSession::post(const std::string &path, const std::string &form, std::string body,
                       std::function<void(Http::Result)> done)
{
    Http::Call call("https://" + m_host + "/cgi-bin/luci/;stok=" + m_stok + "/" + path + "?form=" + form, "POST");
    call.setBody(std::move(body), "application/json");
    call.setTimeout(kTimeout);
    call.tls().setEnabled(true).setCaFile(m_caFile).setVerifyHostname(false);
    if (!m_cookie.empty())
        call.addHeader("Cookie", m_cookie);
    if (!m_http.send(std::move(call), std::move(done)))
        finish(Outcome::Protocol, "a request was already in flight");
}

void DecoSession::encrypted(const std::string &path, const std::string &form, const Json &payload, bool login,
                            std::function<void(std::optional<Json>, int)> done)
{
    const std::string data = aesEncryptBase64(m_aes, dump(payload));
    const std::string seq = std::to_string(m_seq + static_cast<long long>(data.size()));
    const std::string signText = login ? "k=" + m_aes.key + "&i=" + m_aes.iv + "&h=" + m_authHash + "&s=" + seq
                                       : "h=" + m_authHash + "&s=" + seq;
    const std::string sign = rsaEncryptHex(m_signKeyN, m_signKeyE, signText);
    if (data.empty() || sign.empty()) {
        finish(Outcome::Protocol, "the request could not be encrypted");
        return;
    }
    post(path, form, "sign=" + sign + "&data=" + formEncode(data),
         [this, login, done = std::move(done)](Http::Result result) {
             if (login) {
                 // luci hands the session cookie with the token; later calls
                 // carry both.
                 const std::string cookie = result.header("Set-Cookie");
                 if (!cookie.empty())
                     m_cookie = cookie.substr(0, cookie.find(';'));
             }
             if (!result.ok() || result.status() != 200) {
                 done(std::nullopt, result.status());
                 return;
             }
             const Json envelope = parseObject(result.body());
             const std::string data = jsonString(envelope, "data");
             if (data.empty()) {
                 done(envelope, 200);
                 return;
             }
             const std::optional<std::string> plain = aesDecryptBase64(m_aes, data);
             done(plain ? std::optional<Json>(parseObject(*plain)) : std::nullopt, plain ? 200 : -1);
         });
}

void DecoSession::login()
{
    m_aes = {randomDigits16(), randomDigits16()};
    m_authHash = md5Hex("admin" + m_password);
    const std::string read = R"({"operation":"read"})";
    post("login", "keys", read, [this, read](Http::Result keys) {
        if (!keys.ok()) {
            finish(Outcome::Unreachable, keys.error().empty() ? "no answer" : keys.error());
            return;
        }
        const Json k = jsonValue(parseObject(keys.body()), "result");
        if (!keyPair(jsonValue(k, "password"), &m_passwordKeyN, &m_passwordKeyE)) {
            finish(Outcome::Protocol, "no password key in login?form=keys");
            return;
        }
        post("login", "auth", read, [this](Http::Result auth) {
            if (!auth.ok()) {
                finish(Outcome::Unreachable, auth.error().empty() ? "no answer" : auth.error());
                return;
            }
            const Json a = jsonValue(parseObject(auth.body()), "result");
            const Json seq = jsonValue(a, "seq");
            if (!keyPair(jsonValue(a, "key"), &m_signKeyN, &m_signKeyE) || !seq.is_number_integer()) {
                finish(Outcome::Protocol, "no signing key in login?form=auth");
                return;
            }
            m_seq = seq.get<long long>();
            const std::string password = rsaEncryptHex(m_passwordKeyN, m_passwordKeyE, m_password);
            const Json payload = {{"params", {{"password", password}}}, {"operation", "login"}};
            encrypted("login", "login", payload, true, [this](std::optional<Json> reply, int status) {
                if (!reply) {
                    finish(status == 0 ? Outcome::Unreachable : Outcome::Protocol,
                           "login answered " + std::to_string(status));
                    return;
                }
                const int code = jsonInt(*reply, "error_code", -1);
                const std::string stok = jsonString(jsonValue(*reply, "result"), "stok");
                if (code != 0 || stok.empty()) {
                    finish(Outcome::LoginRejected, "login refused (error " + std::to_string(code) + ")");
                    return;
                }
                m_stok = stok;
                next();
            });
        });
    });
}

void DecoSession::next()
{
    if (!m_running)
        return;
    if (m_steps.empty()) {
        logout();
        return;
    }
    Step step = std::move(m_steps.front());
    m_steps.erase(m_steps.begin());
    encrypted(step.path, step.form, step.payload, false,
              [this, done = std::move(step.done)](std::optional<Json> reply, int status) {
                  if (status == 403) {
                      // Somebody else logged in: this round is over.
                      m_stok.clear();
                      finish(Outcome::Evicted, "the session was taken over");
                      return;
                  }
                  if (status == 0) {
                      finish(Outcome::Unreachable, "no answer mid-round");
                      return;
                  }
                  std::vector<Step> more;
                  if (done)
                      done(reply ? *reply : Json{{"http", status}}, more);
                  if (!m_running)
                      return;
                  m_steps.insert(m_steps.begin(), std::make_move_iterator(more.begin()),
                                 std::make_move_iterator(more.end()));
                  next();
              });
}

void DecoSession::logout()
{
    encrypted("admin/system", "logout", Json{{"operation", "logout"}}, false, [this](std::optional<Json>, int) {
        m_stok.clear();
        finish(Outcome::Ok, {});
    });
}

void DecoSession::finish(Outcome outcome, std::string error)
{
    if (!m_running)
        return;
    // A round that broke off still logs out where it got in, so the app is
    // not locked out until the session times out on the router.
    if (outcome != Outcome::Ok && !m_stok.empty() && outcome != Outcome::Evicted) {
        m_result = {outcome, std::move(error)};
        m_steps.clear();
        encrypted("admin/system", "logout", Json{{"operation", "logout"}}, false,
                  [this](std::optional<Json>, int) {
                      m_stok.clear();
                      finish(Outcome::Ok, {});
                  });
        return;
    }
    m_running = false;
    m_steps.clear();
    Result result = m_result.outcome != Outcome::Ok ? m_result : Result{outcome, std::move(error)};
    m_result = {};
    auto done = std::move(m_done);
    m_done = nullptr;
    if (done)
        done(std::move(result));
}

} // namespace phicore::deco::ipc
