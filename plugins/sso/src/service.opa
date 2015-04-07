import stdlib.crypto
import stdlib.apis.oauth
import stdlib.web.client

package sso

// TODO - implements plaintext
// TODO - Prevents replay attacks (see http://tools.ietf.org/html/rfc5849#section-3.3)
// TODO - More docs
// TODO - Move to stdlib?

type SSOService.client_type = {sso} or {oauth}

type SSOService.userstate =
  {unauthenticated} or
  {OAuth.token access}

// type SSOService.access('key, 'service, 'value) = {
//   (string -> option(SSOService.service('service))) get_service,
//   (string -> option(string))                       get_secret,
//   ('key -> option('value))                         get_value,
//   (OAuth.credkey, OAuth.cred('value) -> void)      set_cred,
//   (OAuth.credkey -> void)                          del_cred,
//   (OAuth.credkey -> option(OAuth.cred('value)))    get_cred
// }

// type SSOService.config('key, 'service, 'value) = {
//   SSOService.access('key, 'service, 'value) access,
//   (-> option('key))                         get_key,
//   (-> option(bool))                         get_accept,
//   (string, SSOService.login_args('key, 'service, 'value) -> resource) login_page,
//   (option(outcome(Uri.uri,Uri.uri)) -> resource) auth_success,
//   (-> void) logout_user,
//   string name,
//   Uri.absolute sso_prefix
// }

// type SSOService.service('service) =
//   {'service trusted} or
//   {'service external}

// type SSOService.login_args('key, 'service, 'value) =
//   { bad_request } or
//   { SSOService.service('service) service,
//     {init} or {'key access_denied} or {'value authenticated} status}

private type SSOService.map_message('key, 'val) =
  {'key add, 'val val} or {'key remove} or
  {'key simple_get}  or {'key get} or
  {'key extract} or
  {list(SSOService.map('key, 'val)) poke}

abstract type SSOService.map('key, 'val) = Cell.cell(
  SSOService.map_message('key, 'val),
  option('val)
)

type OAuth.request = {
  string realm,
  string token,
  string consumer_key
}

type OAuth.Client.mode =
  { popup,
    (-> void) main_cb,
    (outcome(void, string) -> resource) popup_cb,
    list(string) popup_opts } or
  { same,
    (outcome(void, string) -> resource) cb }

type SSOService.Cookie.t = {string name, string value}


module SSOService {

  /** A module for thread safe map */
  private module SyncMap {

    function create(Map('key, 'order) Map) {
      Cell.make(
        (Map.empty, []),
        function ((map, friends), SSOService.map_message msg) {
          match (msg) {
            case ~{add, val}:
              { instruction: {set: (Map.add(add, val, map), friends)},
                return: {some: val} }
            case ~{remove}:
              { instruction: {set: (Map.remove(remove, map), friends)},
                return: none }
            case ~{simple_get}:
              { instruction: {unchanged},
                return: Map.get(simple_get, map) }
            case ~{get}:
              here = Map.get(get, map)
              result =
                match (here) {
                  case {some: _}: here
                  default:
                    match (List.filter_map(Cell.call(_, {simple_get: get}), friends)) {
                      case []: none
                      case [one]: some(one)
                      case [first|_]:
                        Log.warning("SyncMap", "more than one result for a get !")
                        some(first)
                    }
                }
              { instruction: {unchanged},
                return: result }
            case ~{extract}:
              (map, return) = Map.extract(extract, map)
              { instruction: {set: (map, friends)},
                ~return }
            case ~{poke}:
              { instruction: {set: (map, (poke ++ friends))},
                return: none }
          }
        })
    }

    function add(SSOService.map map, add, val) { Cell.call(map, ~{add, val}) }
    function remove(SSOService.map map, remove) { Cell.call(map, ~{remove}) }
    function get(SSOService.map map, get) { Cell.call(map, ~{get}) }
    function extract(SSOService.map map, extract) { Cell.call(map, ~{extract}) }
    private function poke(SSOService.map map, poke) { Cell.call(map, ~{poke}) }

    function cloud(string key, Map('key, 'order) Map) {
      shared = Session.cloud(key, [],
        function (set, SSOService.map c) {
          Scheduler.push(function () { List.iter(function (cell) { poke(cell, [c]) |> ignore }, set) }) // register new to the previous ones
          Scheduler.push(function () { poke(c, set) |> ignore }) // register old into new
          {set: [c | set]}
        })
      local = SyncMap.create(Map)
      Session.send(shared, local)
      local
    }

  } // END SYNCMAP


  /** Cookie manipulation. */
  module Cookie {

    /** Parser for cookies header. */
    private cookies =
      cookie = parser {
        case name=((!"=" .)*) "=" value=((!";" .)*):
          SSOService.Cookie.t { name: Text.to_string(name), value: Text.to_string(value) }
      }
      Rule.parse_list(cookie, parser { case ";" Rule.ws: void })

    /** Get the shared cookies from current request. */
    function get_shared(config) {
      name = shared_name(config)
      match (HttpRequest.get_headers()) {
        case {none}: {failure: {internal_server_error}}
        case {some: ~{header_get ...}}:
          match (header_get("Cookie")) {
            case {none}: {failure: {bad_request}}
            case {some: str}:
              match (Parser.try_parse(cookies, str)) {
                case {none}: {failure: {internal_server_error}}
                case {some: cookies}:
                  value = List.find_map(function (cookie) {
                    if (cookie.name == name) some(cookie.value)
                    else none
                  }, cookies)
                  match (value) {
                    case {none}: {failure: {wrong_address}}
                    case ~{some}: {success: {shared: some}}
                  }
              }
          }
      }
    }

    /** Name of shared cookie. */
    function shared_name(config) { "ssopa_{config.name}_scookie" }

  } // END COOKIE


  /** First draft of SSO Client corresponding to service defined above */
  module Client(
   ~{ consumer_key, consumer_secret,
      string auth_prefix, string sso_prefix, name },
   ~{ string uri, string host,
      (string->void) logout_cb,
      (outcome(void,string)->resource) callback,
      (string->void) error },
    SSOService.client_type ctype) {

    /** Configuration. */
    private callbackUrl = "{host}{uri}"
    private accessUrl = "{auth_prefix}/access"
    private shared_name = Cookie.shared_name(~{name})


    private function parameters(http_method) {
      match (ctype) {
        case {sso}:
         ~{ consumer_key, consumer_secret, http_method,
            auth_method: {HMAC_SHA1},
            request_token_uri: "{sso_prefix}/initiate",
            access_token_uri: "{sso_prefix}/credentials",
            authorize_uri: "{auth_prefix}/authorize",
            inlined_auth: false, custom_headers: [] }
        case {oauth}:
         ~{ consumer_key, consumer_secret, http_method,
            auth_method: {HMAC_SHA1},
            request_token_uri: "{sso_prefix}/request_token",
            access_token_uri: "{sso_prefix}/access_token",
            authorize_uri: "{auth_prefix}/authorize",
            inlined_auth: false, custom_headers: [] }
      }
    }


    private GET = OAuth(parameters({GET}))
    private POST = OAuth(parameters({POST}))

    /**
     * Bind local keys to OAuth accesss tokens.
     * localKey -> SSOService.userstate
     * TODO: move to Redis.
     */
    private accessTokens = Mutable.make(stringmap(SSOService.userstate) StringMap.empty)
    /**
     * Bind an oauth request token to the asscoiated local key.
     * Oauth.token -> (localKey, {token: OAuth.token}
     */
    private requestTokens =
      SSOService.map(string, (string, OAuth.token)) SyncMap.cloud("requestTokens", StringMap)
    /**
     * Bind request tokens to their authorization sessions.
     */
    private authorizationSessions =
      SSOService.map(string, (option(channel(void)), (outcome(void, string) -> resource))) SyncMap.cloud("authorizationSessions", StringMap)

    /** Get a request token for the local key. */
    private function getRequestToken(string localKey) {
      match (GET.get_request_token(callbackUrl)) {
        case {error: failure}:
          Log.notice("[SSOService.Client]", "getRequestToken failure: [{localKey}, {failure}]")
          ~{failure}
        case ~{success} as outcome:
          Log.notice("[SSOService.Client]", "getRequestToken success: [{localKey}, {success}]")
          SyncMap.add(requestTokens, success.token, (localKey, success)) |> ignore
          outcome
      }
    }

    /** Aliasing. */
    function init(string localKey) { getRequestToken(localKey) }

    /** Open the given URL in an new window, with the given options. */
    client function channel(void) winopen(string url, options, (-> void) callback) {
      Log.notice("[SSOService.Client]", "winopen [{url}]")
      args = [
        "toolbar=no", "location=no", "directories=no",
        "status=no", "menubar=no" | options
      ]
      win = @toplevel.Client.winopen(url, {_blank}, args, false)
      Session.make(void, function (_, _) {
        @toplevel.Client.winclose(some(win))
        callback()
        {stop}
      })
    }

    /**
     * Launch an OAuth connection, starting from the request token (getRequestToken), and continued
     * by the authorization (winopen) and access token (dispatcher).
     */
    function login(string localKey, OAuth.Client.mode mode) {
      Log.notice("[SSOService.Client]", "login: [{localKey}]")
      match (getRequestToken(localKey)) {
        case ~{failure}: error("SSOInit failure: {failure}")
        case ~{success}:
          url = "{GET.build_authorize_url(success.token)}&oauth_callback={Uri.encode_string(callbackUrl)}"
          match (mode) {
            case {popup, ~main_cb, ~popup_cb, ~popup_opts}:
              session = winopen(url, popup_opts, main_cb)
              SyncMap.add(authorizationSessions, success.token, (some(session), popup_cb)) |> ignore
            case {same, ~cb}:
              SyncMap.add(authorizationSessions, success.token, (none, cb)) |> ignore
              Log.notice("[SSOService.Client]", "login: goto authorization url {url}")
              @toplevel.Client.goto(GET.build_authorize_url(success.token))
          }
      }
    }

    /** Get the access token for a request token. */
    function getAccessToken(string localKey, ~{token, secret, verifier}) {
      match (POST.get_access_token(token, secret, verifier)) {
        case ~{error}: {failure: error}
        case ~{success}:
          accessTokens.set(StringMap.add(localKey, {access: success}, accessTokens.get()))
          {success}
      }
    }

    /** Set the access token for a local key. */
    function setAccessToken(string localKey, OAuth.token token) {
      accessTokens.set(StringMap.add(localKey, {access: token}, accessTokens.get()))
    }

    /** Remove the access token associated with a local key. */
    function removeAccessToken(string localKey) {
      accessTokens.set(StringMap.remove(localKey, accessTokens.get()))
    }

    /**
     * SSO reserved URLs, for the reception of the request token and token verifier.
     * Automatically send a request for an access token when a token verifier is received.
     */
    dispatcher = parser {
      case {Rule.of_string(uri)} "/"? [&|?]
        "oauth_verifier=" verifier=((!"&" .)*) "&"
        "oauth_token=" token=((!("&"|Rule.eos).)*) ("&"|Rule.eos):
        // Retrieve the request token from the server reference.
        match (SyncMap.get(requestTokens, Text.to_string(token))) {
          case {none}:
            Log.error("SSOClient", "Inconsistent state - {Text.to_string(token)}")
            Resource.raw_status({internal_server_error})
          case {some: (localKey, ~{token, secret, verifier:_})}:
            verifier = Text.to_string(verifier)
            accessToken = getAccessToken(localKey, ~{token, secret, verifier})
            // Retrieve the token authorization session, and
            // continue with the access token.
            match (SyncMap.get(authorizationSessions, token)) {
              case {some: (session, continue)}:
                Option.iter(send(_, void), session) // Close th authorization window.
                continue(accessToken) // Continue the login process.
              case {none}:
                callback(accessToken) // Continue with the predefined callback.
            }
        }
    }

    /**
     * Send a request to the identity provider.
     * The access token used to identify the request is either found in
     * the accessTokens server reference, or obtained from a new login.
     */
    function sendRequest(string localKey, string uri, params) {
      // Try sending the request using stored access tokens.
      function sendLocal() {
        match (StringMap.get(localKey, accessTokens.get())) {
          case {some: {access: ~{token, secret ...}}}:
            // Send a request identified by the given token pair.
            match (GET.get_protected_resource_2(uri, params, token, secret)) {
              case ~{failure}: {failure: {web_error: failure}}
              case ~{success}: ~{success}
            }
          default:
            Log.notice("[SSOService]", "sendRequest: no access token associated with [{localKey}]")
            {failure: {unauthenticated}}
        }
      }
      // Locate identification parameters according to the
      // authentication method.
      match (ctype) {
        case {sso}:
          Log.notice("[SSOService]", "sendRequest: using sso")
          match (Cookie.get_shared(~{name})) {
            case {failure: _}: sendLocal() // Fall back to local access token.
            case {success: {shared: cookie}}:
              GET = OAuth({parameters({GET}) with custom_headers: ["Cookie: {shared_name}={cookie}"]})
              match (GET.get_protected_resource_2(uri, params, "", "")) {
                case {success: {code: 200 ...}} as success: success
                default: sendLocal()
              }
          }
        case {oauth}:
          Log.notice("[SSOService]", "sendRequest: using oauth")
          sendLocal()
      }
    }

    /**
     * Logout the user identified by the local key:
     *  - remove the access token associated with the local key
     *  - call the logout callback provided at the service's creation.
     */
    function logout(string localKey, (->void) callback) {
      // Check whether the key is associated with an access token.
      match (StringMap.get(localKey, accessTokens.get())) {
        case {some: {access: ~{token, secret ...}}}:
          accessTokens.set(StringMap.remove(localKey, accessTokens.get())) // Remove the access token.
          uri = "{sso_prefix}/logout"
          match (GET.get_protected_resource_2(uri, [], token, secret)) {
            case ~{failure}: Log.error("[SSOService.Client]", "logout failure: {failure}")
            case ~{success}:
              match (success.code) {
                case 200:
                  match (option({string success} or {string error}) OpaSerialize.String.unserialize(success.content)) {
                    case {some: {success: _}}: logout_cb(localKey)
                    case {some: {error: msg}}: Log.error("[SSOService.Client]", "logout error: {msg}")
                    case {none}: Log.error("[SSOService.Client]", "logout: unable to unserialize {success.content}")
                  }
                case code: Log.error("[SSOService.Client]", "logout: failed with error code {code}")
              }
          }
        default: Log.error("[SSOService.Client]", "logout: No user state")
      }
      // Call the callback.
      Scheduler.sleep(1000, callback)
    }

  } // END CLIENT

} // END SSOSERVICE
