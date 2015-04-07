/**
 * Copyright © 2012-2015 MLstate
 * All rights reserved.
 */

package sso

function get_cmdline(cmd, init, doc, descr) {
  option = ~{
    init,
    parsers: [
      { names: [cmd],
        param_doc: doc,
        description: descr,
        on_encounter: function (s) {{params: s}},
        on_param: function (_) {
          parser {
            x=(.*): {no_params: Text.to_string(x)}
          }
        }
      } ],
    anonymous: [],
    title: "SSO options"
  }
  CommandLine.filter(option)
}

anonymous_name = "Anonymous"

/** Author Access Control */

type User.status = {lambda} or {admin} or {super_admin}
type User.credentials = {
  string key,
  string username,
  User.status status
}


/**
 * Associate local keys to user credentials.
 * Updated when new credentials are fetched from the identity provider.
 */
private context = Mutable.make(stringmap(User.credentials) StringMap.empty)

/** Build a SSO client. */
function SSOClient(no_ssl, sso_host, host, consumer_key, consumer_secret, name, prefix, ctype, error) {

  /** Protocol used in provider requests. */
  protocol = if (no_ssl) "http" else "https"

  SSOService.Client(~{
    name, consumer_key, consumer_secret,
    auth_prefix: "{protocol}://{sso_host}{prefix}",
    sso_prefix: "{protocol}://{sso_host}{prefix}"
  }, ~{
    uri: "/sso/oauth",
    host, error,
    logout_cb: function (key) {
      context.set(StringMap.remove(key, context.get()))
    },
    callback: function {
      case {success: _}:
        Log.error("SSOClient", "Success")
        Resource.page("SSO Success", <h1>SSO Success</h1>)
      case ~{failure}:
        Log.error("SSOClient", "Failure {failure}")
        Resource.page("SSO Error",
          <h1>Sorry but an error occured during the authentification process.</h1>)
    }
  }, ctype)

} // END SSOCLIENT

/** Build a SSO user. */
module SSOUser(
  no_ssl, sso_host, host, consumer_key, consumer_secret,
  name, prefix, ctype, register_user, client_goto, error) {

  /** Attached client. */
  SC = SSOClient(no_ssl, sso_host, host, consumer_key, consumer_secret, name, prefix, ctype, error)
  protocol = if (no_ssl) "http" else "https"
  baseUrl = "{protocol}://{sso_host}/"

  /** Reserved URLs. */
  special_uris = parser { case "": <></> }
  special_uris2 = SC.dispatcher

  #<Ifstatic:SSO_DEV>
  @private demonum = Mutable.make(1)
  @private demolog = UserContext.make(option(User.credentials) none)
  #<End>

  /**
   * Associate the local key with the provided access token.
   * Used in particular to set the access token when the connection
   * is made inside the provider's site.
   * The token secret and verifier will default to the empty string.
   *
   * The provided access token is verified by performing a request to
   * the identity provider asking for the user credentials.
   */
  function setAccessToken(string localKey, string token) {
    SC.setAccessToken(localKey, ~{token, secret: "", verifier: ""})
    match (getCredentials(localKey)) {
      case {some: credentials}: some(credentials)
      default:
        SC.removeAccessToken(localKey)
        none
    }
  }

  /**
   * Send a request to the service provider.
   * @param unserialize request parser.
   */
  function sendRequest(string localKey, string path, (string -> option(outcome('a, string))) unserialize, params) {
    match (SC.sendRequest(localKey, "{baseUrl}{path}", params)) {
      case ~{failure}:
        Log.error("[SSOUser]", "sendRequest: connection failure: {failure} (at URL {baseUrl}/{path})")
        none
      case ~{success}:
        match (success.code) {
          case 200:
            match (unserialize(success.content)) {
              case {none}:
                Log.error("[SSOUser]", "sendRequest: unserialization failure")
                none
              case {some: ~{failure}}:
                Log.error("[SSOUser]", "sendRequest: remote failure: {failure}")
                none
              case {some: {success: value}}:
                {some: value}
            }
          default:
            Log.error("[SSOUser]", "get_generic: request failure: {success}")
            none
        }
    }
  }

  /**
   * Send a request to the identity provider to obtain the active
   * user credentials.
   */
  private function getCredentials(string localKey) {
    unserialize = (string -> option(outcome(User.credentials, string))) OpaSerialize.String.unserialize
    match (sendRequest(localKey, "api/v0/oauth/gnameadmin", unserialize, [])) {
      case {some: ~{key, username, status}}:
        context.set(StringMap.add(localKey, ~{key, username, status}, context.get()))
        _ = register_user(key, username, status)
        some(~{key, username, status})
      case {none}: none
    }
  }

  /**
   * Return the credentials associated with the local key.
   * If no valid credentials are found, send a login request to
   * the identity provider.
   */
  function getCurrent(string localKey) {
    Log.notice("[SSOUser]", "get_current [{localKey}]")
    // Get credentials from the iddentity provider.
    function getCredentials() {
      Option.map(_.key, getCredentials(localKey)) ? anonymous_name
    }
    // Check the context first, and send a request to the provider
    // if the local key is not registered.
    match (StringMap.get(localKey, context.get())) {
      case {some: credentials}:
        if (credentials.key == anonymous_name) getCredentials()
        else credentials.key
      default: getCredentials()
    }
  }

  /**
   * Store the login credentials in the context before calling
   * the provided callback.
   */
  private function void finishLogin(string localKey, callback) {
    Log.notice("[SSOUser]", "finishLogin [{localKey}]")
    match (getCredentials(localKey)) {
      case {none}: callback({failure})
      case {some: ~{key, username, status} as credentials}:
        if (key == "") callback({failure})
        else {
          callback({success: credentials})
          context.set(StringMap.add(localKey, credentials, context.get()))
          _ = register_user(key, username, status)
          void
        }
    }
  }

  /** Login with a callback. */
  function login_cb(string localKey, string redir, callback) {
    Log.notice("[SSOUser]", "login_cb [{localKey}, {redir}]")
    // Configure the login.
    function main_cb() {
      finishLogin(localKey, callback)
      Client.goto(redir)
    }
    function popup_cb(res) {
      match (res) {
        case ~{failure}:
          Log.error("SSOInit", "{failure}")
          Resource.raw_status({bad_request})
        case {success: _}:
          Resource.page(
            "Connection successful",
            <h1>Connection successful, this window should close automatically</h1>
          )
      }
    }
    popup_opts = ["width=1000", "height=500"]
    config = ~{popup: void, main_cb, popup_cb, popup_opts}
    // Call the service login.
    SC.login(localKey, config)
  }

  /** Login with no callback. */
  function login(string localKey, string redir) {
    login_cb(localKey, redir, ignore)
  }

  /** Yet another login method. */
  function login_no_popup_cb(string localKey, string redir, callback) {
    function cb(res) {
      finishLogin(localKey, callback)
      match (res) {
        case ~{failure}:
          Log.error("SSOInit", "{failure}")
          Resource.raw_status({bad_request})
        case {success: _}:
          Resource.page("", <div onready={function (_) { Client.goto(redir) }}></div>)
      }
    }
    // Call the service login.
    SC.login(localKey, {same, ~cb})
  }

  /** Login with no callback. */
  function login_no_popup(string localKey, string redir) {
    login_no_popup_cb(localKey, redir, ignore)
  }

  /** Login with agent specific options. */
  function agent_login_cb(string localKey, string redir, callback) {
    match (HttpRequest.get_user_agent()) {
      case {some: {environment:_, renderer: {Presto: _}}}:
        login_no_popup_cb(localKey, redir, callback)
      default: login_cb(localKey, redir, callback)
    }
  }

  /** Login with no callback. */
  function agent_login(string localKey, string redir) {
    login_no_popup_cb(localKey, redir, ignore)
  }


  function logout_cb(string localKey, string redir, ('a -> void) callback) {
    credentials = StringMap.get(localKey, context.get())
    function void finish() {
      callback(credentials)
      client_goto(redir)
    }
    context.set(StringMap.remove(localKey, context.get()))
    SC.logout(localKey, finish)
  }

  function logout(localKey, redir) {
    logout_cb(localKey, redir, ignore)
  }

  function isLogged(string key) { key != anonymous_name }
  function string toString(string key) { key }

} // END SSOUSER
