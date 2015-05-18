/*
 * PEPS is a modern collaboration server
 * Copyright (C) 2015 MLstate
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */



import stdlib.web.client
import stdlib.web.mail
import stdlib.io.file
import sso

type User.id = Token.t

type User.t = {
  User.id id,
  string username,
  string email,
  User.status status,
  stringmap(Date.date) rooms, // Recently joined rooms.
  bool email_validated
}

// database stringmap(User.t) /opachat/users
database /opachat/users[_]/email_validated = false
database /opachat/users[_]/status = {lambda}

type User.availability =
  {away} or
  {online} or
  {offline}

type User.encryption = {
  string salt,
  string nonce,
  string secretKey,
  string publicKey
}

type User.presence = {
  string username,
  User.status status,
  User.availability availability
}

type Presence.message =
  {(User.credentials, User.availability) status} or
  {string notification}

type picture = { int size, binary data, string mimetype }
type thumbnail = string // Thumbnail as data url.

/**
 * Store user statuses.
 * key -> User.presence
 */
private reference(stringmap(User.presence)) userStatuses =
  ServerReference.create(StringMap.empty)
/**
 * Broadcast status updates.
 */
Network.network(Presence.message) presence = Network.cloud("presence")


module User {

  /** {1} Utils. */

  @stringifier(User.availability) function string availabilityToString(User.availability availability) {
    match (availability) {
      case {online}: "online"
      case {away}: "away"
      case {offline}: "offline"
    }
  }

  function xhtml availabilityToHtml(User.id user, User.availability availability) {
    availabilityClass = "presence presence-{availability}"
    <span class="{user}-availability {availabilityClass}">•</span>
  }

  /** {1} Status updates. */

  function broadcastStatus(User.credentials credentials, User.availability availability) {
    Network.broadcast({status: (credentials, availability)}, presence)
  }

  exposed function broadcastNotification(string notification) {
    Network.broadcast(~{notification}, presence)
  }

  /** Update the status of a user. */
  function setStatus(User.credentials credentials, User.availability availability) {
    presence = {username: credentials.username, status: credentials.status, ~availability}
    ServerReference.update(userStatuses, StringMap.add(credentials.key, presence, _))
    broadcastStatus(credentials, availability)
  }

  /** Return the user statuses, sorted out by username. */
  exposed function getStatuses() {
    StringMap.To.assoc_list(ServerReference.get(userStatuses)) |>
    List.sort_by(_.f2.username, _)
  }

  /** Find the username of the user with the given id. */
  exposed function getUsername(User.id id) {
    match (StringMap.get(id, ServerReference.get(userStatuses))) {
      case {some: status}: status.username
      default: Option.map(_.username, User.get(id)) ? id
    }
  }

  /** Return the availability of a user (online / away / offline). */
  function getAvailability(User.id id) {
    match (StringMap.get(id, ServerReference.get(userStatuses))) {
      case {some: status}: status.availability
      default: {offline}
    }
  }

  /** Return the user key associated with a username. */
  exposed function getKey(string username) {
    StringMap.find(
      function (_, status) { status.username == username },
      ServerReference.get(userStatuses)) |>
    Option.map(_.key, _)
  }

  /** Add an observer to the presence network. */
  @expand protected function observePresence(observer) {
    Network.observe(observer, presence)
  }

  /** {1} Db operations. */

  /** Create a new user. */
  function User.t new(User.id id, string username, User.status status) {
    user = ~{id, username, status, email_validated: false, email: "", rooms: StringMap.empty}
    save(user)
    user
  }

  /** Save a user to the database. */
  function void save(User.t user) {
    /opachat/users[id == user.id] <- user
  }

  /** Return the user with the given key. */
  function option(User.t) get(User.id id) {
    ?/opachat/users[id == id]
  }

  /** Access the user's public key. */
  function option(uint8array) publicKey(string localKey, User.id id) {
    match (AuthorAccess.getEncryption(localKey, id)) {
      case {some: ~{publicKey ...}}: some(Uint8Array.decodeBase64(publicKey))
      default: none
    }
  }

  /** Alias for AuthorAccess.getEncryption. */
  function option(User.encryption) encryption(string localKey, User.id id) {
    AuthorAccess.getEncryption(localKey, id)
  }

  /** Add a user to the database, or update an existing one if needed. */
  function void register(User.id id, string username, User.status status) {
    match (get(id)) {
      case {some: user}: if (user.status != status) save({user with ~status})
      default: new(id, username, status) |> ignore
    }
  }

  /** Return the list of rooms the user recently contributed to. */
  function list(Room.id) getRooms(User.id id) {
    Option.map(Map.To.key_list, ?/opachat/users[id == id]/rooms) ? []
  }

  /** Mark a room. */
  function void addRoom(User.id id, Room.id room) {
    /opachat/users[id == id] <- {rooms[room]: Date.now(); ifexists}
  }

  /** Fetch a user's email. */
  function string getEmail(User.id key) {
    match (get(key)) {
      case {some: user}:
        if (user.email == "" && Email.is_valid_string(user.username)) {
          setEmail(key, user.username)
          user.username
        } else
          user.email
      default: ""
    }
  }

  /** Update a user's email. */
  function void setEmail(User.id id, string email) {
    /opachat/users[id == id] <- ~{email; ifexists}
  }

  /** Update the 'email_validated' field. */
  function void validateEmail(User.id id) {
    /opachat/users[id == id] <- {email_validated: true; ifexists}
  }

  /** Update the 'email_validated' field. */
  function void invalidateEmail(User.id id) {
    /opachat/users[id == id] <- {email_validated: false; ifexists}
  }

  /** Check whether the user email has been validated. */
  function bool isEmailValid(User.id id) {
    ?/opachat/users[id == id]/email_validated ? false
  }

  /** Return true iff the user status is {super_admin} or {admin}. */
  function isAdmin(User.id id) {
    match (get(id)) {
      case {some: user}: user.status == {super_admin} || user.status == {admin}
      default: false
    }
  }

  /** Return the username if defined, else the user key. */
  function toString(User.id id) {
    match (get(id)) {
      case {some: user}: user.username
      default: id
    }
  }

  /** Fetch at most {limit} users matching the query {term}, and sorted by username. */
  function fetch(int limit, string ref, string term) {
    if (term == "") DbSet.iterator(/opachat/users[username > ref; limit limit; order +username]) |> Iter.to_list
    else DbSet.iterator(/opachat/users[username > ref and username =~ term; limit limit; order +username]) |> Iter.to_list
  }

  /** Format a user into a list item. */
  protected function format(string localKey, User.t user, onclick) {
    availability = User.getAvailability(user.id) |> User.availabilityToHtml(user.id, _)
    thumbnail = getHtmlAvatar(localKey, user.id)
    <li class="list-group-item" id="{user.id}" onclick={onclick(user.id, _)}>
      <div class="chat-avatars single">{thumbnail}</div>
      <div class="chat-snippet">
        <div class="chat-authors">{user.username} {availability}</div>
      </div>
    </li>
  }

  /** Return either the avatar, if provided, or the default user icon. */
  both function xhtml getHtmlAvatar(string localKey, User.id user) {
    <img src="/avatar/{user}?localKey={localKey}" alt="" class="user-img" width="32"></img>
  }

} // END USER

int maxThumbnailSize = 64000

/** SSO parameters. */
defaultKey = "xxxxxxxxxxxxxxx"
no_ssl =
  get_cmdline("--no-ssl", "false", "<bool>", "Disable SSL and use HTTP")
sso_host =
  Utils.config("/etc/peps/apps/chat/provider") ?
  get_cmdline("--sso-host", "localhost:4443", "hostname", "Identisty provider")
host =
  get_cmdline("--host", "https://localhost:{serverConf.port}", "<uri>", "Local server uri")
consumer_key =
  Utils.config("/etc/peps/apps/chat/consumer_key") ?
  get_cmdline("--consumer-key", defaultKey, "", "SSO Consumer key")
consumer_secret =
  Utils.config("/etc/peps/apps/chat/consumer_secret") ?
  get_cmdline("--consumer-secret", defaultKey, "", "SSO Consumer secret")
app_name =
  get_cmdline("--app-name", "chat", "", "Name of the application")

/** Log SSO configuration. */
Log.notice("[SSO]", "Initial configuration:
Application name:   {app_name}
Indentity provider: {sso_host}
Application url:    {host}
Consumer key:       {consumer_key}
Consumer secret:    {consumer_secret}
SSL off:            {no_ssl}
")

/** Interfaces SSO User. */
module AuthorAccess {

  private admin = ~{host, sso_host, consumer_key, consumer_secret, app_name}
  private _AuthorAccess =
    SSOUser(
      Bool.of_string(no_ssl) ? false, sso_host, host,
      consumer_key, consumer_secret,  app_name,
      "/api/v0/oauth", {oauth}, User.register,
      function(url) { Client.goto(url) }, Client.alert
    )

  baseUrl = _AuthorAccess.baseUrl
  getCurrent = _AuthorAccess.getCurrent
  isLogged = _AuthorAccess.isLogged
  sendRequest = _AuthorAccess.SC.sendRequest
  isAdmin = User.isAdmin
  toString = User.toString

  /**
   * Check the validity of the access token by performing a request to the identity
   * provider, and update the status of the user if ok.
   *
   * @return true iff the access token was valid, and the login successful.
   */
  exposed function setAccessToken(string localKey, string token) {
    match (_AuthorAccess.setAccessToken(localKey, token)) {
      case {some: credentials}:
        User.setStatus(credentials, {online})
        true
      default: false
    }
  }

  /** Get a user avatar from the identity provider. */
  exposed function getAvatar(string localKey, User.id user) {
    url = "{_AuthorAccess.baseUrl}avatar/{user}"
    match (sendRequest(localKey, url, [])) {
      case {success: response}:
        match (response.code) {
          case 200:
            size = String.length(response.content)
            mimetype = response.header_get("content-type")
            match ((size, mimetype)) {
              case (0, _): @static_resource("resources/img/default-user.svg")
              case (_, {none}): @static_resource("resources/img/default-user.svg")
              case (_, {some: mimetype}):
                Resource.binary(Binary.of_binary(response.content), mimetype)
            }
          default: @static_resource("resources/img/default-user.svg")
        }
      case {failure: _}: @static_resource("resources/img/default-user.svg")
    }
  }

  /** Get the public key of a user. */
  exposed function option(User.encryption) getEncryption(string localKey, User.id user) {
    url = "{_AuthorAccess.baseUrl}encryption/{user}"
    match (sendRequest(localKey, url, [])) {
      case {success: response}:
        match (response.code) {
          case 200: OpaSerialize.String.unserialize(response.content)
          default: none
        }
      case {failure: _}: none
    }
  }

  exposed function slogin(key, redir) {
    // _AuthorAccess.agent_login(key, redir)
    _AuthorAccess.agent_login_cb(key, redir,
       function (res) {
          match (res) {
            case {failure: _}: void
            case {success: credentials}:
              User.setStatus(credentials, {online})
          }
       })
  }

  exposed function slogout(key, redir) {
    _AuthorAccess.logout_cb(key, redir,
      function {
        case {some: cred}: User.setStatus(cred, {away})
        case {none}: void
      })
  }

  client function login(key, redir) { slogin(key, redir) }
  client function logout(key, redir) { slogout(key, redir) }

  special_uris2 = _AuthorAccess.special_uris2
  special_uris = _AuthorAccess.special_uris

} // END AUTHORACCESS


