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



import stdlib.system
import stdlib.themes.bootstrap

/** {1} Constants. */

GITHUB_USER = "MLstate"
GITHUB_REPO = "OpaChat"
PEPS_DIR = "/etc/peps"
NB_LAST_MSGS = 10

/** {1} Types. */

type client_channel = channel(void)

type settings = {
  string host,
  string sso_host,
  string consumer_key,
  string consumer_secret,
  string app_name
}

/** Database declaration. */
database opachat {
  Message.t /messages[{id}]
  Room.t /rooms[{id}]
  User.t /users[{id}]
}

database /opachat/rooms[_]/secure = true

/** {1} Utils. */

/** Check the user agent. */
protected function bool isOpera() {
  match (HttpRequest.get_user_agent()) {
    case {some: {renderer: {Presto: _} ...}}: true
    default: false
  }
}

/** Replaces an event handler. */
client function goto(string url, _evt) {
  Client.goto(url)
}

/** Retrieve the client identifier (a randomly generated key). */
client function getLocalKey() {
  match (Client.SessionStorage.get("localKey")) {
    case {some: key}: key
    case {none}:
      key = Random.string(10)
      Client.SessionStorage.set("localKey", key)
      key
  }
}

/** Send a notification to the identity provider via the rest API. */
protected function notifyUser(string localKey, User.id user, Room.id _room) {
  url = "{AuthorAccess.baseUrl}api/v0/notify/{user}"
  params = [("mode", app_name)]
  AuthorAccess.sendRequest(localKey, url, params) |> ignore
}

/** {1} Statistics. */

private server launchDate = Date.now()

/** Compute uptime and memory usage (MB). */
exposed function computeStatistics() {
  uptime = Date.between(launchDate, Date.now())
  memory = System.get_memory_usage()/(1024*1024)
  ~{uptime, memory}
}

/** Display statistics. */
client function updateStatistics(stats) {
  #uptime = <>Uptime: {Duration.to_formatted_string(Duration.long_time_printer, stats.uptime)}</>
  #memory = <>Memory: {stats.memory} MB</>
}


/** {1} Secret key. */

client function getSecretKey(string localKey, User.id self, callback) {
  Log.notice("[Chat]", "getSecretKey")
  match (Client.SessionStorage.get("userSecretKey")) {
    case {some: secretKey}:
      Log.notice("[Chat]", "getSecretKey: using stored key")
      some(Uint8Array.decodeBase64(secretKey)) |> callback
    default:
      match (User.encryption(localKey, self)) {
        case {some: ~{nonce, salt, secretKey ...}}:
          Log.notice("[Chat]", "getSecretKey: loading password input")
          #main = passwordInput(
            "Authentication",
            "password",
            function (_evt) {
              // Check the entered password.
              password = Dom.get_value(#password) |> Uint8Array.decodeUTF8
              salt = Uint8Array.decodeBase64(salt)
              nonce = Uint8Array.decodeBase64(nonce)
              masterKey = TweetNacl.pbkdf2(password, salt, 5000, TweetNacl.SecretBox.keyLength)
              secretKey = Uint8Array.decodeBase64(secretKey)
              match (TweetNacl.SecretBox.open(secretKey, nonce, masterKey)) {
                case {some: secretKey}:
                  Client.SessionStorage.set("userSecretKey", Uint8Array.encodeBase64(secretKey))
                  callback(some(secretKey))
                default:
                  Log.warning("[Chat]", "unable to uncrypt {self}'s secretKey")
                  #ask_pass_error = <div class="alert alert-danger">Bad password</div>
              }
            }
          )
        default:
          Log.warning("[Chat]", "unable to obtain secret key for user {self}")
          callback(none)
      }
  }
}


/** {1} Users. */

/**
 * Bind a user presence observer, which updates the availability of the users in a
 * list. The availability must have the id '{userId}-availability' in order to be
 * correctly updated. The observer is removed when the URL is changed.
 */
function bindUserObserver() {
  // Bind an observer to the user presence network.
  function observer(msg) {
    match (msg) {
      case {status: (credentials, availability)}:
        availabilityClass = "availability-{availability}"
        Dom.select_class("{credentials.key}-availability") |>
        Dom.iter(Dom.set_class(_, "{credentials.key}-availability {availabilityClass}"), _)
      case ~{notification}:
        Utils.notify(<>{notification}</>, "info")
    }
  }
  obs = User.observePresence(observer)
  Dom.bind_beforeunload_confirmation(function(_) { Network.unobserve(obs); none }) // TODO: opera again
}


/** {1} Conversations list. */

protected function conversations(string localKey, User.id user) {
  Log.notice("[Chat]", "building conversations list")
  rooms = Room.list(user)
  rooms = List.fold(function (room, list) { list <+> Room.format(localKey, room, user, openRoom) }, rooms, <></>)
  rooms = if (rooms == <></>) <p class="list-empty">No conversations</p> else rooms
  #main =
    <div>
      <div class="pane-heading">
        <a type="button" class="btn-icon pull-right" onclick={openRestrictedRoomCreator} title="Start conversation">
          <img src="/resources/img/compose-o.svg"/>
        </a>
        <div class="col-lg-left">
          <input id="roomName" placeholder="Join room" onnewline={joinRoom} class="form-control"/>
        </div>
      </div>
      <ul id="conversations" class="list-group conversations-list">{rooms}</ul>
    </div>
  bindUserObserver()
}

exposed function conversationsPage() {
  page = buildLoggedPage("/", conversations)
  Resource.full_page_with_doctype("Conversations", {html5}, page, headers, {success}, [])
}

client function openConversations(_evt) {
  Client.goto("/")
}

client function joinRoom(_evt) {
  name = Dom.get_value(#roomName) |> String.trim
  if (name != "") Client.goto("/access/{name}")
}

/** {1} Room editor. */

/** Select / unselect a user item. */
client function toggleUser(string id, _evt) {
  Log.notice("[Chat]", "toggleUser {id}")
  Dom.toggle_class(#{id}, "user-selected")
}

exposed function searchUsers(string localKey, User.id self, _evt) {
  // Identify and isolate current selection.
  selected = Dom.select_class("user-selected")
  selectedIds = Dom.fold(function (item, list) {
    [Dom.get_id(item)|list]
  }, [], selected)
  Dom.put_inside(#users_selected, selected) |> ignore
  // Fetch new users.
  term = Dom.get_value(#userSearch)
  list = List.fold(function (user, list) {
    if (user.id == self || List.mem(user.id, selectedIds)) list
    else list <+> User.format(localKey, user, toggleUser)
  }, User.fetch(50, "", term), <></>)
  #users = list
}

/**
 * Build and insert the restricted room creator.
 * This room creator displays a user selector, and the room is created
 * using  the select users.
 */
protected function restrictedRoomCreator(string localKey, User.id self) {
  list = List.fold(function (user, list) {
    if (user.id == self) list
    else list <+> User.format(localKey, user, toggleUser)
  }, User.fetch(50, "", ""), <></>)
  list = if (list == <></>) <p class="list-empty">No users</p> else list

  #main =
    <div class="pane-heading">
      <a type="button" class="btn-icon pull-right" onclick={createRestrictedRoom(self, _)} title="Start conversation">
        <img src="/resources/img/speech-bubble.svg"/>
      </a>
      <a type="button" class="btn-icon pull-left" onclick={openConversations} title="Back">
        <img src="/resources/img/arrow-back.svg"/>
      </a>
      <div class="col-lg-mid">
        <input id="userSearch" class="form-control" placeholder="Search" onkeyup={searchUsers(localKey, self, _)}/>
      </div>
    </div>
    <div class="conversations-list">
      <div class="alert alert-info">
        To create a new chat, select one or more users and click on the Chat icon.
      </div>
      <ul id="users_selected" class="list-group"/>
      <ul id="users" class="list-group">
        {list}
      </ul>
    </div>

  bindUserObserver()
}

/**
 * Build and insert the named room creator.
 * This creator displays a name and a password input.
 */
protected function namedRoomCreator(string _localKey, User.id self) {
  #main =
    <div class="pane-heading">
      <a type="button" class="btn-icon pull-right" onclick={createNamedRoom(self, _)} title="New conversation">
        <img src="/resources/img/speech-bubble.svg"/>
      </a>
      <a type="button" class="btn-icon pull-left" onclick={openRestrictedRoomCreator} title="Back">
        <img src="/resources/img/arrow-back.svg"/>
      </a>
      <div class="col-lg-mid">
        <h3 class="pane-title">Room creation</h3>
      </div>
    </div>
    <div class="conversations-list">
      <div id=#notification/>
      <div class="alert alert-info">
        You are about to create a new room.
        To invite other users to join you just share room name and (optional) password with them.
      </div>
      <div class="form-group">
        <input id="roomName" class="form-control" placeholder="Room name" onnewline={createNamedRoom(self, _)}/>
      </div>
      <div class="form-group">
        <input id="roomPassword" class="form-control" type="password" placeholder="Password" onnewline={createNamedRoom(self, _)}/>
      </div>
    </div>
}

/** Return the room editor as a resource. */
exposed function restrictedRoomCreatorPage() {
  page = buildLoggedPage("/create/restricted", restrictedRoomCreator)
  Resource.full_page_with_doctype("Create Room", {html5}, page, headers, {success}, [])
}

/** Return the room editor as a resource. */
exposed function namedRoomCreatorPage() {
  page = buildLoggedPage("/create/named", namedRoomCreator)
  Resource.full_page_with_doctype("Create Room", {html5}, page, headers, {success}, [])
}

client function openRestrictedRoomCreator(_evt) {
  Client.goto("/create/restricted")
}

client function openNamedRoomCreator(_evt) {
  Client.goto("/create/named")
}

/**
 * Extract the information contained in the form, and return
 * them to the server.
 */
client function createRestrictedRoom(self, evt) {
  localKey = getLocalKey()
  members = Dom.select_class("user-selected")
  members = Dom.fold(function (item, members) {
    [Dom.get_id(item)|members]
  }, [], members)
  kind = {restricted: [self|members]}
  if (members == []) openNamedRoomCreator(evt)
  else saveRoom(localKey, kind, Room.create(localKey, self, kind, self, ""))
}

/**
 * Extract the information contained in the form, and return
 * them to the server.
 */
client function createNamedRoom(self, _evt) {
  localKey = getLocalKey()
  name = Dom.get_value(#roomName) |> String.trim
  password = Dom.get_value(#roomPassword)
  kind = {named: name}
  if (name == "") Utils.notify(<>Please enter a room name</>, "danger")
  else saveRoom(localKey, kind, Room.create(localKey, self, kind, self, password))
}

/** Create a new room. */
exposed function saveRoom(string localKey, Room.kind kind, Room.t room) {
  user = AuthorAccess.getCurrent(localKey)
  if (AuthorAccess.isLogged(user) && room.owner == user)
    match (Room.find(kind)) {
      case {some: room}: Client.goto("/access/{room.id}")
      case {none}:
        Room.save(room)
        Client.goto("/access/{room.id}")
    }
  else AuthorAccess.login(localKey, "/create/restricted")
}


/** {1} Room chat access. */

client function checkPassword(string localKey, self, string username, Room.t room, _evt) {
  password = Dom.get_value(#password) |> Uint8Array.decodeUTF8
  salt = Uint8Array.decodeBase64(room.salt)
  hash = TweetNacl.hash(Uint8Array.concat(password, salt)) |> Uint8Array.encodeBase64
  checkHashedPassword(localKey, self, username, hash, room)
}

/** Check the input password. */
exposed function checkHashedPassword(string localKey, self, string username, string hash, Room.t room) {
  if (Room.checkPassword(room, hash)) {
    channel = Session.make_callback(ignore)
    saveRoomSecretKey(localKey, self, room, chatAccess(localKey, username, room, channel))
  } else {
    Log.warning("[Chat]", "room login error")
    ip ip = HttpRequest.get_ip() ? 0.0.0.0
    Metric.logBadlogin(room.id, "Bad room {room.id}:{Room.name(room, "")} password", ip)
    #ask_pass_error = <div class="alert alert-danger">Bad password</div>
  }
}

/**
 * Save the room secret key, derived from the room password using pbkdf2 algorithm.
 * NB: client function, since all encryption operations must be done client side.
 */
client function saveRoomSecretKey(localKey, self, Room.t room, xhtml page) {
  Log.notice("[Chat]", "saveRoomSecretKey")
  // If room is password protected.
  if (Room.passwordProtected(room)) {
    password = Dom.get_value(#password)
    salt = Uint8Array.decodeBase64(room.salt)
    password = Uint8Array.decodeUTF8(password)
    masterKey = TweetNacl.pbkdf2(password, salt, 5000, TweetNacl.SecretBox.keyLength)
    secretKey = Uint8Array.decodeBase64(room.secretKey.message)
    nonce = Uint8Array.decodeBase64(room.secretKey.nonce)
    match (TweetNacl.SecretBox.open(secretKey, nonce, masterKey)) {
      case {some: secretKey}: Client.SessionStorage.set("roomSecretKey", Uint8Array.encodeBase64(secretKey)) // Store the room master key.
      default: void
    }
    Log.notice("[Chat]", "stored secret key for room {room.id}")
    #main = page
  // If room is restricted: extract the secretKey for current user.
  } else
    getSecretKey(localKey, self, function {
      case {some: mySecretKey}:
        match (StringMap.get(self, room.secretKeys)) {
          case {some: ~{message: roomSecretKey, nonce}}:
            nonce = Uint8Array.decodeBase64(nonce)
            roomSecretKey = Uint8Array.decodeBase64(roomSecretKey)
            roomPublicKey = Uint8Array.decodeBase64(room.publicKey)
            match (TweetNacl.Box.open(roomSecretKey, nonce, roomPublicKey, mySecretKey)) {
              case {some: roomSecretKey}:
                Client.SessionStorage.set("roomSecretKey", Uint8Array.encodeBase64(roomSecretKey))
                #main = page
              default:
                Log.warning("[Chat]", "saveRoomSecretKey: invalid user secret key")
            }
          default: Log.warning("[Chat]", "saveRoomSecretKey: no room secret key for user {self}")
        }
      default: void
    })
}

/** Password input form. */
both function xhtml passwordInput(string title, string placeholder, check) {
  <div id=#content>
    <div class="pane-heading">
      <a type="button" class="btn-icon pull-left" onclick={openConversations} title="Back">
        <img src="/resources/img/arrow-back.svg"/>
      </a>
      <div class="col-lg-right">
        <h3 class="pane-title">{title}</h3>
      </div>
    </div>
    <div class="conversations-list">
      <div id=#ask_pass_error></div>
      <div id=#ask_password class="form-group">
        <input id=#password type="password" autofocus="autofocus"
            placeholder="{placeholder}"
            class="form-control"
            onready={function(_) {Dom.give_focus(#password)}}
            onnewline={check}/>
      </div>
    </div>
  </div>
}

protected function xhtml roomPasswordInput(string localKey, string self, string username, room) {
  passwordInput(
    @toplevel.Room.name(room, ""),
    "Password for {@toplevel.Room.name(room, "")}",
    checkPassword(localKey, self, username, room, _)
  )
}

/** Join the input room. */
client function openRoomAccess(_evt) {
  room = Dom.get_value(#name)
  Client.goto("/access/{room}")
}

/** Join the input room. */
client function openRoom(Room.id id, _evt) {
  Client.goto("/access/{id}")
}

/**
 * Access page: display a password input if needed, and redirect
 * to the room chat after checking the login.
 */
protected function roomAccess(string localKey, User.id self, Room.id room) {
  Log.notice("[Chat]", "roomAccess [{room}]")
  username = AuthorAccess.toString(self)
  match (Room.get(room)) {
    case {some: room}:
      match (Room.checkAccess(room, self)) {
        case {restricted}:
          channel = Session.make_callback(ignore)
          saveRoomSecretKey(localKey, self, room, chatAccess(localKey, username, room, channel))
        case {open}:
          channel = Session.make_callback(ignore)
          #main = chatAccess(localKey, username, room, channel)
        case {pass}:
          #main = roomPasswordInput(localKey, self, username, room)
        case ~{error}:
          #main = error
      }
    default:
      #main = <div class="alert alert-danger">Room {room} does not exist</div>
  }
}

/** Access form made into a resource. */
exposed function roomAccessPage(string room) {
  page = buildLoggedPage("/access/{room}", roomAccess(_, _, room))
  Resource.full_page_with_doctype("Access Room", {html5}, page, headers, {success}, [])
}

/** {1} Chat message handlers. **/

/** Convert a source to html. */
client function sourceToHtml(User.id source) {
  localKey = getLocalKey()
  <div class="user">{User.getHtmlAvatar(localKey, source)}</div>
}

client function sourceName(User.id self, User.id source) {
  if (self == source) "" else User.getUsername(source)
}

/** Format a message into an xhtml element. */
client function formatMessage(User.id self, item) {
  date = Date.to_formatted_string(Date.default_printer, item.date)
  time = Date.to_string_time_only(item.date)
  class = if (item.source == self) "line-right" else "line-left"
  <div class="list-group-item">
    <div class="line {class}">
      {sourceToHtml(item.source)}
      {Message.render(item)}
      <small class="user-name">{sourceName(self, item.source)} {time}</small>
    </div>
  </div>
}

client function prependMessages(User.id self, items) {
  // Get the initial length of the list.
  length = Dom.get_scrollable_size(#conversation).y_px
  scroll = Dom.get_scroll_top(#conversation)
  // Prepend elements.
  List.iter(function (item) {
    #conversation += formatMessage(self, item)
  }, items)
  // Get new length and adjust scroll.
  diff = Dom.get_scrollable_size(#conversation).y_px - length
  Dom.set_scroll_top(#conversation, scroll+diff)
}

/** Insert unidentified items in the chat thread. */
client function insertMessages(User.id self, stats, items) {
  Log.notice("[Chat]", "inserting {List.length(items)} messages")
  updateStatistics(stats)
  List.iter(function (item) {
    #conversation =+ formatMessage(self, item)
  }, items)
  // TODO: scroll on #conversation div.
  Dom.scroll_to_bottom(#conversation)
}

/** Insert a system message. */
client @async function insertSystemMessage(stats, string text, Date.date sysdate) {
  updateStatistics(stats)
  date = Date.to_formatted_string(Date.default_printer, sysdate)
  time = Date.to_string_time_only(sysdate)
  #conversation =+
    <div class="list-group-item">
      <small class="line-system">{text} {time}</small>
    </div>
}

/** Handle room messages. */
protected function handleChatMessages(string localKey, Room.user self, Room.message event) {
  match (event) {
    // Messages and medium.
    case ~{message}:
      if (message.source != self.id)
        notifyUser(localKey, self.id, message.room)
      insertMessages(self.id, computeStatistics(), [message])
    // Connection and disconnection messages.
    case {connection: (user, room, _)} :
      insertSystemMessage(computeStatistics(), Message.connection(room, user.username), Date.now())
    case {disconnection: (user, room)} :
      insertSystemMessage(computeStatistics(), Message.disconnection(room, user.username), Date.now())
    // Statistics.
    case {stats} : updateStatistics(computeStatistics())
    default : void
  }
}

/**
 * {1} Manage room observers.
 *
 * We have horrendous problems with opera, it doesn't implement beforeunload...
 */

server roomObservers = Mutable.make(stringmap((Room.user, Room.t, Network.observer)) StringMap.empty)

/** Handle the active user disconnection. */
client function unobserveRoom(bool opera, Room.user self, Room.t room, Network.observer observer) {
  Log.notice("[Chat]", "unobserveRoom: {room.id}")
  localKey = getLocalKey()
  Room.disconnect(self, room.id) // Broadcast disconnection message.
  Network.unobserve(observer) // Unbind present observer.
  if (opera) {
    roomObservers.set(StringMap.remove(localKey, roomObservers.get())) // Remove room observer.
    Client.SessionStorage.remove("{localKey}CurrentRoomPointer")
  }
}

/** Handle the active user connection. */
client function observeRoom(bool opera, Room.user self, Room.t room, channel, Network.observer observer) {
  Log.notice("[Chat]", "observeRoom: {room.id}")
  localKey = getLocalKey()
  // Unbind current observer.
  if (opera) {
    match (Client.SessionStorage.get("{localKey}CurrentRoomPointer")) {
      case {some: currentRoomId}:
        if (currentRoomId == room.id)
          match (StringMap.get(localKey, roomObservers.get())) {
            case {some: (user, room, obs)}: unobserveRoom(opera, user, room, obs)
            case {none}: void
          }
      default: void
    }
    Client.SessionStorage.set("{localKey}CurrentRoomPointer", room.id) // Update room pointer.
    roomObservers.set(StringMap.add(localKey, (self, room, observer), roomObservers.get())) // Update room observers.
  }
  Room.connect(self, room.id, channel) // Broadcast connection message.
}

/** Initialize the chat. */
exposed function initChat(string localKey, Room.user self, Room.t room, channel, _evt) {
  opera = isOpera()
  // Observe client.
  observer = Room.observe(handleChatMessages(localKey, self, _), room.id)
  observeRoom(opera, self, room, channel, observer)
  // Observe disconnection.
  Dom.bind_beforeunload_confirmation(function(_) {
    unobserveRoom(opera, self, room, observer)
    none
  })
  // Initialize OpaShare.
  Upload.init(sendMedia(self, room.id))
}

protected function xhtml chatAccess(string localKey, string username, Room.t room, channel) {
  self = AuthorAccess.getCurrent(localKey)
  title = Room.name(room, self)
  user = ~{id: self, username}

  function broadcast(string text, Message.encryption encryption) {
    message = Message.new(self, room.id, ~{text}, encryption)
    Room.broadcast(~{message}, room.id)
    Metric.logMessage(self, room.id, text)
  }
  icon = if (room.secure) "locked-o.svg" else "unlocked-o.svg"
  <>
  <div id=#content onready={initChat(localKey, user, room, channel, _)} class="content dropzone">
    <div id=#stats><div id=#users/><div id=#uptime/><div id=#memory/></div>
    <div class="pane-heading">
      <a class="btn-icon pull-left" onclick={openConversations} title="Back">
        <img src="/resources/img/arrow-back.svg"/>
      </a>
      <div class="col-lg-right">
        <h3 class="pane-title">{title}<img class="chat-encryption-icon" src="/resources/img/{icon}"/></h3>
      </div>
    </div>
    <ul id=#conversation class="conversation list-group" onready={MessageScroll.init(self, room.id, _)}></ul>
    <div id=#notification class="chat-notification"></div>
  </div>
  <div id=#chatbar class="chatbar">
      {Upload.html()}
      <div class="col-lg-right">
        <input id=#entry autofocus="autofocus"
          class="form-control"
          onready={function(_) {Dom.give_focus(#entry)}}
          onnewline={sendMessage(room.secure, broadcast, _)}
          x-webkit-speech="x-webkit-speech"/>
      </div>
  </div>
  </>
}

/**
 * Broadcast a message and clear the input.
 * @param encrypt enforce message encryption.
 */
client @async function sendMessage(bool encrypt, broadcast, _) {
  if (encrypt)
    match (Client.SessionStorage.get("roomSecretKey")) {
      case {some: secretKey}:
        secretKey = Uint8Array.decodeBase64(secretKey)
        publicKey = TweetNacl.Box.keyPairFromSecretKey(secretKey).publicKey
        nonce = TweetNacl.randomBytes(TweetNacl.Box.nonceLength)
        data = Uint8Array.decodeUTF8(Dom.get_value(#entry))
        message = TweetNacl.Box.box(data, nonce, publicKey, secretKey) |> Uint8Array.encodeBase64
        broadcast(message, {nonce: Uint8Array.encodeBase64(nonce), key: Uint8Array.encodeBase64(publicKey)})
      default: Log.warning("[Chat]", "Could not send the message, encryption is not an available option.")
    }
  else void broadcast(Dom.get_value(#entry), {none})
  Dom.clear_value(#entry)
}

/** Broadcast a media file. */
protected function sendMedia(Room.user self, Room.id room)(string name, string mimetype, int id) {
  file = ~{name, mimetype, id}
  message = Message.new(self.id, room, ~{file}, {none})
  Room.broadcast(~{message}, room)
}

/** Implement an infinite scroll. */
module MessageScroll {

  /**
   * Fetched pre-formatted user snippets from the database, ready for
   * insertion in the view. The asynchronous status ensures that the list scroll
   * remains fluid.
   */
  private exposed @async function void fetch(User.id self, Room.id room, Date.date ref) {
    Log.notice("[Chat]", "Scroll.fetch: ref={ref} room={room} self={self}")
    page = Message.fetchPage(room, 20, ref)
    prepend(self, room, page)
  }

  /**
   * Insert the loaded elements into the view.
   * If more elements are to be expected, then restore the {scroll} handler, with updated
   * parameters (set to fetch the following elements).
   */
  private client function prepend(self, room, page) {
    if (page.size > 0) {
      prependMessages(self, page.elts) // Prepend new elements.
      Dom.bind(#conversation, {scroll}, scroll(self, room, page.last, _)) |> ignore
    }
  }

  /**
   * Load more elements, and append them to the end of the list.
   * Called exclusively by the function {scroll}, which detects the optimal moment for loading more elements.
   * This function must NOT be async: we need to deactivate the {scroll} event handler, to avoid duplicate
   * calls to {fetch}. {fetch} IS asynchronous, and this ensures the fluidity of the scroll.
   */
  private client function void load(self, room, ref) {
    Dom.unbind_event(#conversation, {scroll}) // Unbind event to avoid multiple requests.
    fetch(self, room, ref) // Send request for more elements.
  }

  /**
   * Called on scroll events. Detect when less than a certain amount of elements remain in the list
   * to know when to trigger the function to fetch more user.
   * User height is estimated at 80px for the purpose of determining the number of elements left in the list.
   * When less than three times the amount of visible user remain in the list, new elements are fetched.
   * Same as {load}, this function needn't be asynchronous.
   */
  private client function void scroll(self, room, ref, _evt) {
    list = #conversation
    current = Dom.get_scroll_top(list)
    height = Dom.get_height(list)
    mvisible = height/80
    mleft = current/80
    if (mleft < 3*mvisible) load(self, room, ref)
  }

  /** Initialize the infinite scolling. */
  function init(self, room, _evt) {
    load(self, room, Date.now())
  }

} // END MESSAGESCROLL



/** {1} Server launch. */

watch_button =
  <iframe src="http://ghbtns.com/github-btn.html?user={GITHUB_USER}&repo={GITHUB_REPO}&type=watch&count=true&size=large"
          allowtransparency="true" frameborder="0" scrolling="0" width="146px" height="30px"></iframe>

fork_button =
  <iframe src="http://ghbtns.com/github-btn.html?user={GITHUB_USER}&repo={GITHUB_REPO}&type=fork&count=true&size=large"
          allowtransparency="true" frameborder="0" scrolling="0" width="146px" height="30px"></iframe>

/** Page headers. */
headers =
  Xhtml.of_string_unsafe("
<!--[if lt IE 9]>
<script src=\"//html5shiv.googlecode.com/svn/trunk/html5.js\"></script>
<![endif]-->") <+>
  <meta charset="utf-8"></meta>
  <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"></meta>
  <meta name="viewport" content="width=device-width,initial-scale=1"></meta>

/**
 * Create the page structure, and set up an initializer.
 * The login is automatically checked, and the page redirects to a login box
 * if no user is connected.
 */
protected function xhtml buildLoggedPage(string redirect, init) {
  // Retrieve access token from query parameters (if provided).
  // The access token is inserted into SSO service.
  url = HttpRequest.get_url()
  token = match (url) {
    case {some: url}: List.assoc("oauth_token", url.query)
    default: none
  }
  <div id=#main class="main-view" onready={initClient(token, checkLogin(redirect, init, _), _)}/>
}

/**
 * Set the access token if provided, and initialize the client's local key.
 * Check login state and retrieve credentials.
 */
client function void initClient(option(string) token, callback, evt) {
  match (token) {
    case {some: token}:
      localKey = getLocalKey()
      if (AuthorAccess.setAccessToken(localKey, token)) {
        Client.SessionStorage.set("chat_provider_login", "true")
      }
    default: void
  }
  callback(evt)
}

/**
 * Insert the logout button. The button is inserted only if the login wasn't automatic
 * (from the identity provider). This is determined by the value of the local storage variable
 * 'chat_provider_login'.
 */
client function insertLogout(localKey, _evt) {
  match (Client.SessionStorage.get("chat_provider_login")) {
    case {some: "true"}: void
    default:
      #loginout_button =
        <button class="btn btn-default"
            onclick={function (_) { AuthorAccess.logout(localKey, "/") }}>
          Logout
        </button>
  }
}

/**
 * Check whether the login state is defined, and redirect the
 * user accordingly.
 */
exposed function checkLogin(string url, onready, _evt) {
  localKey = getLocalKey()
  user = AuthorAccess.getCurrent(localKey)
  if (AuthorAccess.isLogged(user))
    onready(localKey, user)
  else AuthorAccess.login(localKey, url)
}

/** Execute the function only if the active user if correctly logged in. */
exposed function ifLogin(string localKey, iflogin) {
  user = AuthorAccess.getCurrent(localKey)
  if (AuthorAccess.isLogged(user)) iflogin()
  else void
}

/**
 * Return the avatar of the user as a dataUrl.
 * If no avatar is attributed to the user, the dataUrl will be the reference
 * 'resources/img/default-user.svg'.
 */
protected function downloadAvatar(User.id user) {
  match (HttpRequest.get_url()) {
    case {some: url}:
      match (List.assoc("localKey", url.query)) {
        case {some: localKey}:
          AuthorAccess.getAvatar(localKey, user)
        default: @static_resource("resources/img/default-user.svg")
      }
    default: @static_resource("resources/img/default-user.svg")
  }
}

/** Download a file. */
protected function downloadFile(int id) {
  match (Upload.get(id)) {
    case {some: file}:
      Resource.binary(file.content, file.mimetype) |>
      Resource.add_header(_, {content_disposition: {attachment: file.name}})
    default:
      conversationsPage()
  }
}

/** Access metrics. */
function metrics(string room, option(string) timestamp) {
  match (Room.find({named: room})) {
    case {some: room}:
      messages = Metric.fetch(room.id, 255, 0, timestamp)
      RPC.Json.json json = {List: List.map(Metric.toJson, messages)}
      Resource.json(json)
    case {none}:
      Resource.json({Record:[("error", {String: "Room {room} does not exist"})]})
  }
}

/** Global dispatcher. */
dispatcher = parser {
  // SSO reserved URLs.
  case _special=AuthorAccess.special_uris : conversationsPage()
  case special = AuthorAccess.special_uris2 : special
  // Specific URLs.
  case "/avatar/" id=((!"?" .)*) ("?" .*)?: downloadAvatar(Text.to_string(id))
  case "/file/" id=Rule.integer: downloadFile(id)
  case "/access/" room=Rule.ident: roomAccessPage(room)
  case "/create/restricted": restrictedRoomCreatorPage()
  case "/create/named": namedRoomCreatorPage()
  case "/metrics/" room=Rule.ident "/"? timestamp=Rule.ident? : metrics(room, timestamp)
  // Default to front page.
  case _url=(.*): conversationsPage()
    // startPage(<></>)
}

/** Server configuration. */
serverConf =
  port = Utils.config("{PEPS_DIR}/apps/chat/port") |> Option.bind(Int.of_string_opt, _)
  conf =
    if (no_ssl == "true") Server.http
    else
      { Server.https with
        name: "opachat",
        encryption: {
          certificate : "{PEPS_DIR}/server.crt",
          private_key : "{PEPS_DIR}/server.key",
          password : ""
        } }
  match (port) {
    case {some: port}: {conf with ~port}
    default: conf
  }

// Start the server.
Server.start(serverConf, [
  { resources : @static_resource_directory("resources") }, // include resources directory
  { register : {css:["/resources/css/style.css"]} }, // include CSS in headers
  { custom : dispatcher } // URL parser
])
