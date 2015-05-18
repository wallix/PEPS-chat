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



type Room.id = Token.t

/** Only used at the room creation. */
type Room.kind =
  {string named} or
  {list(User.id) restricted}

type Room.t = {
  Room.id id,
  User.id owner,
  string name,
  list(string) members,
  // Encryption.
  string hash, // Hashed password.
  string salt, // Salt using in hashing the password.
  cipher secretKey, // Encrypted secret key (for password-protected rooms).
  string publicKey, // Public key.
  stringmap(cipher) secretKeys, // Encrypted secret keys (for restricted rooms).
  bool secure, // Indicate whether encryption is available for this room.
  // Statistics.
  int count,
  Date.date updated
}

type Room.user = {
  User.id id,
  string username
}

/** Type of room chat messages. */
type Room.message =
  {Message.t message} or
  {(Room.user, Room.id, client_channel) connection} or
  {(Room.user, Room.id) disconnection} or
  {stats}

/**
 * A room network contains a private network, and a server observer
 * desgined to log all user connections.
 */
type Room.network = {
  Network.network(Room.message) network,
  Network.observer observer
}

/**
 * Store room users.
 * Room.id -> User.id -> Room.user
 * TODO: move to Redis.
 */
private reference(stringmap(stringmap(Room.user))) roomUsers =
  ServerReference.create(StringMap.empty)

/**
 * Store room channels.
 * Room.id -> Network.network(Network.message)
 * TODO: move to Redis.
 */
private reference(stringmap(Room.network)) roomNetworks =
  ServerReference.create(StringMap.empty)

module Room {

  private nopassword = Crypto.salted {data:binary_of_string(""), salt:binary_of_string("")}

  /**
   * Create a new room and upload it to the server. Keep client side: the password should not be sent
   * to the server, and the secret key must be generated client side.
   */
  client function create(string localKey, User.id self, Room.kind kind, string owner, string password) {
    localKey = getLocalKey()
    pass = Uint8Array.decodeUTF8(password)
    (salt, hash) =
      if (password == "") ("", "")
      else {
        salt = TweetNacl.randomBytes(16)
        hash = TweetNacl.hash(Uint8Array.concat(pass, salt))
        (Uint8Array.encodeBase64(salt), Uint8Array.encodeBase64(hash))
      }
    keyPair = TweetNacl.Box.keyPair()
    match (kind) {
      case {restricted: members}:
        // TODO: encryption.
        members = List.sort(members)
        secretKeys = List.fold(function (member, secretKeys) {
          match (User.publicKey(localKey, member)) {
            case {some: hisPublicKey}:
              nonce = TweetNacl.randomBytes(TweetNacl.Box.nonceLength)
              secretKey = TweetNacl.Box.box(keyPair.secretKey, nonce, hisPublicKey, keyPair.secretKey)
              cipher = {
                message: Uint8Array.encodeBase64(secretKey),
                nonce: Uint8Array.encodeBase64(nonce)
              }
              StringMap.add(member, cipher, secretKeys)
            default:
              Log.warning("[Room]", "create: missing publicKey for {member}")
              secretKeys
          }
        }, members, StringMap.empty)
        name = String.concat(",", members)
        ~{
          id: Token.generate(),
          owner, name, hash, salt,
          members, count: 0,
          secretKeys,
          secretKey: { message: "_", nonce: "_" }, // Need to be non empty, the room encryption is decided upon that.
          publicKey: Uint8Array.encodeBase64(keyPair.publicKey),
          updated: Date.now(),
          secure: true }

      case {named: name}:
        // Generate the key pair.
        nonce = TweetNacl.randomBytes(TweetNacl.SecretBox.nonceLength)
        masterKey = TweetNacl.pbkdf2(pass, Uint8Array.decodeBase64(salt), 5000, TweetNacl.SecretBox.keyLength)
        secretKey = TweetNacl.SecretBox.box(keyPair.secretKey, nonce, masterKey)
        ~{
          id: Token.generate(),
          owner, name, hash, salt,
          members: [], count: 0,
          updated: Date.now(),
          secretKey: {
            message: Uint8Array.encodeBase64(secretKey),
            nonce: Uint8Array.encodeBase64(nonce)
          },
          publicKey: Uint8Array.encodeBase64(keyPair.publicKey),
          secretKeys: StringMap.empty,
          secure: password != "" }
    }
  }

  /** Save a room to the database. */
  protected function save(Room.t room) {
    /opachat/rooms[id == room.id] <- room
  }

  /** Update the room statistics after sending a message. */
  function log(Message.t message) {
    /opachat/rooms[id == message.room] <- {count++, updated: message.date; ifexists}
  }

  /** Return the room with the given id. */
  function option(Room.t) get(Room.id id) {
    Utils.Db.uniq(/opachat/rooms[id == id or name == id])
  }

  /** Return the room's name. */
  function string name(Room.t room, User.id user) {
    match (room.members) {
      case []: room.name
      default:
        members = List.remove(user, room.members)
        String.concat(", ", List.map(User.getUsername, members))
    }
  }

  /** Find a room by its kind. */
  exposed function option(Room.t) find(Room.kind kind) {
    match (kind) {
      case {named: name}: Utils.Db.option(/opachat/rooms[name == name])
      case {restricted: members}:
        members = List.sort(members)
        name = String.concat(",", members)
        Utils.Db.option(/opachat/rooms[name == name])
    }
    // get(name) // We allow the id as the name ?
  }

  /** Check the existance of a room named {name}. */
  function bool exists(string name) {
    Utils.Db.exists(/opachat/rooms[name == name; limit 1].{})
  }

  /** Return the room members. */
  function members(Room.id id) {
    ?/opachat/rooms[id == id]/members ? []
  }

  /** Check whether {user} can access the room chat. */
  function checkAccess(Room.t room, User.id user) {
    if (not(room.members == [] || List.mem(user, room.members)))
     {error: <div class="error" style="color: red;">You are not a member of room {name(room, user)}</div>}
    else if (passwordProtected(room)) {pass:void}
    else if (room.members == []) {open:void}
    else {restricted:void}
  }

  /** Check whether the room access is protected by a password. */
  both function passwordProtected(Room.t room) {
    room.hash != "" && room.salt != ""
  }

  function bool checkPassword(Room.t room, string hash) {
    if (passwordProtected(room)) room.hash == hash
    else true
  }

  /**
   * List the rooms that can be accessed by the given user (excepting named rooms).
   * Rooms are sorted according to the date of the last sent message.
   * TODO: add a relevance field, which would be a function of the number of messages
   * and the date of the last message.
   */
  function list(User.id user) {
    rooms = User.getRooms(user) // Get personal rooms.
    DbSet.iterator(/opachat/rooms[id in rooms or members[_] == user; order -updated]) |> Iter.to_list
  }

  /**
   * Create a small item displaying the room, including:
   *  - room members / room name
   *  - last message in room
   * TODO: add user avatars.
   */
  protected function format(string localKey, Room.t room, User.id user, onclick) {
    (title, avatars, avatarClass) =
      match (room.members) {
        case []: (<span>{room.name}</span>, <></>, "none")
        default:
          List.fold(function (member, (list, avatars, avatarClass)) {
            if (member != user) {
              availability = User.getAvailability(member)
              avatar = User.getHtmlAvatar(localKey, member)
              item = <span>{User.getUsername(member)} {User.availabilityToHtml(member, availability)}</span>
              if (list == <></>) (item, avatar, "single")
              else (list <+> <>, </> <+> item, avatars <+> avatar, "multiple")
            } else
              (list, avatars, avatarClass)
          }, room.members, (<></>, <></>, "single"))
      }
    last =
      if (room.members == []) ""
      else match (Message.lastText(room.id)) {
        case {some: message}: "{Message.sourceName(message)}: {Utils.suffix(Message.textContent(message), 50)}"
        default: ""
      }
    <li class="list-group-item" onclick={onclick(room.id, _)}>
      <div class="chat-avatars {avatarClass}">{avatars}</div>
      <div class="chat-snippet">
        <div class="chat-authors">{title}</div>
        <small class="chat-descr">{last}</small>
      </div>
    </li>
  }

  /** {1} RoomUsers network updates. */

  /** Add a user to a room. */
  function void join(Room.user user, Room.id id) {
    match (StringMap.get(id, ServerReference.get(roomUsers))) {
      case {some: room}: ServerReference.update(roomUsers, StringMap.add(id, StringMap.add(user.id, user, room), _))
      case {none}: ServerReference.update(roomUsers, StringMap.add(id, StringMap.singleton(user.id, user), _))
    }
  }

  /** Remove a user from a room. */
  function void leave(Room.user user, Room.id id) {
    match (StringMap.get(id, ServerReference.get(roomUsers))) {
      case {some: room}:
        room = StringMap.remove(user.id, room)
        if (StringMap.is_empty(room)) ServerReference.update(roomUsers, StringMap.remove(id, _))
        else ServerReference.update(roomUsers, StringMap.add(id, room, _))
      default: void
    }
  }

  /** Intercept connection and disconnection messages. */
  protected function handleConnections(Room.message message) {
    match (message) {
      case {connection: (user, roomId, channel)}:
        Room.join(user, roomId) // Add the user to the room (locally).
        Room.broadcast({stats}, roomId) // Send new statistics. cpu??? space???
        Metric.logStatistics(roomId, 0, System.get_memory_usage()/(1024*1024), 0)
        // Handle disconnection.
        Session.on_remove(channel, function() {
          handleConnections({disconnection: (user, roomId)})
        })
      case {disconnection: (user, roomId)}:
        Room.leave(user, roomId) // Remove the user from the room (locally).
        Room.broadcast({stats}, roomId) // Send new statistics.
        Metric.logStatistics(roomId, 0, System.get_memory_usage()/(1024*1024), 0)
      default: void
    }
  }

  /** Return the cloud associated with a room, or create a new one. */
  protected function Network.network(Room.message) getNetwork(Room.id id) {
    match (StringMap.get(id, ServerReference.get(roomNetworks))) {
      case {some: ~{network, observer: _}}: network
      case {none}:
        cloud = Network.cloud(id)
        network = {
          network: cloud,
          observer: Network.observe(handleConnections, cloud)
        }
        ServerReference.set(roomNetworks, StringMap.add(id, network, ServerReference.get(roomNetworks)))
        cloud
    }
  }

  /** Broadcast a message to a room's cloud. */
  exposed function broadcast(Room.message message, Room.id id) {
    Network.broadcast(message, getNetwork(id))
  }

  /** Add a room observer */
  exposed function observe(handler, Room.id id) {
    Network.observe(handler, getNetwork(id))
  }

  /** Disconnect a user from a room. */
  exposed function disconnect(Room.user user, Room.id id) {
    Metric.logDisconnect(user.id, id) // Statistics.
    broadcast({disconnection: (user, id)}, id)
  }

  /** Connect a user to a room. */
  exposed function connect(Room.user user, Room.id id, channel) {
    Metric.logConnect(user.id, id) // Statistics.
    User.addRoom(user.id, id)
    broadcast({connection: (user, id, channel)}, id)
  }

  /** Return the sorted list of room users. */
  function list(Room.user) users(Room.id id) {
    match (StringMap.get(id, ServerReference.get(roomUsers))) {
      case {some: room}: StringMap.To.val_list(room) |> List.sort_by(_.username, _)
      default: []
    }
  }

}
