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



type Message.id = Token.t

type Message.encryption =
  {none} or
  {string key, string nonce} // Encrypted secret key.

type Message.content =
  {string text} or
  {{string mimetype, string name, int id} file}

type Message.t = {
  Message.id id,
  User.id source,
  Message.content content,
  Date.date date,
  Room.id room,
  Message.encryption encryption
}

database /opachat/messages[_]/content = {text: ""}

module Message {

  /** Create a new message, and save it to the database. */
  function Message.t new(User.id source, Room.id room, Message.content content, Message.encryption encryption) {
    message = ~{
      id: Token.generate(), source,
      content, date: Date.now(), room,
      encryption
    }
    save(message)
    Room.log(message)
    message
  }

  /** Save a new message. */
  function save(Message.t message) {
    /opachat/messages[id == message.id] <- message
  }

  /** Returnt the last *text* message posted to a room chat. */
  function lastText(Room.id room) {
    Utils.Db.option(/opachat/messages[room == room and content.text exists; order -date; limit 1])
  }

  /** Fetch {limit} messages, dated after {ref}, ordered by decreasing date. */
  function fetch(Room.id room, int limit, Date.date ref) {
    DbSet.iterator(/opachat/messages[room == room and date < ref; order -date; limit limit]) |> Iter.to_list
  }

  /** Same as {fetch}, but the results are returned in a page. */
  function fetchPage(Room.id room, int limit, Date.date ref) {
    messages = fetch(room, limit, ref)
    size = List.length(messages)
    first = Option.map(_.date, List.head_opt(messages)) ? ref
    last = Option.map(_.date, List.last_opt(messages)) ? ref
    ~{elts: messages, size, first, last}
  }

  /** Return the name of the message source. */
  function sourceName(Message.t message) { User.getUsername(message.source) }
  /** Return the text content, or the filename if the message is a file. */
  function textContent(Message.t message) {
    match (message.content) {
      case ~{text}: text
      case ~{file}: file.name
    }
  }

  /** Build a (dis)connection message. */
  both @expand function connection(Room.id _room, string username) { "{username} joined the room" }
  both @expand function disconnection(Room.id _room, string username) { "{username} left the room" }

  /** Render a message. */
  client function render(Message.t message) {
    // Decrypt the message content, if needed.
    content = match (message.encryption) {
      case ~{key, nonce}:
        match (Client.SessionStorage.get("roomSecretKey")) {
          case {some: secretKey}:
            secretKey = Uint8Array.decodeBase64(secretKey)
            nonce = Uint8Array.decodeBase64(nonce)
            publicKey = Uint8Array.decodeBase64(key)
            match (message.content) {
              case ~{text}:
                data = Uint8Array.decodeBase64(text)
                match (TweetNacl.Box.open(data, nonce, publicKey, secretKey)) {
                  case {some: message}: {text: Uint8Array.encodeUTF8(message)}
                  default:
                    Log.warning("[Chat]", "unable to read an encrypted chat message.")
                    message.content
                }
              case ~{file}: ~{file}
            }
          default:
            Log.warning("[Chat]", "unable to read an encrypted chat message.")
            message.content
        }
      case {none}: message.content
    }
    match (content) {
      case ~{text}:
        <p class="message">{text}</p>
      case {file: ~{mimetype, name, id}}:
        media = ~{mimetype, name, src: "/file/{id}"}
        Upload.render(media)
    }
  }

}
