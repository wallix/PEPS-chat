/**
 * Copyright © 2012-2015 MLstate
 * All rights reserved.
 */

import stdlib.crypto
import file

/** Sharing module. */

MAX_SIZE = 5
LIMIT_TEXT = "File size limit exceeded! ({MAX_SIZE} Mb)"

/** Internal representation of the media. */
type OpaShare.file = {
  int id,                    // File ID.
  string name,               // File name.
  int size,                  // File size.
  binary content,            // File content.
  string mimetype,           // File mimetype.
  Date.date uploaded,        // Upload date.
  Date.date downloaded,      // Last download date.
  int count,                 // Download counter.
  option(string) password,   // File password.
}

/** External representation of the media. */
type media = {
  User.id source,
  string name,
  string src,
  string mimetype,
  Date.date date
}

database opashare {
  OpaShare.file /files[{id}]
}

module Upload {

  /** Generate a fresh file Id. */
  private function freshId() { Date.in_milliseconds(Date.now()) }

  /** Render a media source. */
  client function render(media) {
    match (Parser.try_parse(Utils.mimeParser, media.mimetype)) {
      case {some: {image}}: <img src="{media.src}" alt="{media.name}" class="media-message"/>
      case {some: {audio}}:
        <audio src="{media.src}"
            controls="controls"
            type="{media.mimetype}"
            preload="auto">
          Your browser does not support the audio tag!
        </audio>
      case {some: {video}}:
        <video src="{media.src}"
            controls="controls"
            preload="auto"
            type="{media.name}"
            class="media-message">
          Your browser does not support the video tag!
        </video>
      default:
        <span class="media-message {media.mimetype}">is sharing a file :
          <a target="_blank" href="{media.src}"
              draggable="true"
              data-downloadurl="{media.mimetype}:{media.name}:{media.src}"
              class="chat-media">
            {media.name}
          </a>
        </span>
    }
  }

  /** {1} Upload. */

  client function init(callback) {
    dropzone = Dom.select_class("dropzone")
    FilePlugin.hookFileDrop(dropzone, fileUploading, fileUpload(callback), fileDone)
    FilePlugin.hookFileUpload(#files, fileUploading, fileUpload(callback), fileDone)
  }

  /** Called before uploading the files. */
  private client function fileUploading() {
    Log.notice("[Upload]", "Uploading files...")
    #share = <img src="/resources/img/facebook-loader.gif" alt="Uploading..."/>
  }

  /** Called after uploading the files. */
  private client function fileDone() {
    Log.notice("[Upload]", "Upload done")
    #share = <img src="/resources/img/paper-clip.svg"/>
  }

  /**
   * Check the characteristics of the selected file.
   * If the file is too large, show an error message, else upload the file to the database.
   */
  private client function fileUpload(callback)(string name, string mimetype, int size, string content) {
    if (size > MAX_SIZE*1024*1024)
      Utils.notify(<>File too large !</>, "warning")
    else
      processFile(name, mimetype, size, content, callback) |> ignore
  }

  /** Upload a file to the database. */
  exposed function processFile(string name, string mimetype, int size, string content, callback) {
    // Decode raw content.
    content =
      match (String.index("base64,", content)) {
        case {none}: binary_of_string(content)
        case {some: i}:
          offset = i+7
          data = String.sub(offset, String.length(content)-offset, content)
          Crypto.Base64.decode(data)
      }
    // Build file.
    file = ~{
      id: freshId(), name, size, mimetype, content,
      uploaded: Date.now(), downloaded: Date.now(),
      count: 0, password: none
    }
    // Db update.
    /opashare/files[id == file.id] <- file
    callback(name, mimetype, file.id)
  }

  /** Trigger a click on input element. */
  private client function triggerUpload(_evt) {
    Dom.trigger(#files, {click})
  }

  /** Build the upload box. */
  function html() {
    <div class="pull-left file-upload">
      <span id="share" onclick={triggerUpload} title="Upload files">
        <img src="/resources/img/paper-clip.svg"/>
      </span>
      <input id="files" type="file" multiple="multiple"/>
    </div>
  }

  /** Fetch the raw content of a file. */
  function get(int id) {
    ?/opashare/files[id == id]
  }

} // END SHARE
