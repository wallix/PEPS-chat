/**
 * Copyright © 2012-2015 MLstate
 * All rights reserved.
 */

type cipher = {
  string message,
  string nonce
}

module Utils {

  /** Read the content of a configuration file. */
  function config(string path) {
    if (File.exists(path)) {
      value = File.read(path) |> Binary.to_string |> String.trim // Remove ending \n.
      // Log.notice("[Config]", "Obtained value={value} from path {path}")
      some(value)
    } else {
      Log.warning("[Config]", "Missing configuration file {path}")
      none
    }
  }

  /** Dismiss a notification. */
  client function dismiss(string id, _evt) {
    Dom.remove(#{id})
  }

  /** Wait some delay before automatically dismissing a notification. */
  client function dismissAfter(string id, int ms, _evt) {
    Scheduler.sleep(ms, function () { dismiss(id, 0) })
  }

  /** Make and insert a notification. */
  function notify(xhtml content, string class) {
    notification =
      id = Dom.fresh_id()
      <div id="{id}" class="alert alert-{class}" onready={dismissAfter(id, 3000, _)}>
        <a class="close" data-dismiss="alert" onclick={dismiss(id, _)}>&times;</a>
        {content}
      </div>
    #notification = notification
  }

  /** Compute the duration in ms between two dates. */
  function delta(a, b) { Duration.between(a, b) |> Duration.in_milliseconds }

  /** Extract the last caracters of a string. */
  function suffix(string text, int size) {
    len = String.length(text)
    if (len < size) text
    else "...{String.substring(len-size+3, size-3, text)}"
  }

  /** Parse the media mimetype. */
  mimeParser = parser {
    case "image/" .*: {image}
    case "audio/" .*: {audio}
    case "video/" .*: {video}
  }

  module Db {
    /** Convert a dbset to a unique option. */
    function uniq(x) {
      iter = DbSet.iterator(x)
      if (Iter.count(iter) == 1)
        Option.map(_.f1, iter.next())
      else
        {none}
    }

    /**
     * Convert a dbset to an option. If the function is used to extract a value
     * from an dbset built with the key as query, it is better to use this one since
     * the set can not contain more than one element.
     * @return the first element of the iteration if non empty, else [{none}].
     */
    function option(x) {
      iter = DbSet.iterator(x)
      Option.map(_.f1, iter.next())
    }

    function exists(x) {
      iter = DbSet.iterator(x)
      Option.is_some(iter.next())
    }

  } // END DB

} // END UTILS