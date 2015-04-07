/**
 * Copyright © 2012-2014 MLstate
 * All rights reserved.
 */

// TODO: abstract datatype
abstract type Token.t = string

module Token {

  function Token.t generate() {
    Random.string(10)
  }

}
