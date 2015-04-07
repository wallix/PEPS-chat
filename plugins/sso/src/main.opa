import sso

db /users : stringmap({pass : string; user : SSODemo.val})

do /users["test"] <- {pass = "test" user = {name="toto" age=10}}

db /services : stringmap({service : SSOService.service(SSODemo.service) secret : string})

do /services["vqsv58lkj"] <- {{service = {external = {name = "mon service"}} : SSOService.service(SSODemo.service)
                              secret  = "kqs89lo54acdsq" }}

db /services[_] full

do /services["vqsv58lkj2"] <- {{service = {trusted = {name = "mon service trusted"}}  : SSOService.service(SSODemo.service)
                               secret  = "kqs89lo54acdsq2" }}

db /creds/simple : stringmap(OAuth.cred(SSODemo.val))

db /creds/shared : stringmap(OAuth.cred(SSODemo.val))

/** SSO type */
type SSODemo.val = {
  name : string;
  age : int;
}

type SSODemo.key = {
  name : string
  pass : string
}

type SSODemo.service = {
  name : string
}

/** SSO key value access */
access : SSOService.access(SSODemo.key, SSODemo.service, SSODemo.val) = {
  get_service(consumer_key) =
    Option.map(_.service, ?/services[consumer_key])

  get_secret(consumer_key) =
    Option.map(_.secret, ?/services[consumer_key])

  get_value(~{name pass}) =
    val = /users[name]
    if val.pass == pass then some(val.user)
    else none

  set_cred(key, cred) = match key
    | {simple = key} -> /creds/simple[key] <- cred
    | {shared = key} -> /creds/shared[key] <- cred

  get_cred(key) = match key
    | {simple = key} -> ?/creds/simple[key]
    | {shared = key} -> ?/creds/shared[key]

  del_cred(key) = match key
    | {simple = key} -> Db.remove(@/creds/simple[key])
    | {shared = key} -> Db.remove(@/creds/shared[key])

}

sso_config : SSOService.config(SSODemo.key, SSODemo.service, SSODemo.val) = {
  name = "demo"

  ~access

  /* Get key from the current request*/
  get_key() =
    match HttpRequest.get_body()
    | {none} -> {none}
    | {some = body} ->
      match Parser.try_parse(UriParser.query_parser, body)
      | {none} -> {none}
      | {some = queries} ->
        match List.assoc("username", queries)
        | {none} -> {none}
        | {some = name} ->
          match List.assoc("password", queries)
          | {none} -> {none}
          | {some = pass} -> {some = ~{name pass}}

  get_accept() =
    match HttpRequest.get_body()
    | {none} -> {none}
    | {some = body} ->
      match Parser.try_parse(UriParser.query_parser, body)
      | {none} -> {none}
      | {some = queries} ->
        match List.assoc("accept", queries)
        | {none} -> {none}
        | {some = "Accept"} -> {some = true}
        | {some = "Cancel"} -> {some = false}
        | _ -> {none}

  /* Build the login page */
  login_page(_uri, build_form, largs) =
    form(msg, username) =
      xhtml =
        <>
          {msg}
          <h1>A demo sso server</h1>
          <h2>Please enter your login datas</h2>
          {build_form(
            <input type="text" name="username" value="{username}"/>
            <input type="password" name="password"/>
            <input type="submit" name="accept" value="Accept"/>
            <input type="submit" name="accept" value="Cancel"/>
          )}
        </>
      Resource.page("SSO login page", xhtml)
    match largs
    | {bad_request} ->
      form(<>Request seems bad formatted</>, "")

    | {service = {trusted = ~{name}} status = {init}}
    | {service = {external = ~{name}} status = {init}} ->
      form(<>Service "{name}" request your access authorization</>, "")

    | {service = {trusted = ~{name}} status = {access_denied = key}}
    | {service = {external = ~{name}} status = {access_denied = key}} ->
      form(<>
             <h3 style="color:red"> Bad login or password</h3>
             <>Service "{name}" request your access authorization</>
           </>
      , key.name)

    | {service = {trusted = ~{name}} status = {authenticated = val}}
    | {service = {external = ~{name}} status = {authenticated = val}} ->
      Resource.page("SSO loging page",
        build_form(
          <>
            <h1>Hello {val.name}, service "{name}" request your authorization</h1>
            <input type="submit" name="accept" value="Accept"/>
            <input type="submit" name="accept" value="Cancel"/>
          </>
        )
      )


  /* Build page in case of success page */
  auth_success(callback) = match callback with
    | {none} ->
      Resource.page("Authentication : Success",
        <h1>Authentication : Success</h1>)
    | {some = {success=callback}} ->
      Resource.redirection_page("Authentication : Failure",
        <>
          <h1>Access granted</h1>
          <h2>You will be redirect in a few seconds</h2>
        </>,
        {success}, 1, Uri.to_string(callback))
    | {some = {failure=callback}} ->
      Resource.redirection_page("Authentication : Success",
        <>
          <h1>Access granted</h1>
          <h2>You will be redirect in a few seconds</h2>
        </>,
        {success}, 1, Uri.to_string(callback))

  sso_prefix = {
    schema       = some("https")
    credentials  = {username=none password=none}
    domain       = "localhost"
    port         = some(4343)
    path         = ["sso", "oauth"]
    query        = []
    fragment     = none
    is_directory = false
  }

}


/** SSO services */

SSO = SSOService.OAuth(sso_config)

server =
  service = SSO.service.sso_interface
  {service with
    url_handler = parser
      | "/sso/oauth/" r={service.url_handler} -> r
      | "/dataaccess" -> _ -> match SSO.get_credential()
        | ~{failure} -> Resource.raw_status(failure)
        | {success = ~{value service=_}} -> Resource.json(
            OpaSerialize.Json.serialize(value)
          )
    server_name="http"
  }

map_parser(map, parser) = b, i -> Option.map(((i, r) -> (i, map(r))), parser(b,i))

server =
  service = SSO.service.usr_interface
  handler = map_parser(Server.public, parser "/sso/oauth/" r={service.url_handler} -> r)
  ssl_params = { Server.ssl_default_params with
                   certificate="main.crt"
                   private_key="main.key"
               } <: Server.encryption
  { Server.secure(ssl_params, handler) with server_name = "https" }
