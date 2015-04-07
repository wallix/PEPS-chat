import sso

sso_prefix = {
  schema       = some("http")
  credentials  = {username=none password=none}
  domain       = "localhost"
  port         = some(8080)
  path         = ["sso", "oauth"]
  query        = []
  fragment     = none
  is_directory = false
} : Uri.absolute

auth_prefix = {sso_prefix with schema = some("https") port=some(4343)}

SSOClientDemo = SSOService.Client(
  {name="demo"
   consumer_key="vqsv58lkj"
   consumer_secret="kqs89lo54acdsq"
   sso_prefix=Uri.to_string(@opensums(sso_prefix))
   auth_prefix=Uri.to_string(@opensums(auth_prefix))
  },
  {uri = "/sso/oauth/"
   host = "http://localhost:8081"
   callback =
     | {success=_} ->
       do Log.error("SSOClient", "Success")
       Resource.page("SSO Success", <h1>SSO Success</h1>)
     | ~{failure} ->
       do Log.error("SSOClient", "Failure {failure}")
       Resource.page("SSO Error",
       <h1>Sorry but an error occurs while your authentication</h1>)}
)

authenticate() = SSOClientDemo.full({same cb = result -> Resource.page("return", <>{"{result}"}</>)})

server = Server.simple_server(
  parser | r={SSOClientDemo.parser} ->  r
         | "/" -> Resource.page("Init", <h1 onclick={_ -> authenticate()}>Try</h1>)
  )
