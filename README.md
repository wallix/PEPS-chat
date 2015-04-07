% PEPS Chat

# About

PEPS Chat is a multi-room chat for the PEPS platform that also supports individual conversations.

![Screenshot goes here]()

# Installation

PEPS Chat is not a standalone application, but an add-on to PEPS.
You first need to [install PEPS](https://github.com/MLstate/PEPS) from its repository and run it on your server or test machine.

Then, within PEPS, create a new application.

![Screenshot goes here]()

By default, PEPS will export the application parameters to `/etc/peps/apps/{appname}` which will enable you to directly launch PEPS Chat from the same machine without command line arguments.

The next step is to generate the consumer key on the PEPS website. Login as `admin` and go to the page `Admin/Apps`.  Enter a name for the application (usually "chat").

The link should be the URI of your OpaChat deployment. Click on `CREATE APP` to generate the key. If the OpaChat server is running on the same machine, OpaChat will be able to automatically retrieve its configuration parameters. If not, you will have to pass the `Key` and `Secret` fields as arguments of the OpaChat deployment.

# Command line configuration

If you run PEPS Chat from a different host, or if you can't give access to `/etc/peps`, you will need to pass arguments manually to PEPS Chat:
To run the chat program, type something like:

    ./opa_chat.js --db-remote:opachat localhost:27017 \
                  --db-remote:opashare localhost:27017 \
                  --port 8080 \
                  --host http://localhost:8080 \
                  --sso-host localhost:4443 \
                  --consumer-key 3Q1SfahLPW99juH80PXKRCXD9FdIlg3Y \
                  --consumer-secret IoWj7lycFYs3H5XaizLZmR2jPrkcAOjl \
                  --app-name peps_chat

Note that you have to set the domain name for your PEPS deployment to the same
as the `--host` value, in this case `localhost`.

This example assumes:

- Your MongoDB server is running on the `localhost` machine on the default port,
  27017, for Mongo.

- You are deploying the chat program on the localhost machine on port 8080.  The
  two instances of the port number in this command must match.

- The `--host` argument must be the full URI for the chat deployment, this will
  define the callback used by the PEPS SSO code, see above.

- The `--sso-host` option should be the domain name where PEPS is running.
  Again, this has to exactly match the `Domain` value configured in the PEPS
  program.  Note that if you are running PEPS on port 443, which is most likely,
  you should *not* add the port number to the SSO host name.

- The `--consumer-key` and `--consumer-secret` options are the `Key` and
  `Secret` values read from the PEPS `Apps` page.

- The `--app-name` value is the `Name` value from PEPS.

You can disable TLS/SSL by using the `no-ssl` option. Note also that if you wish to
use the `--no-ssl` option then you should also run PEPS with this same option.

If everything matches up between PEPS and the OpaChat application, you should be
able to login to OpaChat using your PEPS login.  If the login fails, you should
carefully check all these options and verify that they match your PEPS setup.

