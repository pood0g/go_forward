# go_forward

One executable with three commands: an SSH server, an SSH client, and a SOCKS5 proxy.

    go_forward server   run the SSH server (remote and local port forwards)
    go_forward client   connect to a server with local, remote and SOCKS forwards
    go_forward socks    serve a SOCKS5 proxy

Run `go_forward <command> -h` for the options of a command.

## Build

Requires Go 1.26 or newer. Dependencies are vendored in `vendor/`, so no network access is needed:

    go build -o go_forward .

Cross-compiling works the same way, for example `GOOS=windows GOARCH=amd64 go build -o go_forward.exe .`.

## Typical setup

The server can run on either machine, whichever one the other can connect to. A SOCKS proxy can
then be put on either side, exiting from the other:

    # proxy on the client machine, connections leave from the server
    ./go_forward client -i <server> -p 2222 -U <user> -k <identity> -D 1080

    # proxy on the server machine, connections leave from the client
    ./go_forward client -i <server> -p 2222 -U <user> -k <identity> -R 1080
    # or, decided on the server instead of the client
    ./go_forward server -p 2222 -U <user> -K authorized_keys -D 1080

    # then, on whichever machine has the proxy
    curl --socks5-hostname 127.0.0.1:1080 https://example.com

Proxies listen on 127.0.0.1 unless an address is given. Any local user on that machine can use
them, so add `--dynamic-auth user:password` on shared machines.

## server

Serves SSH with port forwarding. Clients authenticate with a password, an authorized keys file, or
both.

    ./go_forward server -U <user> -P <password>
    ./go_forward server -U <user> -K authorized_keys
    ./go_forward server -d -U <user> -K authorized_keys     # run as a daemon
    ./go_forward server -s                                  # stop the daemon
    ./go_forward server -a ./id_ed25519.pub -K authorized_keys

- `-U, --username` (required unless `-s`): the single user allowed to log in.
- `-P, --password` (optional): password for that user.
- `-K, --authorized-keys` (optional): OpenSSH `authorized_keys` file. Keys with options
  (`command=`, `no-port-forwarding`, ...) are rejected.
- `-H, --host-key` (default `ssh_host_ed25519_key`): server host key. If the file is missing an
  ed25519 key is generated and saved (mode 0600), so clients keep the same host key across restarts.
- `-p, --port` (default `22`), `-i, --interface` (default `0.0.0.0`).
- `-d, --daemon`: run in the background. The parent prints the daemon's pid and exits.
- `-s, --stop`: stop the daemon recorded in the pid file.
- `-a, --add-key <key or .pub file>`: add a public key to the `--authorized-keys` file and exit. The
  server does not start. Adding a key that is already present does nothing.
- `-D, --dynamic [addr:]port`: start a SOCKS5 proxy on the server. Its connections leave from the
  connected client. A bare port listens on 127.0.0.1.
- `--dynamic-auth user:password` (optional): login required by the `--dynamic` proxy.
- `--pid-file` (default `go_forward_server.pid`), `--log-file` (default `go_forward_server.log`).

At least one of `--password` or `--authorized-keys` is required.

Daemon mode works on Linux, macOS, FreeBSD and Windows. On Unix the daemon starts in a new session.
On Windows it starts as a detached process without a console. `--stop` sends SIGTERM on Unix and
kills the process on Windows. To start at boot, run `go_forward server` in the foreground under
systemd or a Windows service instead of using `--daemon`.

Forwarding supported by the server:

- Remote forward: `ssh -R 9000:localhost:80 ...`. `-R 0:localhost:80` lets the server pick a free
  port and report it back.
- Local forward: `ssh -L 8080:example.com:80 ...`.
- Dynamic local forward (SOCKS): `ssh -D 1080 ...`.

Remote forwards belong to the connection that opened them and close when it disconnects.

## client

Connects to a server and sets up the forwards given on the command line. The forward options follow
OpenSSH and can each be repeated. With no forwards the client only connects, which is enough for
`server -D`.

    ./go_forward client -i <server> -p <ssh port> -U <user> -k <private key> -D 1080
    ./go_forward client -i <server> -U <user> -P <password> -R 9000:127.0.0.1:80
    ./go_forward client -g -k ./id_ed25519                  # create a key pair

- `-i, --host` (required): server address.
- `-p, --port` (default `22`): port the server's SSH listener is on.
- `-U, --username` (required): user to log in as.
- `-P, --password` (optional): password. One of `--password` or `--identity` is required.
- `-k, --identity` (optional): private key file. Encrypted keys prompt for the passphrase.
- `-g, --generate-key`: create an ed25519 key pair at the `--identity` path (private key mode 0600,
  public key at `<path>.pub`), print the public key and exit. It asks for an optional passphrase:
  press Enter for none, or type one twice. Existing files are never overwritten.
- `-L, --local [bind:]port:host:hostport`: listen on the client and connect to `host:hostport`
  from the server.
- `-R, --remote [bind:]port:host:hostport`: listen on the server and connect to `host:hostport`
  from the client. Port `0` lets the server pick a free port; the chosen port is logged.
- `-R, --remote [bind:]port`: start a SOCKS5 proxy on the server whose connections leave from the
  client (reverse dynamic forward).
- `-D, --dynamic [bind:]port`: start a SOCKS5 proxy on the client whose connections leave from the
  server.
- `--dynamic-auth user:password` (optional): login required by the SOCKS proxies from `-D` and `-R`.

`bind` defaults to `127.0.0.1`; `*` or an empty bind (`:1080`) listens on all interfaces.

Key setup:

    ./go_forward client -g -k ./id_ed25519
    ./go_forward server -a ./id_ed25519.pub -K authorized_keys

Host keys are checked against `./known_hosts`. An unknown host key asks for confirmation before it
is saved.

## Dynamic (SOCKS) proxies

A SOCKS5 proxy can run on either side. The connections it makes leave from the other side, through
the SSH connection:

| Proxy runs on | Exits from | Use |
|---------------|------------|-----|
| client        | server     | `client -D 1080` |
| server        | client     | `client -R 1080` or `server -D 1080` |

`client -R 1080` is the same reverse dynamic forward as OpenSSH's and works with any server.
`server -D 1080` is for when the proxy should be set on the server; the client registers itself when
it connects, and requests fail while no client is connected. Several can be used at once.

## socks

Serves a SOCKS5 proxy with optional username and password authentication.

    ./go_forward socks -i 127.0.0.1 -p 1080 -U socks -P <password>

- `-i, --interface` (default `127.0.0.1`): address to listen on.
- `-p, --port` (default `1080`): port to listen on.
- `-U, --user` (default `socker`): username, used when `-P` is set.
- `-P, --pass` (optional): password. Without it the proxy accepts unauthenticated connections.

The SOCKS5 implementation is [go-socks5](https://github.com/things-go/go-socks5) by thinkgos, built
on armon's original.

## Layout

    main.go               command dispatch and banner
    constants.go          banner
    internal/server       SSH server, host keys, auth, forwarding, daemon mode
    internal/client       SSH client
    internal/socks        SOCKS5 proxy
    internal/tunnel       forward parsing, piping, and the server-to-client dial channel
