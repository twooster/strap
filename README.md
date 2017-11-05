# Strap - SRP6/6a (Secure Remote Password) for Elixir

This is a simple module that helps you implement the Secure Remote Password
(SRP) protocol in Elixir applications. For more information about SRP, see
the [design documents](http://srp.stanford.edu/design.html) and
[RFC5054](https://tools.ietf.org/html/rfc5054).

[![Build Status](https://travis-ci.org/twooster/strap.svg?branch=master)](https://travis-ci.org/twooster/strap)
[![Hex.pm Version](http://img.shields.io/hexpm/v/strap.svg?style=flat)](https://hex.pm/packages/strap)

## Installation

This package can be installed by adding `strap` to your list of dependencies in
`mix.exs`:

```elixir
def deps do
  [
    {:strap, "~> 0.1.1"}
  ]
end
```

If you're running inside of a Phoenix application, you may need to ensure the
Erlang crypto application is loaded.

```elixir
def application do
  [
    extra_applications: [
      :logger,
      :crypto
    ]
  ]
end
```

## Documentation

The HexDocs.pm documentation is available [here](https://hexdocs.pm/strap).

## SRP Flow

A typical SRP request/response flow looks like this:

1. Client gets username/password from user

2. Client -> Server: Client sends the username to the server.

3. Server looks up the user's information, from a database for example.
   This information would be the prime, generator, salt, and so-called verifier
   value for this user. Optionally, if the server doesn't know this user, it
   may return/calculate fake values to obscure the user's lack-of-presence.

4. Server generates a public value, based on the prime, generator, verifier,
   and an ephemeral randomly-generated private value only it knows.

5. Server -> Client: Server sends the prime, generator, salt, and
   public value back to the client.

6. Client generates a public value, based on the prime, generator, and
   an ephemeral randomly-generated private value only it knows.

7. Client -> Server: Client sends its public value to the server.

8. Server generates a pre-shared master key based upon the information it has.

9. Client generates a pre-shared master key based upon the information it has.

The server and client should, at this point, verify that their pre-shared master
keys match. For example, the client could send a `HMAC(key, server-public-key)`
to the server, and the server could send `HMAC(key, client-public-key)` back
to the client.

Altenatively, if the preshared key will be utilized for further encrypted
communication, not just authentication, the server and the client can simply
exchange encrypted messages using an agreed-upon cipher (e.g. AES-256). A
failure to decrypt messages indicates a lack of knowledge of the preshared key.

## Usage

This library helps with steps 4, 6, 8, and 9, above. An example flow might look
like:

```elixir
# Client

username = get_username()
private_client_password = get_password()

# Server

# Fetch verifier and salt from database
{salt, private_server_verifier} = get_salt_and_verifier(username)
# Use "known-good" prime/generator; could also be stored in database
{prime, generator} = Strap.prime_group(2048)

server =
  Strap.protocol(:srp6a, prime, generator)
  |> Strap.server(verifier)

server_public_value = Strap.public_value(server)

# Client

client =
  Strap.protocol(:srp6a, prime, generator)
  |> Strap.client(username, private_client_password, salt)

client_public_vlaue = Strap.public_value(client)

# Server

{:ok, private_server_session_key} =
  Strap.session_key(server, client_public_value)

# Client

{:ok, private_client_session_key} =
  Strap.session_key(client, server_public_value)

# At this point, the following should be true:

^private_server_session_key = private_client_session_key
```
