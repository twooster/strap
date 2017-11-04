defmodule Strap do
  @moduledoc """
  A module for using SRP (Secure Remote Password) versions 6 and 6a in Elixir.
  """

  @type hash_fn :: (iodata -> binary)
  @type hash_types :: :sha | :sha256 | atom
  @type srp_version :: :srp6 | :srp6a
  @type protocol :: {srp_version, binary, non_neg_integer, non_neg_integer, hash_fn}
  @type client :: {:client, protocol, non_neg_integer, non_neg_integer, non_neg_integer}
  @type server :: {:server, protocol, non_neg_integer, non_neg_integer, non_neg_integer}
  @type bin_number :: non_neg_integer | binary

  @doc """
  Creates a protocol structure.

  ## Parameters

    - srp_version: Either `:srp6` or `:srp6a`
    - prime: A binary string representing the prime `N` value
    - generator: The generator `g` integer
    - hash: One of the hash atoms supported by `:crypto.hash/2` or a
        `fn/1` that takes an `t:iodata` value and returns a binary
        hash of that value.

  ## Returns

  A protocol structure, for use in `server/3` or `client/5`.
  """
  @spec protocol(srp_version, binary, bin_number, hash_types) :: protocol
  def protocol(version, prime, generator, hash \\ :sha)
  when version in [:srp6, :srp6a] do
    hash = hash_fn(hash)

    k = gen_k(version, prime, generator, hash)
    g = to_int(generator)

    {version, prime, g, k, hash}
  end

  @doc """
  Creates a server structure.

  ## Parameters

    - protocol: a protocol structure created by `protocol/4`.
    - verifier: the verifier value, either `t:integer` or `t:binary`.
    - private: the private key for the server; if not provided, a
        256-bit secure random value will be generated.

  ## Returns

  A server structure, for use with `public_key/1` and `session_key/2`.
  """
  @spec server(protocol, bin_number, bin_number) :: server
  def server(protocol, verifier, private \\ rand_bytes()) do
    v = to_int(verifier)
    b_priv = to_int(private)
    b_pub = gen_b_pub(protocol, v, b_priv)

    {:server, protocol, v, b_priv, b_pub}
  end

  @doc """
  Creates a client structure.

  ## Parameters

    - protocol: a protocol structure created by `protocol/4`.
    - username: a `t:String.t` or `t:binary` username.
    - password: a `t:String.t` or `t:binary` password.
    - salt: the salt, `t:String.t` or `t:binary`, as provided from
        the server.
    - private: the private key for the client; if not provided, a
        256-bit secure random value will be generated.

  ## Returns

  A client structure, for use with `public_key/1` and `session_key/2`.

  ## Notes

  The username and password are not stored in the resulting structure,
  but a hash of their values _is_ stored.
  """
  @spec client(protocol, binary, binary, bin_number, bin_number) :: client
  def client(protocol, username, password, salt, private \\ rand_bytes()) do
    {_ver, _n, _g, _k, hash} = protocol
    x = gen_x(username, password, salt, hash)

    a_priv = to_int(private)
    a_pub = gen_a_pub(protocol, a_priv)

    {:client, protocol, x, a_priv, a_pub}
  end

  @doc """
  Returns the public key for a given client or server.

  ## Parameters

    - client_server: either a client or server structure, from which
        the public key will be produced.

  ## Returns

  A binary representation of the public key.
  """
  @spec public_value(client | server) :: binary
  def public_value({:client, _proto, _x, _a_priv, a_pub}), do: to_bin(a_pub)
  def public_value({:server, _proto, _v, _b_priv, b_pub}), do: to_bin(b_pub)

  @doc """
  Generates a session key for communication with the remote counterparty.

  ## Parameters

  - client_server: either a client or server structure.
  - counterparty_public: the counterparty's public value.

  ## Returns

  Either:

  - `{:ok, session_key}`: if the session key creation was successful
  - `{:error, reason}`: if the session key creation was unsuccesful

  Session key creation can be unsuccessful if certain mathematical properties
  do not hold, compromising the security of unshared secrets or future
  communication.
  """
  @spec session_key(client | server, bin_number) :: {:error, atom}  | {:ok, binary}
  def session_key({:server, protocol, v, b_priv, b_pub}, client_public) do
    # u = SHA1(PAD(A) | PAD(B))
    # <premaster secret> = (A * v^u) ^ b % N
    {_ver, n, _g, _k, hash} = protocol
    n_int = to_int(n)
    a_pub = to_int(client_public)
    case rem(a_pub, n_int) do
      0 -> {:error, :invalid_parameters}
      _ ->
        u = gen_u(n, a_pub, b_pub, hash)
        case u do
          0 -> {:error, :invalid_parameters}
          _ ->
            v_exp_u = to_int(pow_mod(v, u, n))
            key = pow_mod(a_pub * v_exp_u, b_priv, n)

            {:ok, key}
        end
    end
  end

  def session_key({:client, protocol, x, a_priv, a_pub}, server_public) do
    # RFC5054
    # <premaster secret> = (B - (k * g^x)) ^ (a + (u * x)) % N
    {_ver, n, g, k, hash} = protocol
    n_int = to_int(n)
    b_pub = to_int(server_public)
    case rem(b_pub, n_int) do
      0 -> {:error, :invalid_parameters}
      _ ->
        u = gen_u(n, a_pub, b_pub, hash)
        case u do
          0 -> {:error, :invalid_parameters}
          _ ->
            base = b_pub + n_int - rem(k * to_int(pow_mod(g, x, n)), n_int)
            exp = a_priv + u * x
            key = pow_mod(base, exp, n)

            {:ok, key}
        end
    end
  end

  @doc """
  Creates a verifier value that could be sent to the server, e.g.
  during account creation, without ever sharing the user password.

  ## Parameters

  - client: a client, created previously.

  ## Returns

  A binary string of the verifier.
  """
  @spec verifier(client) :: binary
  def verifier({:client, protocol, x, _a_priv, _a_pub}) do
    # x = SHA1(s | SHA1(I | ":" | P))
    # v = g^x % N

    {_ver, n, g, _k, _hash} = protocol
    pow_mod(g, x, n)
  end

  @doc """
  Same as `verifier/1`, but can be used only with a protocol,
  not a full client. Could be used, e.g. on the server if
  the server is supposed to verify characteristics of the user's
  password before creating a verifier.

  ## Parameters

  - protocol: a protocol object created with `protocol/4`.
  - username: the username.
  - password: the password.
  - salt: the salt.

  ## Returns

  A binary string of the verifier.
  """
  @spec verifier(protocol, binary, binary, bin_number) :: binary
  def verifier(protocol, username, password, salt) do
    {_ver, n, g, _k, hash} = protocol

    x = gen_x(username, password, salt, hash)
    pow_mod(g, x, n)
  end

  # Helper macro to convert large string-formatted hex values to
  # binstrings at compile time
  @spec hex_to_bin(String.t) :: binary
  defmacrop hex_to_bin(hex) do
    {:ok, val} =
      hex
      |> String.replace(~r/\s/m, "")
      |> String.upcase()
      |> Base.decode16()
    val
  end

  @doc """
  Returns known-good primes and generators as defined in RFC5054.

  The following bit-sizes are defined: 1024, 1536, 2048, 3072, 4096,
  6144, 8192.


  ## Parameters

    - bit_size: the size in bits of the prime group

  ## Returns

  Tuple of the form `{<<prime :: binary>>, generator}`
  """
  @spec prime_group(pos_integer) :: {binary, pos_integer}
  def prime_group(1024) do
    {
      hex_to_bin("""
        EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
        9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
        8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
        7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
        FD5138FE 8376435B 9FC61D2F C0EB06E3
      """),
      2
    }
  end

  def prime_group(1536) do
    {
      hex_to_bin("""
        9DEF3CAF B939277A B1F12A86 17A47BBB DBA51DF4 99AC4C80 BEEEA961
        4B19CC4D 5F4F5F55 6E27CBDE 51C6A94B E4607A29 1558903B A0D0F843
        80B655BB 9A22E8DC DF028A7C EC67F0D0 8134B1C8 B9798914 9B609E0B
        E3BAB63D 47548381 DBC5B1FC 764E3F4B 53DD9DA1 158BFD3E 2B9C8CF5
        6EDF0195 39349627 DB2FD53D 24B7C486 65772E43 7D6C7F8C E442734A
        F7CCB7AE 837C264A E3A9BEB8 7F8A2FE9 B8B5292E 5A021FFF 5E91479E
        8CE7A28C 2442C6F3 15180F93 499A234D CF76E3FE D135F9BB
      """),
      2
    }
  end

  def prime_group(2048) do
    {
      hex_to_bin("""
        AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294
        3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D
        CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB
        D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
        7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A
        436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D
        5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73
        03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
        94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F
        9E4AFF73
      """),
      2
    }
  end

  def prime_group(3072) do
    {
      hex_to_bin("""
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
        8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
        302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
        A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
        49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
        FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
        180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
        3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
        04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
        B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
        1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
        BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
        E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
      """),
      5
    }
  end

  def prime_group(4096) do
    {
      hex_to_bin("""
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
        8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
        302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
        A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
        49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
        FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
        180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
        3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
        04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
        B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
        1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
        BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
        E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
        99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
        04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
        233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
        D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
        FFFFFFFF FFFFFFFF
      """),
      5
    }
  end

  def prime_group(6144) do
    {
      hex_to_bin("""
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
        8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
        302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
        A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
        49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
        FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
        180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
        3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
        04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
        B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
        1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
        BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
        E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
        99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
        04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
        233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
        D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
        36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406
        AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918
        DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151
        2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03
        F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F
        BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
        CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B
        B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632
        387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E
        6DCC4024 FFFFFFFF FFFFFFFF
      """),
      5
    }
  end

  def prime_group(8192) do
    {
      hex_to_bin("""
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
        8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
        302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
        A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
        49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
        FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
        180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
        3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
        04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
        B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
        1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
        BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
        E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
        99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
        04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
        233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
        D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
        36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406
        AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918
        DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151
        2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03
        F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F
        BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
        CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B
        B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632
        387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E
        6DBE1159 74A3926F 12FEE5E4 38777CB6 A932DF8C D8BEC4D0 73B931BA
        3BC832B6 8D9DD300 741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C
        5AE4F568 3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9
        22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B 4BCBC886
        2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A 062B3CF5 B3A278A6
        6D2A13F8 3F44F82D DF310EE0 74AB6A36 4597E899 A0255DC1 64F31CC5
        0846851D F9AB4819 5DED7EA1 B1D510BD 7EE74D73 FAF36BC3 1ECFA268
        359046F4 EB879F92 4009438B 481C6CD7 889A002E D5EE382B C9190DA6
        FC026E47 9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71
        60C980DD 98EDD3DF FFFFFFFF FFFFFFFF
      """),
      19
    }
  end

  # Internal functions

  @spec gen_a_pub(protocol, non_neg_integer) :: pos_integer
  defp gen_a_pub({_ver, n, g, _k, _hash}, a_priv) do
    # A = g^a % N
    pow_mod(g, a_priv, n)
    |> to_int()
  end

  @spec gen_b_pub(protocol, non_neg_integer, non_neg_integer) :: pos_integer
  defp gen_b_pub({_ver, n, g, k, _hash}, v, b_priv) do
    # B = k*v + g^b % N
    n_int = to_int(n)
    rem(k * v + to_int(pow_mod(g, b_priv, n)), n_int)
  end

  @spec gen_k(srp_version, binary, pos_integer, hash_fn) :: non_neg_integer
  defp gen_k(:srp6, _n, _g, _hash) do
    # http://srp.stanford.edu/design.html
    # k = 3 for legacy SRP-6
    3
  end

  defp gen_k(:srp6a, n, g, hash) do
    # RFC5054
    # k = hash(N | PAD(g))
    hash.([n, lpad_match(to_bin(g), n)])
    |> to_int()
  end

  @spec gen_x(binary, binary, binary, hash_fn) :: non_neg_integer
  defp gen_x(i, p, s, hash) do
    # RFC5054
    # x = hash(s | SHA1(I | ":" | P))
    hash.([s, hash.([i, ":", p])])
    |> to_int()
  end

  @spec gen_u(binary, non_neg_integer, non_neg_integer, hash_fn) :: non_neg_integer
  defp gen_u(n, a_pub, b_pub, hash) do
    # RFC5054
    # u = hash(PAD(A) | PAD(B))
    hash.([lpad_match(to_bin(a_pub), n),
           lpad_match(to_bin(b_pub), n)])
    |> to_int()
  end

  @spec lpad_match(binary, binary) :: binary
  defp lpad_match(data, other) do
    lpad_size(data, bit_size(other))
  end

  @spec lpad_size(binary, pos_integer) :: binary
  defp lpad_size(data, width) when bit_size(data) <= width do
    padding = width - bit_size(data)
    <<0 :: size(padding), data :: binary>>
  end

  # Helpers

  # Converts an atom (or function) into a hashing function
  @spec hash_fn(atom | (iodata -> binary)) :: (iodata -> binary)
  defp hash_fn(h) when is_atom(h), do: fn x -> :crypto.hash(h, x) end
  defp hash_fn(h) when is_function(h), do: h

  # Sugar
  @spec pow_mod(bin_number, bin_number, bin_number) :: binary
  defp pow_mod(n, e, m), do: :crypto.mod_pow(n, e, m)

  # Sugar
  @spec rand_bytes(pos_integer) :: binary
  defp rand_bytes(size \\ 32), do: :crypto.strong_rand_bytes(size)

  @spec to_bin(non_neg_integer | binary) :: binary
  defp to_bin(val) when is_bitstring(val), do: val
  defp to_bin(val) when is_integer(val), do: :binary.encode_unsigned(val)

  @spec to_int(binary | non_neg_integer) :: non_neg_integer
  defp to_int(val) when is_integer(val), do: val
  defp to_int(val) when is_bitstring(val), do: :binary.decode_unsigned(val)
end
