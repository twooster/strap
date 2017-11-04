defmodule StrapTest do
  use ExUnit.Case
  doctest Strap

  def to_bin(s) do
    {:ok, val} =
      s
      |> String.replace(~r/\s/m, "")
      |> Base.decode16()
    val
  end

  test "rfc5054" do
    # Taken directly from appendix B of RFC5054
    i = "alice"

    p = "password123"

    s =
      "BEB25379 D1A8581E B5A72767 3A2441EE"
      |> to_bin()


    # n =
    #   """
    #   EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
    #   9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
    #   8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
    #   7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
    #   FD5138FE 8376435B 9FC61D2F C0EB06E3
    #   """
    #   |> to_bin()

    # g = 2

    {n, g} = Strap.prime_group(1024)

    # Derived in-algorithm:
    #     k = 7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F
    #     x = 94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124

    v =
      """
      7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
      9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
      C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
      EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
      E955A5E2 9E7AB245 DB2BE315 E2099AFB
      """
      |> to_bin()

    a_priv =
      """
      60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD
      DA2D4393
      """
      |> to_bin()

    b_priv =
      """
      E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1
      05284D20
      """
      |> to_bin()

    a_pub =
      """
      61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
      4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
      8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
      BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
      B349EF5D 76988A36 72FAC47B 0769447B
      """
      |> to_bin()

    b_pub =
      """
      BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
      BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
      6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
      37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
      EB4012B7 D7665238 A8E3FB00 4B117B58
      """
      |> to_bin()

    # Derived in-algorithm:
    #     u = CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019

    key =
      """
      B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D
      233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C
      41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F
      3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D
      C346D7E4 74B29EDE 8A469FFE CA686E5A
      """
      |> to_bin()

    server =
      Strap.protocol(:srp6a, n, g, :sha)
      |> Strap.server(v, b_priv)

    client =
      Strap.protocol(:srp6a, n, g, :sha)
      |> Strap.client(i, p, s, a_priv)

    calc_b_pub = Strap.public_value(server)
    assert calc_b_pub == b_pub

    calc_a_pub = Strap.public_value(client)
    assert calc_a_pub == a_pub

    {:ok, client_key} = Strap.session_key(client, calc_b_pub)
    {:ok, server_key} = Strap.session_key(server, calc_a_pub)

    assert client_key == server_key
    assert key == client_key
  end
end
