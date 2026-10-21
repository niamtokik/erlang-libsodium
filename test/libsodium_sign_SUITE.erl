%%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%%% vim: ts=4 sw=4 ft=erlang noet
-module(libsodium_sign_SUITE).
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([sign/1]).
-include_lib("common_test/include/ct.hrl").
-include("libsodium_SUITE.hrl").

all() ->
  [
    sign
  ].

groups() ->
  [].

init_per_suite(Config) ->
  _ = application:ensure_all_started(libsodium),
  tv_file_hex4([{config_file, "sign.config"}|Config]).

end_per_suite(Config) ->
  _ = application:stop(libsodium),
  Config.

init_per_group(_Group, Config) ->
  Config.

end_per_group(_Group, _Config) ->
  ok.

sign(Config) ->
	TV = ?config(tv, Config),
	sign(TV, Config).

sign([{Seed, PK, Sig, M} | Vectors], Config) ->
	SK = << Seed/binary, PK/binary >>,
	SM = << Sig/binary, M/binary >>,
	?tv_ok(T0, libsodium_crypto_sign, crypto_sign, [M, SK], SM),
	?tv_ok(T1, libsodium_crypto_sign, open, [SM, PK], M),
	?tv_ok(T2, libsodium_crypto_sign, detached, [M, SK], Sig),
	?tv_ok(T3, libsodium_crypto_sign, verify_detached, [Sig, M, PK], 0),
	sign(Vectors, Config);
sign([], _Config) ->
	ok.

tv_file_hex4(Config) ->
  Filename = ?config(config_file, Config),
  File = filename:join([?config(data_dir, Config), Filename]),
  {ok, [{tv, Terms}]} = file:consult(File),
	[{tv, lists:map(fun({A,B,C,D}) ->
		{
			binary:decode_hex(list_to_binary(A)),
			binary:decode_hex(list_to_binary(B)),
			binary:decode_hex(list_to_binary(C)),
			binary:decode_hex(list_to_binary(D))
		}
	end, Terms)}].
