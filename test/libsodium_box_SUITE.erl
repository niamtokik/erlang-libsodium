%%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%%% vim: ts=4 sw=4 ft=erlang noet
-module(libsodium_box_SUITE).
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([box_check/1]).
-export([box_seal/1]).
-include_lib("common_test/include/ct.hrl").
-include("libsodium_SUITE.hrl").

all() -> 
  [
    box_check,
    box_seal
  ].

groups() -> [].

init_per_suite(Config) ->
  Config.

end_per_suite(_Config) ->
  ok.

init_per_group(_Group, Config) ->
  Config.

end_per_group(_Group, _Config) ->
  ok.

box_check(_Config) ->
	libsodium_test_helper:check(libsodium_crypto_box, [
		{seedbytes,      32},
		{publickeybytes, 32},
		{secretkeybytes, 32},
		{noncebytes,     24},
		{macbytes,       16},
		{primitive,      curve25519xsalsa20poly1305},
		{beforenmbytes,  32},
		{sealbytes,      48},
		{zerobytes,      32},
		{boxzerobytes,   16}
	]).

box_seal(_Config) ->
	{PK, SK} = libsodium_crypto_box:keypair(),
	MLen = libsodium_randombytes:uniform(1000),
	_CLen = libsodium_crypto_box:sealbytes() + MLen,
	M = libsodium_randombytes:buf(MLen),
	C = ?tv_not(T0, libsodium_crypto_box, seal, [M, PK], -1),
	?tv_ok(T1, libsodium_crypto_box, seal_open, [C, PK, SK], M),
	?tv_badarg(T2, libsodium_crypto_box, seal_open, [<<>>, PK, SK]),
	?tv_ok(T3, libsodium_crypto_box, seal_open, [binary:part(C, 0, byte_size(C) - 1), PK, SK], -1),
	ok.
