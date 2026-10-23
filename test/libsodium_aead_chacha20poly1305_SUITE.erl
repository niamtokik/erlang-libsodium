%%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%%% vim: ts=4 sw=4 ft=erlang noet
%%%===================================================================
%%%
%%%===================================================================
-module(libsodium_aead_chacha20poly1305_SUITE).
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([aead_chacha20poly1305/1]).
-export([aead_chacha20poly1305_check/1]).
-export([aead_chacha20poly1305_ietf/1]).
-include_lib("common_test/include/ct.hrl").
-include("libsodium_SUITE.hrl").

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
all() ->
  [
			aead_chacha20poly1305,
			aead_chacha20poly1305_check,
			aead_chacha20poly1305_ietf
  ].

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
groups() -> [].

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
init_per_suite(Config) ->
  Config.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
end_per_suite(_Config) ->
  ok.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
init_per_testcase(aead_chacha20poly1305, Config) ->
	[{vector_file, "aead_chacha20poly1305.config"}|Config];
init_per_testcase(aead_chacha20poly1305_ietf, Config) ->
	[{vector_file, "aead_chacha20poly1305_ietf.config"}|Config];
init_per_testcase(_, Config) ->
	Config.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
end_per_testcase(_, _) ->
	ok.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
init_per_group(_Group, Config) ->
  Config.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
end_per_group(_Group, _Config) ->
  ok.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
aead_chacha20poly1305_check(_Config) ->
	libsodium_test_helper:check(libsodium_crypto_aead_chacha20poly1305, [
		{keybytes,       32},
		{nsecbytes,       0},
		{npubbytes,       8},
		{abytes,         16},
		{ietf_npubbytes, 12}
	]).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
aead_chacha20poly1305(Config) ->
	Vectors = libsodium_test_helper:vectors(Config),
	aead_chacha20poly1305(Vectors, Config).

aead_chacha20poly1305([{K, M, NPub, AD, C, CNoAD} | Vectors], Config) ->
	MLen = byte_size(M),
	<< CD:MLen/binary, MAC/binary >> = C,
	TruncatedMAC = binary:part(MAC, 0, libsodium_randombytes:uniform(byte_size(MAC))),
	?tv_ok(T0, libsodium_crypto_aead_chacha20poly1305, encrypt, [M, AD, NPub, K], C),
	?tv_ok(T1, libsodium_crypto_aead_chacha20poly1305, encrypt, [M, NPub, K], CNoAD),
	?tv_ok(T2, libsodium_crypto_aead_chacha20poly1305, decrypt, [C, AD, NPub, K], M),
	?tv_ok(T3, libsodium_crypto_aead_chacha20poly1305, decrypt, [CNoAD, NPub, K], M),
	?tv_ok(T4, libsodium_crypto_aead_chacha20poly1305, encrypt_detached, [M, AD, NPub, K], {CD, MAC}),
	?tv_badarg(T5, libsodium_crypto_aead_chacha20poly1305, decrypt_detached, [CD, TruncatedMAC, AD, NPub, K]),
	?tv_ok(T6, libsodium_crypto_aead_chacha20poly1305, decrypt_detached, [CD, MAC, AD, NPub, K], M),
	aead_chacha20poly1305(Vectors, Config);
aead_chacha20poly1305([], _Config) ->
	ok.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
aead_chacha20poly1305_ietf(Config) ->
	Vectors = libsodium_test_helper:vectors(Config),
	aead_chacha20poly1305_ietf(Vectors, Config).

aead_chacha20poly1305_ietf([{K, M, NPub, AD, C, CNoAD} | Vectors], Config) ->
	MLen = byte_size(M),
	<< CD:MLen/binary, MAC/binary >> = C,
	TruncatedMAC = binary:part(MAC, 0, libsodium_randombytes:uniform(byte_size(MAC))),
	?tv_ok(T0, libsodium_crypto_aead_chacha20poly1305, ietf_encrypt, [M, AD, NPub, K], C),
	?tv_ok(T1, libsodium_crypto_aead_chacha20poly1305, ietf_encrypt, [M, NPub, K], CNoAD),
	?tv_ok(T2, libsodium_crypto_aead_chacha20poly1305, ietf_decrypt, [C, AD, NPub, K], M),
	?tv_ok(T3, libsodium_crypto_aead_chacha20poly1305, ietf_decrypt, [CNoAD, NPub, K], M),
	?tv_ok(T4, libsodium_crypto_aead_chacha20poly1305, ietf_encrypt_detached, [M, AD, NPub, K], {CD, MAC}),
	?tv_badarg(T5, libsodium_crypto_aead_chacha20poly1305, ietf_decrypt_detached, [CD, TruncatedMAC, AD, NPub, K]),
	?tv_ok(T6, libsodium_crypto_aead_chacha20poly1305, ietf_decrypt_detached, [CD, MAC, AD, NPub, K], M),
	aead_chacha20poly1305_ietf(Vectors, Config);
aead_chacha20poly1305_ietf([], _Config) ->
  ok.
