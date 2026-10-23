%%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%%% vim: ts=4 sw=4 ft=erlang noet
%%%===================================================================
%%% @doc
%%% @end
%%%===================================================================
-module(libsodium_pwhash_argon2i_SUITE).
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([pwhash_argon2i_key_derivation/1]).
-export([pwhash_argon2i_key_derivation2/1]).
-export([pwhash_argon2i_password_storage/1]).
-include_lib("common_test/include/ct.hrl").
-include("libsodium_SUITE.hrl").

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
all() ->
  [
			pwhash_argon2i_key_derivation,
			pwhash_argon2i_key_derivation2,
			pwhash_argon2i_password_storage
  ].

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
groups() ->
  [].

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
init_per_testcase(pwhash_argon2i_key_derivation, Config) ->
	[{vector_file, "pwhash_argon2i.config"}|Config];
init_per_testcase(pwhash_argon2i_key_derivation2, Config) ->
	[{vector_file, "pwhash_argon2i_vector4.config"}|Config];
init_per_testcase(pwhash_argon2i_password_storage, Config) ->
	[{vector_file, "pwhash_argon2i_vector3.config"}|Config];
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
pwhash_argon2i_key_derivation(Config) ->
	Vectors = libsodium_test_helper:vectors(Config),
	Converter = fun ({Passwd, Passwdlen, Salt, Outlen, Opslimit, Memlimit, Alg, Out}) ->
		{
			binary:decode_hex(list_to_binary(Passwd)),
			Passwdlen,
			binary:decode_hex(list_to_binary(Salt)),
			Outlen,
			Opslimit,
			Memlimit,
			Alg,
			begin
				case Out of
					-1 -> -1;
					_ -> binary:decode_hex(list_to_binary(Out))
				end
			end
		}
	end,
	Converted = lists:map(Converter, Vectors),
	pwhash_argon2i_key_derivation(Converted, Config).

pwhash_argon2i_key_derivation([], _Config) -> ok;
pwhash_argon2i_key_derivation([{Passwd, _Passwdlen, Salt, Outlen, Opslimit, Memlimit, Alg, Out} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_pwhash_argon2i, crypto_pwhash_argon2i, [Outlen, Passwd, Salt, Opslimit, Memlimit, Alg], Out),
	pwhash_argon2i_key_derivation(Vectors, Config).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
pwhash_argon2i_key_derivation2(Config) ->
	Vectors = libsodium_test_helper:vectors(Config),
	Converter = fun({Passwd, PasswdLen, Salt, OutLen}) ->
		{
			binary:decode_hex(list_to_binary(Passwd)),
			PasswdLen,
			binary:decode_hex(list_to_binary(Salt)),
			OutLen
		}
	end,
	Converted = lists:map(Converter, Vectors),
	pwhash_argon2i_key_derivation2(Converted, Config).

pwhash_argon2i_key_derivation2([], _Config) -> ok;
pwhash_argon2i_key_derivation2([{Passwd, _Passwdlen, Salt, Outlen} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_pwhash_argon2i, crypto_pwhash_argon2i, [Outlen, Passwd, Salt, 3, 1 bsl 12, 0], -1),
	?tv_ok(T1, libsodium_crypto_pwhash_argon2i, crypto_pwhash_argon2i, [Outlen, Passwd, Salt, 3, 1, libsodium_crypto_pwhash:alg_default()], -1),
	?tv_ok(T2, libsodium_crypto_pwhash_argon2i, crypto_pwhash_argon2i, [Outlen, Passwd, Salt, 3, 1 bsl 12, libsodium_crypto_pwhash:alg_default()], -1),
	?tv_ok(T3, libsodium_crypto_pwhash_argon2i, crypto_pwhash_argon2i, [Outlen, Passwd, Salt, 2, 1 bsl 12, libsodium_crypto_pwhash:alg_default()], -1),
	pwhash_argon2i_key_derivation2(Vectors, Config).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
pwhash_argon2i_password_storage(Config) ->
	Vectors = libsodium_test_helper:vectors(Config),
	Converter = fun ({Passwd, Out, Verified}) ->
		{
			list_to_binary(Passwd),
			list_to_binary(Out),
			Verified
		}
	end,
	Converted = lists:map(Converter, Vectors),
	pwhash_argon2i_password_storage(Converted, Config).

pwhash_argon2i_password_storage([{Passwd, Out, Verified} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_pwhash_argon2i, str_verify, [Out, Passwd], Verified),
	pwhash_argon2i_password_storage(Vectors, Config);
pwhash_argon2i_password_storage([], _Config) ->
	Passwd = <<"Correct Horse Battery Staple">>,
	Opslimit = 3,
	Memlimit = 5000000,
	T1 = ?tv_not(T0, libsodium_crypto_pwhash_argon2i, str, [Passwd, Opslimit, Memlimit], -1),
	T3 = ?tv_not(T2, libsodium_crypto_pwhash_argon2i, str, [Passwd, Opslimit, Memlimit], T1),
	_T5 = ?tv_not(T4, libsodium_crypto_pwhash_argon2i, str, [Passwd, Opslimit, Memlimit], T3),
	?tv_ok(T6, libsodium_crypto_pwhash_argon2i, str_verify, [T1, Passwd], 0),
	?tv_ok(T7, libsodium_crypto_pwhash_argon2i, str_verify, [T3, Passwd], 0),
	ok.
