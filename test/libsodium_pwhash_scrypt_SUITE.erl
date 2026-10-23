%%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%%% vim: ts=4 sw=4 ft=erlang noet
-module(libsodium_pwhash_scrypt_SUITE).
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([pwhash_scrypt_key_derivation/1]).
-export([pwhash_scrypt_password_storage/1]).
-include_lib("common_test/include/ct.hrl").
-include("libsodium_SUITE.hrl").

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
all() ->
  [
			pwhash_scrypt_key_derivation,
			pwhash_scrypt_password_storage
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

init_per_testcase(pwhash_scrypt_key_derivation, Config) ->
	[{vector_file, "pwhash_scrypt.config"}|Config];
init_per_testcase(pwhash_scrypt_password_storage, Config) ->
	[{vector_file, "pwhash_scrypt_vector3.config"}|Config];
init_per_testcase(_, Config) ->
	Config.

end_per_testcase(_, _) -> ok.

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
pwhash_scrypt_key_derivation(Config) ->
	Vectors = libsodium_test_helper:vectors(Config),
	Converter = fun ({Passwd, Passwdlen, Salt, Outlen, Opslimit, Memlimit, Out}) ->
		{
			binary:decode_hex(list_to_binary(Passwd)),
			Passwdlen,
			binary:decode_hex(list_to_binary(Salt)),
			Outlen,
			Opslimit,
			Memlimit,
			binary:decode_hex(list_to_binary(Out))
		}
	end,
	Converted = lists:map(Converter, Vectors),
	pwhash_scrypt_key_derivation(Converted, Config).

pwhash_scrypt_key_derivation([{Passwd, _Passwdlen, Salt, Outlen, Opslimit, Memlimit, Out} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256, [Outlen, Passwd, Salt, Opslimit, Memlimit], Out),
	pwhash_scrypt_key_derivation(Vectors, Config);
pwhash_scrypt_key_derivation([], _Config) ->
	ok.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
pwhash_scrypt_password_storage(Config) ->
	Vectors = libsodium_test_helper:vectors(Config),
	Converter = fun ({Passwd, Out, Verified}) ->
		{
			list_to_binary(Passwd),
			list_to_binary(Out),
			Verified
		}
	end,
	Converted = lists:map(Converter, Vectors),
	pwhash_scrypt_password_storage(Converted, Config).

pwhash_scrypt_password_storage([{Passwd, Out, Verified} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_pwhash_scryptsalsa208sha256, str_verify, [Out, Passwd], Verified),
	pwhash_scrypt_password_storage(Vectors, Config);
pwhash_scrypt_password_storage([], _Config) ->
	Passwd = <<"Correct Horse Battery Staple">>,
	Opslimit = 1000000,
	Memlimit = 10000000,
	T1 = ?tv_not(T0, libsodium_crypto_pwhash_scryptsalsa208sha256, str, [Passwd, Opslimit, Memlimit], -1),
	T3 = ?tv_not(T2, libsodium_crypto_pwhash_scryptsalsa208sha256, str, [Passwd, Opslimit, Memlimit], T1),
	?tv_ok(T4, libsodium_crypto_pwhash_scryptsalsa208sha256, str_verify, [T1, Passwd], 0),
	?tv_ok(T5, libsodium_crypto_pwhash_scryptsalsa208sha256, str_verify, [T3, Passwd], 0),
	ok.

