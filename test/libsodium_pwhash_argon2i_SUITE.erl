%%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%%% vim: ts=4 sw=4 ft=erlang noet
-module(libsodium_pwhash_argon2i_SUITE).
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([pwhash_argon2i_key_derivation/1]).
-export([pwhash_argon2i_password_storage/1]).
-include_lib("common_test/include/ct.hrl").
-include("libsodium_SUITE.hrl").

all() ->
  [
			pwhash_argon2i_key_derivation,
			pwhash_argon2i_password_storage
  }.

groups() ->
  [].

pwhash_argon2i_key_derivation(Config) ->
	TV = ?config(tv, Config),
	pwhash_argon2i_key_derivation(TV, Config).

pwhash_argon2i_password_storage(Config) ->
	TV = ?config(tv3, Config),
	pwhash_argon2i_password_storage(TV, Config).

pwhash_argon2i_key_derivation([{Passwd, _Passwdlen, Salt, Outlen, Opslimit, Memlimit, Alg, Out} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_pwhash_argon2i, crypto_pwhash_argon2i, [Outlen, Passwd, Salt, Opslimit, Memlimit, Alg], Out),
	pwhash_argon2i_key_derivation(Vectors, Config);
pwhash_argon2i_key_derivation([{Passwd, _Passwdlen, Salt, Outlen} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_pwhash_argon2i, crypto_pwhash_argon2i, [Outlen, Passwd, Salt, 3, 1 bsl 12, 0], -1),
	?tv_ok(T1, libsodium_crypto_pwhash_argon2i, crypto_pwhash_argon2i, [Outlen, Passwd, Salt, 3, 1, libsodium_crypto_pwhash:alg_default()], -1),
	?tv_ok(T2, libsodium_crypto_pwhash_argon2i, crypto_pwhash_argon2i, [Outlen, Passwd, Salt, 3, 1 bsl 12, libsodium_crypto_pwhash:alg_default()], -1),
	?tv_ok(T3, libsodium_crypto_pwhash_argon2i, crypto_pwhash_argon2i, [Outlen, Passwd, Salt, 2, 1 bsl 12, libsodium_crypto_pwhash:alg_default()], -1),
	pwhash_argon2i_key_derivation(Vectors, Config);
pwhash_argon2i_key_derivation([], _Config) ->
	ok.

%% @private
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
