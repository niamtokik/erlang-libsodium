%%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%%% vim: ts=4 sw=4 ft=erlang noet
-module(libsodium_pwhash_scrypt_SUITE).
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([pwhash_scrypt_key_derivation/1]).
-export([pwhash_scrypt_password_storage/1]).
-include_lib("common_test/include/ct.hrl").
-include("libsodium_SUITE.hrl").

all() ->
  [
			pwhash_scrypt_key_derivation,
			pwhash_scrypt_password_storage
  ].

pwhash_scrypt_key_derivation(Config) ->
	TV = ?config(tv, Config),
	pwhash_scrypt_key_derivation(TV, Config).

pwhash_scrypt_password_storage(Config) ->
	TV = ?config(tv3, Config),
	pwhash_scrypt_password_storage(TV, Config).

pwhash_scrypt_key_derivation([{Passwd, _Passwdlen, Salt, Outlen, Opslimit, Memlimit, Out} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_pwhash_scryptsalsa208sha256, crypto_pwhash_scryptsalsa208sha256, [Outlen, Passwd, Salt, Opslimit, Memlimit], Out),
	pwhash_scrypt_key_derivation(Vectors, Config);
pwhash_scrypt_key_derivation([], _Config) ->
	ok.

%% @private
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

