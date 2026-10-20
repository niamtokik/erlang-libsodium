%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2015-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  14 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(libsodium_SUITE).

-include_lib("common_test/include/ct.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([check/2]).
-export([aead_chacha20poly1305/1]).
-export([aead_chacha20poly1305_check/1]).
-export([aead_chacha20poly1305_ietf/1]).
-export([box_check/1]).
-export([box_seal/1]).
-export([pwhash_argon2i_key_derivation/1]).
-export([pwhash_argon2i_password_storage/1]).
-export([pwhash_argon2id_key_derivation/1]).
-export([pwhash_argon2id_password_storage/1]).
-export([pwhash_scrypt_key_derivation/1]).
-export([pwhash_scrypt_password_storage/1]).
-include("libsodium_SUITE.hrl").

all() ->
	[
		{group, aead_chacha20poly1305},
		{group, box},
		{group, pwhash_argon2i},
		% {group, pwhash_argon2id},
		{group, pwhash_scrypt}
	].

groups() ->
	[
		{aead_chacha20poly1305, [parallel], [
			aead_chacha20poly1305,
			aead_chacha20poly1305_check,
			aead_chacha20poly1305_ietf
		]},
		{box, [parallel], [
			box_check,
			box_seal
		]},
		{pwhash_argon2i, [parallel], [
			pwhash_argon2i_key_derivation,
			pwhash_argon2i_password_storage
		]},
		{pwhash_argon2id, [parallel], [
			pwhash_argon2id_key_derivation,
			pwhash_argon2id_password_storage
		]},
		{pwhash_scrypt, [parallel], [
			pwhash_scrypt_key_derivation,
			pwhash_scrypt_password_storage
		]},
		{sign, [parallel], [
			sign
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(libsodium),
	Config.

end_per_suite(_Config) ->
	_ = application:stop(libsodium),
	ok.

init_per_group(Group, Config) ->
	init_group(Group, libsodium_ct:start(Group, Config)).

%% @private
init_group(aead_chacha20poly1305, Config) ->
	tv_file("aead_chacha20poly1305.config", Config) ++ Config;
init_group(pwhash_argon2i, Config) ->
	tv_file_hex("pwhash_argon2i.config", Config) ++ Config;
init_group(pwhash_argon2id, Config) ->
	tv_file_hex8("pwhash_argon2id.config", Config) ++ Config;
init_group(pwhash_scrypt, Config) ->
	tv_file_hex7("pwhash_scrypt.config", Config) ++ Config;
init_group(_, Config) ->
	Config.

end_per_group(_Group, Config) ->
	libsodium_ct:stop(Config),
	ok.

%%====================================================================
%% Tests
%%====================================================================

aead_chacha20poly1305(Config) ->
	TV = ?config(tv, Config),
	aead_chacha20poly1305(TV, Config).

aead_chacha20poly1305_check(_Config) ->
	check(libsodium_crypto_aead_chacha20poly1305, [
		{keybytes,       32},
		{nsecbytes,       0},
		{npubbytes,       8},
		{abytes,         16},
		{ietf_npubbytes, 12}
	]).

aead_chacha20poly1305_ietf(Config) ->
	TVIETF = ?config(tv_ietf, Config),
	aead_chacha20poly1305_ietf(TVIETF, Config).

box_check(_Config) ->
	check(libsodium_crypto_box, [
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

pwhash_argon2i_key_derivation(Config) ->
	TV = ?config(tv, Config),
	pwhash_argon2i_key_derivation(TV, Config).

pwhash_argon2i_password_storage(Config) ->
	TV = ?config(tv3, Config),
	pwhash_argon2i_password_storage(TV, Config).

pwhash_argon2id_key_derivation(Config) ->
	TV = ?config(tv, Config),
	pwhash_argon2id_key_derivation(TV, Config).

pwhash_argon2id_password_storage(Config) ->
	TV = ?config(tv3, Config),
	pwhash_argon2id_password_storage(TV, Config).

pwhash_scrypt_key_derivation(Config) ->
	TV = ?config(tv, Config),
	pwhash_scrypt_key_derivation(TV, Config).

pwhash_scrypt_password_storage(Config) ->
	TV = ?config(tv3, Config),
	pwhash_scrypt_password_storage(TV, Config).

%%%-------------------------------------------------------------------
%%% Internal Vector functions
%%%-------------------------------------------------------------------


%% @private
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

%% @private
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

%% @private
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

%% @private
pwhash_argon2id_key_derivation([{Passwd, _Passwdlen, Salt, Outlen, Opslimit, Memlimit, Alg, Out} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_pwhash_argon2id, crypto_pwhash_argon2id, [Outlen, Passwd, Salt, Opslimit, Memlimit, Alg], Out),
	pwhash_argon2id_key_derivation(Vectors, Config);
pwhash_argon2id_key_derivation([{Passwd, _Passwdlen, Salt, Outlen} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_pwhash_argon2id, crypto_pwhash_argon2id, [Outlen, Passwd, Salt, 3, 1 bsl 12, 0], -1),
	?tv_ok(T1, libsodium_crypto_pwhash_argon2id, crypto_pwhash_argon2id, [Outlen, Passwd, Salt, 3, 1, libsodium_crypto_pwhash:alg_default()], -1),
	?tv_ok(T2, libsodium_crypto_pwhash_argon2id, crypto_pwhash_argon2id, [Outlen, Passwd, Salt, 3, 1 bsl 12, libsodium_crypto_pwhash:alg_default()], -1),
	?tv_ok(T3, libsodium_crypto_pwhash_argon2id, crypto_pwhash_argon2id, [Outlen, Passwd, Salt, 2, 1 bsl 12, libsodium_crypto_pwhash:alg_default()], -1),
	pwhash_argon2id_key_derivation(Vectors, Config);
pwhash_argon2id_key_derivation([], _Config) ->
	ok.

%% @private
pwhash_argon2id_password_storage([{Passwd, Out, Verified} | Vectors], Config) ->
	?tv_ok(T0, libsodium_crypto_pwhash_argon2id, str_verify, [Out, Passwd], Verified),
	pwhash_argon2id_password_storage(Vectors, Config);
pwhash_argon2id_password_storage([], _Config) ->
	Passwd = <<"Correct Horse Battery Staple">>,
	Opslimit = 3,
	Memlimit = 5000000,
	T1 = ?tv_not(T0, libsodium_crypto_pwhash_argon2id, str, [Passwd, Opslimit, Memlimit], -1),
	T3 = ?tv_not(T2, libsodium_crypto_pwhash_argon2id, str, [Passwd, Opslimit, Memlimit], T1),
	_T5 = ?tv_not(T4, libsodium_crypto_pwhash_argon2id, str, [Passwd, Opslimit, Memlimit], T3),
	?tv_ok(T6, libsodium_crypto_pwhash_argon2id, str_verify, [T1, Passwd], 0),
	?tv_ok(T7, libsodium_crypto_pwhash_argon2id, str_verify, [T3, Passwd], 0),
	ok.

%% @private
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

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
check(Module, [{Function, Value} | Checks]) ->
	case Module:Function() of
		Value ->
			check(Module, Checks);
		Other ->
			ct:fail({{Module, Function, []}, {expected, Value}, {got, Other}})
	end;
check(_Module, []) ->
	ok.

%% @private
data_file(File, Config) ->
	filename:join([?config(data_dir, Config), File]).

%% @private
tv_file(Name, Config) ->
	File = data_file(Name, Config),
	case file:consult(File) of
		{ok, Terms} ->
			Terms;
		ConsultError ->
			erlang:error(ConsultError)
	end.

%% @private
tv_file_hex(Name, Config) ->
	[begin
		{Key, [begin
			list_to_tuple([begin
				case Val of
					_ when is_binary(Val) ->
						try
							hex:hex_to_bin(Val)
						catch
							_:_ ->
								Val
						end;
					_ when is_list(Val) ->
						try
							hex:hex_to_bin(Val)
						catch
							_:_ ->
								list_to_binary(Val)
						end;
					_ ->
						Val
				end
			end || Val <- tuple_to_list(Tuple)])
		end || Tuple <- List, is_tuple(Tuple)]}
	end || {Key, List} <- tv_file(Name, Config), is_list(List)].


tv_file_hex7(Name, Config) ->
	Proplist = tv_file(Name, Config),
	Map = fun({A,B,C,D,E,F,G}) ->
		{
			binary:decode_hex(list_to_binary(A)),
			binary:decode_hex(list_to_binary(B)),
			binary:decode_hex(list_to_binary(C)),
			binary:decode_hex(list_to_binary(D)),
			binary:decode_hex(list_to_binary(E)),
			binary:decode_hex(list_to_binary(F)),
			binary:decode_hex(list_to_binary(G))
		}
	end,
	[
		{Key, lists:map(Map, Terms)}
		|| {Key, Terms} <- Proplist
	].

tv_file_hex8(Name, Config) ->
	[{tv, Terms}] = tv_file(Name, Config),
	[{tv, lists:map(fun({A,B,C,D,E,F,G,H}) ->
		{
			binary:decode_hex(list_to_binary(A)),
			binary:decode_hex(list_to_binary(B)),
			binary:decode_hex(list_to_binary(C)),
			binary:decode_hex(list_to_binary(D)),
			binary:decode_hex(list_to_binary(E)),
			binary:decode_hex(list_to_binary(F)),
			binary:decode_hex(list_to_binary(G)),
			binary:decode_hex(list_to_binary(H))
		}
	end, Terms)}].
