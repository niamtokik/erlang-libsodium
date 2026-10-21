%%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%%% vim: ts=4 sw=4 ft=erlang noet
-module(libsodium_aead_aes256gcm_SUITE).
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([aead_aes256gcm/1]).
-export([aead_aes256gcm_check/1]).
-include_lib("common_test/include/ct.hrl").
-include("libsodium_SUITE.hrl").

all() ->
  [aead_aes256gcm].

groups() ->
  [].

init_per_suite(Config) ->
  _ = application:ensure_all_started(libsodium),
  tv_file_hex6([{config_file, "aead_aes256gcm.config"}|Config]).

end_per_suite(Config) ->
  _ = application:stop(libsodium),
  Config.

init_per_group(_Group, Config) ->
  Config.

end_per_group(_Group, _Config) ->
  ok.

aead_aes256gcm(Config) ->
	case libsodium_crypto_aead_aes256gcm:is_available() of
		1 ->
			Vectors = ?config(vectors, Config),
			aead_aes256gcm(Vectors, Config);
		_ ->
			ct:log("aead_aes256gcm is not available, skipping..."),
			ok
	end.

aead_aes256gcm_check(_Config) ->
	case libsodium_crypto_aead_aes256gcm:is_available() of
		1 ->
			libsodium_test_helper:check(libsodium_crypto_aead_aes256gcm, [
				{keybytes,    32},
				{nsecbytes,    0},
				{npubbytes,   12},
				{abytes,      16},
				{statebytes, 512}
			]);
		_ ->
			ct:log("aead_aes256gcm is not available, skipping..."),
			ok
	end.

aead_aes256gcm([{Key, Nonce, Message, Ad, Ciphertext, Mac} | Vectors], Config) ->
	ExpectedCiphertext = << Ciphertext/binary, Mac/binary >>,
	TruncatedCiphertext = binary:part(ExpectedCiphertext, 0, libsodium_randombytes:uniform(byte_size(ExpectedCiphertext))),
	TruncatedTag = binary:part(ExpectedCiphertext, 0, libsodium_randombytes:uniform(libsodium_crypto_aead_aes256gcm:abytes())),
	TruncatedDetachedMac = binary:part(Mac, 0, libsodium_randombytes:uniform(byte_size(Mac))),
	?tv_ok(T0, libsodium_crypto_aead_aes256gcm, encrypt, [Message, Ad, Nonce, Key], ExpectedCiphertext),
	?tv_ok(T1, libsodium_crypto_aead_aes256gcm, decrypt, [TruncatedCiphertext, Ad, Nonce, Key], -1),
	?tv_ok(T2, libsodium_crypto_aead_aes256gcm, decrypt, [TruncatedTag, Ad, Nonce, Key], -1),
	?tv_ok(T3, libsodium_crypto_aead_aes256gcm, decrypt, [ExpectedCiphertext, Ad, Nonce, Key], Message),
	?tv_ok(T4, libsodium_crypto_aead_aes256gcm, encrypt_detached, [Message, Ad, Nonce, Key], {Ciphertext, Mac}),
	?tv_badarg(T6, libsodium_crypto_aead_aes256gcm, decrypt_detached, [Ciphertext, TruncatedDetachedMac, Ad, Nonce, Key]),
	?tv_ok(T7, libsodium_crypto_aead_aes256gcm, decrypt_detached, [Ciphertext, Mac, Ad, Nonce, Key], Message),
	aead_aes256gcm(Vectors, Config);
aead_aes256gcm([], _Config) ->
	ok.

tv_file_hex6(Config) ->
  Filename = ?config(config_file, Config),
  File = filename:join([?config(data_dir, Config), Filename]),
  {ok, [{vectors, Terms}]} = file:consult(File),
  Fun = fun({A,B,C,D,E,F}) ->
		{
			binary:decode_hex(list_to_binary(A)),
			binary:decode_hex(list_to_binary(B)),
			binary:decode_hex(list_to_binary(C)),
			binary:decode_hex(list_to_binary(D)),
			binary:decode_hex(list_to_binary(E)),
			binary:decode_hex(list_to_binary(F))
		}
  end,
  [{vectors, lists:map(Fun, Terms)}|Config].
