%%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%%% vim: ts=4 sw=4 ft=erlang noet
%%%===================================================================
%%% @doc
%%% @end
%%%===================================================================
-module(libsodium_sign_SUITE).
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).
-export([sign/1]).
-include_lib("common_test/include/ct.hrl").
-include("libsodium_SUITE.hrl").

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
all() ->
  [sign].

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
  _ = application:ensure_all_started(libsodium),
  Config.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
end_per_suite(Config) ->
  _ = application:stop(libsodium),
  Config.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
init_per_testcase(_, Config) ->
	[{vector_file, "sign.config"}|Config].

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
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
sign(Config) ->
	Vectors = libsodium_test_helper:vectors(Config),
	Converter = fun ({Seed, PK, Sig, M}) ->
		{
			binary:decode_hex(list_to_binary(Seed)),
			binary:decode_hex(list_to_binary(PK)),
			binary:decode_hex(list_to_binary(Sig)),
			binary:decode_hex(list_to_binary(M))
		}
	end,
	Converted = lists:map(Converter, Vectors),
	sign(Converted, Config).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
sign([], _Config) -> ok;
sign([{Seed, PK, Sig, M} | Vectors], Config) ->
	SK = << Seed/binary, PK/binary >>,
	SM = << Sig/binary, M/binary >>,
	?tv_ok(T0, libsodium_crypto_sign, crypto_sign, [M, SK], SM),
	?tv_ok(T1, libsodium_crypto_sign, open, [SM, PK], M),
	?tv_ok(T2, libsodium_crypto_sign, detached, [M, SK], Sig),
	?tv_ok(T3, libsodium_crypto_sign, verify_detached, [Sig, M, PK], 0),
	sign(Vectors, Config).
