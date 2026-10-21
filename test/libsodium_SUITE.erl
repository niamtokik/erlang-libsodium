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
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-include_lib("common_test/include/ct.hrl").
-include("libsodium_SUITE.hrl").

all() -> [].

groups() -> [].

init_per_suite(Config) ->
	_ = application:ensure_all_started(libsodium),
	Config.

end_per_suite(_Config) ->
	_ = application:stop(libsodium),
	ok.

init_per_group(Group, Config) ->
	init_group(Group, libsodium_ct:start(Group, Config)).

init_group(_, Config) ->
	Config.

end_per_group(_Group, Config) ->
	libsodium_ct:stop(Config),
	ok.
