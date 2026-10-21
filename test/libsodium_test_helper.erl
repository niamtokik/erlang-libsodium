%%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%%% vim: ts=4 sw=4 ft=erlang noet
%%%===================================================================
%%%
%%%===================================================================
-module(libsodium_test_helper).
-export([
  check/2,
  data_file/2,
  tv_file/2,
  tv_file_hex/2,
  tv_file_hex7/2,
  tv_file_hex8/2,
  vectors/1
]).
-include_lib("common_test/include/ct.hrl").
-include("libsodium_SUITE.hrl").

%%--------------------------------------------------------------------
%% @doc consults test vectors files, usually a list of `tuple()'.
%% @end
%%--------------------------------------------------------------------
-spec vectors(Config) -> Vectors when
	  Config :: proplists:proplists(),
	  Vectors :: [tuple()].

vectors(Config) ->
	DataDir = proplists:get_value(data_dir, Config),
	VectorFile = proplists:get_value(vector_file, Config),
	VectorPath = filename:join([DataDir, VectorFile]),
	{ok, Vectors} = file:consult(VectorPath),
	Vectors.

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
