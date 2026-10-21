%%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%%% vim: ts=4 sw=4 ft=erlang noet
-define(tv_badarg(T, M, F, A),
	try erlang:apply(M, F, A) of
		T ->
			ct:fail({{M, F, A}, badarg_expected, {got, T}})
	catch
		error:badarg ->
			ok
	end).
-define(tv_not(T, M, F, A, E),
	case erlang:apply(M, F, A) of
		E ->
			ct:fail({{M, F, A}, {not_expected, E}});
		T ->
			T
	end).
-define(tv_ok(T, M, F, A, E),
	case erlang:apply(M, F, A) of
		E ->
			ok;
		T ->
			ct:fail({{M, F, A}, {expected, E}, {got, T}})
	end).
