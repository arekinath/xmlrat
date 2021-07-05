%% xmlrat
%%
%% Copyright 2021 The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

%% @private
-module(xmlrat_xpath_utils).

%% Runtime utility functions for compiled xpath matching functions.

-include("include/records.hrl").

-export([
    filter_with_index/4,
    filter/3,
    elementset_to_scalar/1,
    attrset_to_scalar/1,
    to_scalar/1,
    recursive_set/1
    ]).

to_scalar(I) when is_integer(I) -> I;
to_scalar(S) when is_binary(S) -> S;
to_scalar([V]) -> to_scalar(V);
to_scalar(List) when is_list(List) ->
    iolist_to_binary([to_scalar(X) || X <- List]);
to_scalar(#xml_comment{text = T}) -> T;
to_scalar(#xml_pi{}) -> <<>>;
to_scalar(#xml_namespace{uri = URI}) -> URI;
to_scalar(#xml_attribute{value = V}) -> V;
to_scalar(#xml_element{content = Kids}) ->
    to_scalar(Kids).

elementset_to_scalar(Elems) ->
    iolist_to_binary([
        [B || B <- Kids, is_binary(B)] ||
            #xml_element{content = Kids} <- Elems]).

attrset_to_scalar([]) -> <<"">>;
attrset_to_scalar([#xml_attribute{value = Val}]) ->
    Val.

recursive_set([]) -> [];
recursive_set([E = #xml_element{content = Kids} | Rest]) ->
    [E | recursive_set(Rest ++ Kids)];
recursive_set([_ | Rest]) ->
    recursive_set(Rest).

-type index_filter_fun(X) :: fun(
    ([X], Index :: integer(), MaxIndex :: integer(), Root :: term(), Varbinds :: term()) -> true | false
    ).

-spec filter_with_index(index_filter_fun(X), [X], term(), term()) -> [X].
filter_with_index(Fun, List, Root, VarBinds) ->
    filter_with_index(Fun, 1, length(List), List, Root, VarBinds).

filter_with_index(_Fun, _N, _MaxN, [], _Root, _VarBs) -> [];
filter_with_index(Fun, N, MaxN, [Next | Rest], Root, VarBinds) ->
    case Fun([Next], N, MaxN, Root, VarBinds) of
        true ->
            [Next | filter_with_index(Fun, N + 1, MaxN, Rest, Root, VarBinds)];
        false ->
            filter_with_index(Fun, N + 1, MaxN, Rest, Root, VarBinds)
    end.

-type filter_fun(X) :: fun ( (X, Root :: term()) -> true | false ).

-spec filter(filter_fun(X), [X], term()) -> [X].
filter(_Fun, [], _Root) -> [];
filter(Fun, [Next | Rest], Root) ->
    case Fun(Next, Root) of
        true ->
            [Next | filter(Fun, Rest, Root)];
        false ->
            filter(Fun, Rest, Root)
    end.
