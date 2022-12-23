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
-module(xmlrat_xpath_compile).

-include_lib("xmlrat/include/records.hrl").

-export([
    compile_fun/1, compile_fun/2, compile_module/2, compile_module/1,
    to_function_forms/3, to_function_forms/4
    ]).

-type var_tok() :: {var,erl_anno:anno(),atom()}.
-type tok() :: {atom(), erl_anno:anno()} | {atom(), erl_anno:anno(), term()}.

-record(func_state, {
    args = [] :: [var_tok()],
    toks = [] :: [tok()]
    }).

-record(stk, {
    func :: atom(),
    ctx :: var_tok(),
    idx :: undefined | var_tok(),
    maxidx :: undefined | var_tok()
    }).

-record(?MODULE, {
    stk = [] :: [#stk{}],
    func :: atom(),
    ctx :: var_tok(),
    idx :: undefined | var_tok(),
    maxidx :: undefined | var_tok(),
    root :: undefined | var_tok(),
    varbinds :: undefined | var_tok(),
    funcs = #{} :: #{atom() => #func_state{}},
    nextn = erlang:unique_integer([positive]) :: integer(),
    ns :: #{default | binary() => binary()},
    loc :: undefined | integer() | {integer(),integer()}
    }).

make_forms([]) -> [];
make_forms(Tokens) ->
    {BeforeDot, AfterDot0} = lists:splitwith(fun
        ({dot, _}) -> false;
        (_) -> true
    end, Tokens),
    [Dot = {dot, _} | AfterDot1] = AfterDot0,
    {ok, Form} = erl_parse:parse_form(BeforeDot ++ [Dot]),
    [Form | make_forms(AfterDot1)].

%% @private
-spec to_function_forms(atom(), undefined | erl_anno:anno(), xmlrat_xpath:xpath()) -> [erl_parse:abstract_form()].
to_function_forms(FName, L, XPath) -> to_function_forms(FName, L, XPath, #{}).
to_function_forms(FName, L0, XPath, NS0) ->
    L = case L0 of
        undefined -> 2;
        _ -> L0
    end,
    NS1 = NS0#{
        <<"xml">> => <<"http://www.w3.org/XML/1998/namespace">>,
        <<"xmlns">> => <<"http://www.w3.org/2000/xmlns/">>
    },
    F0 = #{FName => #func_state{args = [{var,L,'Doc'}, {var,L,'VarBinds'}]}},
    S0 = #?MODULE{func = FName, ctx = {var,L,'Doc'}, root = {var,L,'Doc'},
                  varbinds = {var,L,'VarBinds'},
                  funcs = F0, ns = NS1, loc = L0},
    S1 = compile_expr(S0, XPath),
    #?MODULE{funcs = F1} = S1,
    WrapFuncForm0 = erl_syntax:function(
        erl_syntax:atom(FName),
        [erl_syntax:clause(
            [erl_syntax:variable('Doc')], none,
            [erl_syntax:application(
                erl_syntax:atom(FName),
                [erl_syntax:variable('Doc'),
                 erl_syntax:map_expr([])])])
        ]),
    WrapFuncForm1 = erl_syntax:revert(WrapFuncForm0),
    WrapFuncForm2 = erl_parse:map_anno(fun (_) ->
        erl_anno:set_generated(true, L)
    end, WrapFuncForm1),
    maps:fold(fun (Name, F, Acc) ->
        #func_state{args = Args, toks = BodyToks} = rename_unused_vars(F),
        FuncToks = [{atom, L, Name}, {'(', L}] ++
            lists:join({',', L}, Args) ++ [{')', L}, {'->', L}] ++
            BodyToks ++ [{dot, L}],
        {ok, FuncForm0} = erl_parse:parse_form(FuncToks),
        FuncForm1 = erl_parse:map_anno(fun (_) ->
            erl_anno:set_generated(true, L)
        end, FuncForm0),
        [FuncForm1 | Acc]
    end, [WrapFuncForm2], F1).

compile_module(XPath) -> compile_module(XPath, #{}).
compile_module(XPath, NS0) ->
    ModName = binary_to_atom(iolist_to_binary([
        "xmlrat_xpath_dyn_", integer_to_binary(erlang:unique_integer([positive]))
        ])),
    RecordsPath = code:lib_dir(xmlrat) ++ "/include/records.hrl",
    {ok, Data} = file:read_file(RecordsPath),
    {ok, RecTokens, _} = erl_scan:string(
        unicode:characters_to_list(Data, utf8)),
    RecForms = make_forms(RecTokens),
    ModHeaderForms = [
        {attribute, 1, module, ModName},
        {attribute, 1, export, [{match, 1}, {match, 2}]}],
    FuncForms = to_function_forms(match, undefined, XPath, NS0),
    Forms = ModHeaderForms ++ RecForms ++ FuncForms,
    {ok, Mod, Bin} = compile:forms(Forms, [return_errors]),
    {module, Mod} = code:load_binary(Mod, "xmlrat_xpath_dynamic", Bin),
    {ok, Mod}.

compile_fun(XPath) -> compile_fun(XPath, #{}).
compile_fun(XPath, NS0) ->
    {ok, Mod} = compile_module(XPath, NS0),
    {ok, fun Mod:match/1, fun Mod:match/2}.

count_var_usage(C0, []) -> C0;
count_var_usage(C0, [{var, _, VarName} | Rest]) ->
    C1 = C0#{VarName => maps:get(VarName, C0, 0) + 1},
    count_var_usage(C1, Rest);
count_var_usage(C0, [_Other | Rest]) ->
    count_var_usage(C0, Rest).

count_var_usage(Toks) ->
    count_var_usage(#{}, Toks).

rename_unused_vars(FS0 = #func_state{args = Args, toks = Toks}) ->
    Counts = count_var_usage(Args ++ Toks),
    maps:fold(fun
        (VarName, 1, Acc) ->
            NewVarName = list_to_atom([$_ | atom_to_list(VarName)]),
            rename_var(VarName, NewVarName, Acc);
        (_VarName, _Count, Acc) ->
            Acc
    end, FS0, Counts).

rename_var(OldName, NewName, FS0) ->
    #func_state{args = Args0, toks = Toks0} = FS0,
    Args1 = lists:map(fun
        ({var, L, Name}) when Name =:= OldName -> {var, L, NewName};
        (Other) -> Other
    end, Args0),
    Toks1 = lists:map(fun
        ({var, L, Name}) when Name =:= OldName -> {var, L, NewName};
        (Other) -> Other
    end, Toks0),
    FS0#func_state{args = Args1, toks = Toks1}.

-define(atoks(S,T), atoks(S, T, ?LINE)).

atoks(S0 = #?MODULE{func = FN, funcs = F0}, Toks, Line0) ->
    Line = case S0 of
        #?MODULE{loc = undefined} -> Line0;
        #?MODULE{loc = Loc} -> Loc
    end,
    #{FN := FS0} = F0,
    #func_state{toks = T0} = FS0,
    T1 = T0 ++ lists:map(fun
        ({T,L,W}) when is_atom(T) and is_integer(L) -> {T,Line,W};
        ({T,L}) when is_atom(T) and is_integer(L) -> {T,Line};
        (Other) -> Other
    end, lists:flatten(Toks)),
    FS1 = FS0#func_state{toks = T1},
    F1 = F0#{FN => FS1},
    S0#?MODULE{funcs = F1}.

enter_func(S0 = #?MODULE{}, BaseName, ArgNames = [_Ctx]) ->
    {Name, [CtxVar], S1} = alloc_func(S0, BaseName, ArgNames),
    S2 = push_func(S1, Name, CtxVar),
    {Name, S2};
enter_func(S0 = #?MODULE{}, BaseName, ArgNames = [_Ctx, _Idx, _MaxIdx]) ->
    {Name, [CtxVar, IdxVar, MaxIdxVar], S1} = alloc_func(S0, BaseName, ArgNames),
    S2 = push_func(S1, Name, CtxVar, IdxVar, MaxIdxVar),
    {Name, S2}.

alloc_func(S0 = #?MODULE{nextn = N0, funcs = F0}, BaseName, ArgNames) ->
    #?MODULE{root = RootVar, varbinds = VBVar} = S0,
    Name = list_to_atom("_xmlrat_" ++ BaseName ++ integer_to_list(N0)),
    S1 = S0#?MODULE{nextn = N0 + 1},
    {ArgVars0, S2} = lists:foldl(fun (ArgBase, {Acc, SS0}) ->
        {V, SS1} = tvar(SS0, ArgBase),
        {Acc ++ [V], SS1}
    end, {[], S1}, ArgNames),
    ArgVars1 = ArgVars0 ++ [RootVar, VBVar],
    FS0 = #func_state{args = ArgVars1},
    F1 = F0#{Name => FS0},
    S3 = S2#?MODULE{funcs = F1},
    {Name, ArgVars0, S3}.

push_func(S0 = #?MODULE{stk = Stk0, funcs = F0}, FuncName, Ctx1) ->
    #{FuncName := _} = F0,
    #?MODULE{ctx = Ctx0, idx = Idx0, maxidx = MaxIdx0, func = Func0} = S0,
    StkEnt = #stk{func = Func0, ctx = Ctx0, idx = Idx0, maxidx = MaxIdx0},
    Stk1 = [StkEnt | Stk0],
    S0#?MODULE{func = FuncName, ctx = Ctx1, idx = undefined,
               maxidx = undefined, stk = Stk1}.

push_func(S0 = #?MODULE{stk = Stk0, funcs = F0}, FuncName, Ctx1, Idx1, MaxIdx1) ->
    #{FuncName := _} = F0,
    #?MODULE{ctx = Ctx0, idx = Idx0, maxidx = MaxIdx0, func = Func0} = S0,
    StkEnt = #stk{func = Func0, ctx = Ctx0, idx = Idx0, maxidx = MaxIdx0},
    Stk1 = [StkEnt | Stk0],
    S0#?MODULE{func = FuncName, ctx = Ctx1, idx = Idx1, maxidx = MaxIdx1,
               stk = Stk1}.

pop_func(S0 = #?MODULE{stk = [StkEnt | Stk0]}) ->
    #stk{func = Func1, ctx = Ctx1, idx = Idx1, maxidx = MaxIdx1} = StkEnt,
    S0#?MODULE{stk = Stk0, func = Func1, ctx = Ctx1, idx = Idx1,
               maxidx = MaxIdx1}.

-spec cvar(#?MODULE{}, string()) -> {var_tok(), #?MODULE{}}.
cvar(S0 = #?MODULE{}, BaseName) ->
    {Var, S1} = tvar(S0, BaseName),
    S2 = S1#?MODULE{ctx = Var, idx = undefined, maxidx = undefined},
    {Var, S2}.

-spec tvar(#?MODULE{}, string()) -> {var_tok(), #?MODULE{}}.
tvar(S0 = #?MODULE{nextn = N}, BaseName) ->
    S1 = S0#?MODULE{nextn = N + 1},
    {var(BaseName, N), S1}.

binary_to_tokens(B) when is_binary(B) ->
    [{'<<',1},{string,1,unicode:characters_to_list(B, utf8)}, {'>>', 1}].

match_case(Var, Patterns) ->
    lists:flatten([{'case',1}, Var, {'of',1},
     [ [P, {'->',1}, {atom,1,true}, {';',1}] || P <- Patterns ],
     {var,1,'_'}, {'->',1}, {atom,1,false}, {'end',1}]).

qname_compare(_Var, '_', #?MODULE{}) ->
    [{atom,1,true}];
qname_compare(Var, {NSName, '_'}, #?MODULE{ns = NS}) ->
    case NS of
        #{NSName := BaseURI} ->
            URIToks = [{'<<',1},
                {string,1,unicode:characters_to_list(BaseURI, utf8)},
                {',', 1}, {var,1,'_'}, {'/',1}, {atom,1,binary},
                {'>>', 1}],
            Pattern = [{'{', 1}, {var,1,'_'}, {',', 1}, {var,1,'_'},
                {',',1}, URIToks, {'}',1}],
            match_case(Var, [Pattern]);
        _ ->
            Pattern = [{'{',1}, binary_to_tokens(NSName), {',',1},
                {var, 1, '_'}, {'}', 1}],
            match_case(Var, [Pattern])
    end;
qname_compare(Var, {NSName, Name}, #?MODULE{ns = NS}) ->
    case NS of
        #{NSName := BaseURI} ->
            URI = iolist_to_binary([BaseURI, Name]),
            Pattern = [{'{', 1}, {var,1,'_'}, {',', 1}, {var,1,'_'},
                {',',1}, binary_to_tokens(URI), {'}',1}],
            match_case(Var, [Pattern]);
        _ ->
            Pattern = [{'{',1}, binary_to_tokens(NSName), {',',1},
                binary_to_tokens(Name), {'}', 1}],
            match_case(Var, [Pattern])
    end;
qname_compare(Var, N, #?MODULE{ns = NS}) when is_binary(N) ->
    case NS of
        #{default := BaseURI} ->
            URI = iolist_to_binary([BaseURI, N]),
            URIPattern = [{'{', 1}, {var,1,'_'}, {',', 1}, {var,1,'_'},
                {',',1}, binary_to_tokens(URI), {'}',1}],
            match_case(Var, [URIPattern]);
        _ ->
            Pattern1 = [binary_to_tokens(N)],
            Pattern2 = [{'{',1}, {var,1,'_'}, {',',1}, binary_to_tokens(N),
                        {'}', 1}],
            Pattern3 = [{'{',1}, {var,1,'_'}, {',',1}, binary_to_tokens(N),
                        {',',1}, {var,1,'_'}, {'}', 1}],
            match_case(Var, [Pattern1, Pattern2, Pattern3])
    end.

-spec var(string(), integer()) -> var_tok().
var(Name, N) ->
    {var, erl_anno:new(1), list_to_atom(Name ++ integer_to_list(N))}.

filter(Conds, Var, InputVar) ->
    [{'[', 1}, Var, {'||', 1}, Var, {'<-', 1}, InputVar, {',', 1}] ++
        Conds ++ [{']', 1}].

idx_filter_fun(Func, InputVar, RootVar, VBVar) ->
    [{atom, 1, xmlrat_xpath_utils}, {':', 1}, {atom, 1, filter_with_index},
     {'(', 1}, {'fun', 1}, {atom, 1, Func}, {'/', 1}, {integer, 1, 5}, {',', 1},
     InputVar, {',', 1}, RootVar, {',',1}, VBVar, {')', 1}].

celement(N, Var) ->
    [{atom,1,'element'}, {'(',1}, {integer,1,N}, {',',1}, Var, {')',1}].

compile_steps(S0 = #?MODULE{}, []) ->
    #?MODULE{ctx = CtxVar} = S0,
    ?atoks(S0, [CtxVar]);
compile_steps(S0, [Next | Rest]) ->
    S1 = compile_step(S0, Next),
    S2 = ?atoks(S1, [{',', 1}]),
    compile_steps(S2, Rest).

scan(String, Var) ->
    {ok, T0, _} = erl_scan:string(lists:flatten(String)),
    lists:map(fun
        ({var, _, 'InputVar'}) -> Var;
        (Other) -> Other
    end, T0).
scan(String, InVar, TempVar) ->
    {ok, T0, _} = erl_scan:string(lists:flatten(String)),
    lists:map(fun
        ({var, _, 'InputVar'}) -> InVar;
        ({var, _, 'TempVar'}) -> TempVar;
        (Other) -> Other
    end, T0).

last_axis(Axis, []) -> Axis;
last_axis(_, [absolute | Rest]) ->
    last_axis(child, Rest);
last_axis(Axis, [self | Rest]) ->
    last_axis(Axis, Rest);
last_axis(Axis, [parent | Rest]) ->
    last_axis(Axis, Rest);
last_axis(_, ['_' | Rest]) ->
    last_axis(child, Rest);
last_axis(_, [{_Axis, {type_match, text}, _Preds} | Rest]) ->
    last_axis(text, Rest);
last_axis(_, [{_Axis, {type_match, comment}, _Preds} | Rest]) ->
    last_axis(comment, Rest);
last_axis(_, [{Axis, _Test, _Preds} | Rest]) when is_atom(Axis) ->
    last_axis(Axis, Rest).

or_chain([Cond]) -> Cond;
or_chain([Cond1 | Rest]) ->
    {'or', Cond1, or_chain(Rest)}.

compile_step(S0, absolute) ->
    #?MODULE{root = RootVar} = S0,
    T0 = scan("[#xml_element{tag = root, content = "
        "[X || X = #xml_element{} <- InputVar]}]", RootVar),
    {OutVar, S1} = cvar(S0, "Step"),
    ?atoks(S1, [OutVar, {'=', 1}, T0]);
compile_step(S0, '_') ->
    #?MODULE{ctx = InVar} = S0,
    {OutVar, S1} = cvar(S0, "Step"),
    OutToks = scan("xmlrat_xpath_utils:recursive_set(InputVar)", InVar),
    ?atoks(S1, [OutVar, {'=', 1}, OutToks]);
compile_step(S0, {function_call, <<"id">>, [Expr]}) when is_binary(Expr) ->
    IDs = binary:split(Expr, [<<" ">>, <<$\t>>, <<$\n>>], [global, trim_all]),
    S1 = compile_step(S0, absolute),
    S2 = ?atoks(S1, [{',', 1}]),
    S3 = compile_step(S2, '_'),
    S4 = ?atoks(S3, [{',', 1}]),
    Conds = [ {eq, X, [{attribute, {name_match, <<"id">>}, []}]} || X <- IDs ],
    compile_step(S4, {child, {name_match, '_'}, [or_chain(Conds)]});
compile_step(S0, {child, {type_match, text}, []}) ->
    #?MODULE{ctx = InVar} = S0,
    {AxisVar, S1} = tvar(S0, "Axis"),
    {OutVar, S2} = cvar(S1, "Step"),
    AxisToks = scan("lists:flatten("
        "[Kids || #xml_element{content = Kids} <- InputVar])", InVar),
    StepToks = scan("iolist_to_binary([B || B <- InputVar, is_binary(B)])",
        AxisVar),
    ?atoks(S2, [
        AxisVar, {'=', 1}, AxisToks, {',', 1},
        OutVar, {'=', 1}, StepToks]);
compile_step(S0, {child, {type_match, name}, []}) ->
    #?MODULE{ctx = InVar} = S0,
    {TagsVar, S1} = tvar(S0, "Tags"),
    {TagVar, S2} = tvar(S1, "Tag"),
    {OutVar, S3} = cvar(S2, "Step"),
    Toks = scan("[Tag || #xml_element{tag = Tag} <- InputVar]", InVar),
    CaseToks = scan("case InputVar of [TempVar] -> TempVar; _ -> InputVar end",
        TagsVar, TagVar),
    ?atoks(S3, [
        TagsVar, {'=', 1}, Toks, {',', 1},
        OutVar, {'=', 1}, CaseToks]);
compile_step(S0, {child, {type_match, 'local-name'}, []}) ->
    #?MODULE{ctx = InVar} = S0,
    {TagsVar, S1} = tvar(S0, "Tags"),
    {TagVar, S2} = tvar(S1, "Tag"),
    {OutVar, S3} = cvar(S2, "Step"),
    Toks = scan("[case Tag of"
        "{_, T, _} -> T;"
        "{_, T} -> T;"
        "T when is_binary(T) -> T end || "
        "#xml_element{tag = Tag} <- InputVar]", InVar),
    CaseToks = scan("case InputVar of [TempVar] -> TempVar; _ -> InputVar end",
        TagsVar, TagVar),
    ?atoks(S3, [
        TagsVar, {'=', 1}, Toks, {',', 1},
        OutVar, {'=', 1}, CaseToks]);
compile_step(S0, {self, {name_match, '_'}, Predicates}) ->
    #?MODULE{ctx = InVar} = S0,
    {OutVar, S1} = cvar(S0, "Step"),
    compile_predicates(S1, InVar, OutVar, Predicates);
compile_step(S0, {self, {name_match, Name}, Predicates}) ->
    #?MODULE{ctx = InVar} = S0,
    {NodesVar, S1} = tvar(S0, "Nodes"),
    {OutVar, S2} = cvar(S1, "Step"),
    NodeConds = [
        {atom,1,'is_tuple'}, {'(',1}, {var,1,'X'}, {')',1}, {'andalso',1},
        {'(',1},
            celement(1, {var,1,'X'}), {'=:=',1}, {atom,1,'xml_element'},
        {')',1},{'andalso',1},
        {'(',1},
            qname_compare(celement(2, {var,1,'X'}), Name, S0),
        {')',1}
        ],
    NodeToks = filter(NodeConds, {var,1,'X'}, InVar),
    S3 = ?atoks(S2, [NodesVar, {'=', 1}, NodeToks, {',', 1}]),
    compile_predicates(S3, NodesVar, OutVar, Predicates);
compile_step(S0, {child, {name_match, '_'}, Predicates}) ->
    #?MODULE{ctx = InVar} = S0,
    {AxisVar, S1} = tvar(S0, "Axis"),
    {OutVar, S2} = cvar(S1, "Step"),
    AxisToks = scan("lists:flatten("
        "[Kids || #xml_element{content = Kids} <- InputVar])", InVar),
    S3 = ?atoks(S2, [AxisVar, {'=', 1}, AxisToks, {',', 1}]),
    compile_predicates(S3, AxisVar, OutVar, Predicates);
compile_step(S0, {child, {name_match, Name}, Predicates}) ->
    #?MODULE{ctx = InVar} = S0,
    {AxisVar, S1} = tvar(S0, "Axis"),
    {NodesVar, S2} = tvar(S1, "Nodes"),
    {OutVar, S3} = cvar(S2, "Step"),
    AxisToks = scan("lists:flatten("
        "[Kids || #xml_element{content = Kids} <- InputVar])", InVar),
    S4 = ?atoks(S3, [AxisVar, {'=', 1}, AxisToks, {',', 1}]),
    NodeConds = [
        {atom,1,'is_tuple'}, {'(',1}, {var,1,'X'}, {')',1}, {'andalso',1},
        {'(',1},
            celement(1, {var,1,'X'}), {'=:=',1}, {atom,1,'xml_element'},
        {')',1},{'andalso',1},
        {'(',1},
            qname_compare(celement(2, {var,1,'X'}), Name, S0),
        {')',1}
        ],
    NodeToks = filter(NodeConds, {var,1,'X'}, AxisVar),
    S5 = ?atoks(S4, [NodesVar, {'=', 1}, NodeToks, {',', 1}]),
    compile_predicates(S5, NodesVar, OutVar, Predicates);
compile_step(S0, {attribute, {name_match, Name}, Predicates}) ->
    #?MODULE{ctx = InVar} = S0,
    {AxisVar, S1} = tvar(S0, "Axis"),
    {NodesVar, S2} = tvar(S1, "Nodes"),
    {OutVar, S3} = cvar(S2, "Step"),
    AxisToks = scan("lists:flatten("
        "[Attrs || #xml_element{attributes = Attrs} <- InputVar])", InVar),
    S4 = ?atoks(S3, [AxisVar, {'=', 1}, AxisToks, {',', 1}]),
    NodeConds = [
        {atom,1,'is_tuple'}, {'(',1}, {var,1,'X'}, {')',1}, {'andalso',1},
        {'(',1},
            celement(1, {var,1,'X'}), {'=:=',1}, {atom,1,'xml_attribute'},
        {')',1},{'andalso',1},
        {'(',1},
            qname_compare(celement(2, {var,1,'X'}), Name, S0),
        {')',1}
        ],
    NodeToks = filter(NodeConds, {var,1,'X'}, AxisVar),
    S5 = ?atoks(S4, [NodesVar, {'=', 1}, NodeToks, {',', 1}]),
    compile_predicates(S5, NodesVar, OutVar, Predicates).

compile_predicates(S0, InVar, OutVar, []) ->
    ?atoks(S0, [OutVar, {'=', 1}, InVar]);
compile_predicates(S0, InVar, OutVar, [Last]) ->
    #?MODULE{root = RootVar, varbinds = VarBindsVar} = S0,
    {PredFunc, S1} = enter_func(S0, "predicate_",
        ["Step", "Idx", "MaxIdx"]),
    S2 = compile_predicate(S1, Last),
    S3 = pop_func(S2),
    Toks = idx_filter_fun(PredFunc, InVar, RootVar, VarBindsVar),
    ?atoks(S3, [OutVar, {'=', 1}, Toks]);
compile_predicates(S0, InVar, OutVar, [Next | Rest]) ->
    #?MODULE{root = RootVar, varbinds = VarBindsVar} = S0,
    {NextVar, S1} = tvar(S0, "Predicate"),
    {PredFunc, S2} = enter_func(S1, "predicate_",
        ["Step", "Idx", "MaxIdx"]),
    S3 = compile_predicate(S2, Next),
    S4 = pop_func(S3),
    Toks = idx_filter_fun(PredFunc, InVar, RootVar, VarBindsVar),
    S5 = ?atoks(S4, [NextVar, {'=', 1}, Toks, {',', 1}]),
    compile_predicates(S5, NextVar, OutVar, Rest).

compile_predicate(S0, I) when is_integer(I) ->
    #?MODULE{idx = IdxVar} = S0,
    ?atoks(S0, [{'(', 1}, IdxVar, {'=:=', 1}, {integer, 1, I}, {')', 1}]);
compile_predicate(S0, Ex) ->
    compile_expr(S0, Ex).

compile_expr(S0, X) when is_list(X) ->
    #?MODULE{root = RootVar, ctx = CtxVar, varbinds = VarBindsVar} = S0,
    {PathFunc, S1} = enter_func(S0, "match_path_", ["Step"]),
    S2 = compile_steps(S1, X),
    S3 = pop_func(S2),
    ?atoks(S3, [{atom, 1, PathFunc}, {'(', 1}, CtxVar, {',', 1},
        RootVar, {',',1}, VarBindsVar, {')', 1}]);
compile_expr(S0, {boolean, X}) ->
    case expr_type(X) of
        boolean ->
            compile_expr(S0, X);
        scalar ->
            S1 = ?atoks(S0, [{'case', 1}]),
            S2 = compile_expr(S1, X),
            ?atoks(S2, [{'of', 1},
                {integer, 1, 0}, {'->', 1}, {atom,1,false}, {';',1},
                {'<<', 1}, {'>>', 1}, {'->', 1}, {atom,1,false}, {';',1},
                {var, 1, '_'}, {'->',1}, {atom,1,true}, {'end', 1}
                ]);
        Set when (Set =:= elementset) or (Set =:= attrset) or (Set =:= nsset) ->
            S1 = ?atoks(S0, [{'case', 1}]),
            S2 = compile_expr(S1, X),
            ?atoks(S2, [{'of', 1},
                {'[', 1}, {']', 1}, {'->', 1}, {atom,1,false}, {';',1},
                {var, 1, '_'}, {'->',1}, {atom,1,true}, {'end', 1}
                ])
    end;
compile_expr(S0, I) when is_integer(I) ->
    ?atoks(S0, [{integer,1,I}]);
compile_expr(S0, B) when is_binary(B) ->
    ?atoks(S0, [{'<<',1}, {string,1,unicode:characters_to_list(B, utf8)},
               {'>>',1}]);
compile_expr(S0, {var, N}) ->
    #?MODULE{varbinds = VarBindsVar} = S0,
    NBin = [{'<<',1}, {string,1,unicode:characters_to_list(N, utf8)}, {'>>',1}],
    ?atoks(S0, [{atom,1,'maps'}, {':',1}, {atom,1,'get'}, {'(',1},
        NBin, {',',1}, VarBindsVar, {')',1}]);
compile_expr(S0, {eq, A, B}) ->
    S1 = ?atoks(S0, [{'(', 1}]),
    S2 = case {expr_type(A), expr_type(B)} of
        {X, X} ->
            SS0 = compile_expr(S1, A),
            SS1 = ?atoks(SS0, [{'=:=',1}]),
            compile_expr(SS1, B);
        {elementset, scalar} ->
            SS0 = ?atoks(S1, [{atom, 1, 'xmlrat_xpath_utils'}, {':', 1},
                {atom, 1, 'elementset_to_scalar'}, {'(', 1}]),
            SS1 = compile_expr(SS0, A),
            SS2 = ?atoks(SS1, [{')', 1}, {'=:=',1}]),
            compile_expr(SS2, B);
        {scalar, elementset} ->
            SS0 = ?atoks(S1, [{atom, 1, 'xmlrat_xpath_utils'}, {':', 1},
                {atom, 1, 'elementset_to_scalar'}, {'(', 1}]),
            SS1 = compile_expr(SS0, B),
            SS2 = ?atoks(SS1, [{')', 1}, {'=:=',1}]),
            compile_expr(SS2, A);
        {attrset, scalar} ->
            SS0 = ?atoks(S1, [{atom, 1, 'xmlrat_xpath_utils'}, {':', 1},
                {atom, 1, 'attrset_to_scalar'}, {'(', 1}]),
            SS1 = compile_expr(SS0, A),
            SS2 = ?atoks(SS1, [{')', 1}, {'=:=',1}]),
            compile_expr(SS2, B);
        {scalar, attrset} ->
            SS0 = ?atoks(S1, [{atom, 1, 'xmlrat_xpath_utils'}, {':', 1},
                {atom, 1, 'attrset_to_scalar'}, {'(', 1}]),
            SS1 = compile_expr(SS0, B),
            SS2 = ?atoks(SS1, [{')', 1}, {'=:=',1}]),
            compile_expr(SS2, A)
    end,
    ?atoks(S2, [{')',1}]);
compile_expr(S0, {'and', A, B}) ->
    S1 = compile_expr(S0, {boolean, A}),
    S2 = ?atoks(S1, [{'andalso', 1}]),
    compile_expr(S2, {boolean, B});
compile_expr(S0, {'or', A, B}) ->
    S1 = compile_expr(S0, {boolean, A}),
    S2 = ?atoks(S1, [{'orelse', 1}]),
    compile_expr(S2, {boolean, B});
compile_expr(S0, {function_call, <<"not">>, [Expr]}) ->
    S1 = ?atoks(S0, [{'not', 1}, {'(', 1}]),
    S2 = compile_expr(S1, {boolean, Expr}),
    ?atoks(S2, [{')', 1}]);
compile_expr(S0, {function_call, <<"last">>, []}) ->
    #?MODULE{idx = IdxVar, maxidx = MaxIdxVar} = S0,
    ?atoks(S0, [
        {'(',1}, IdxVar, {'==',1}, MaxIdxVar, {')',1}
    ]);
compile_expr(S0, {function_call, <<"position">>, []}) ->
    #?MODULE{idx = IdxVar} = S0,
    ?atoks(S0, [IdxVar]);
compile_expr(S0, {function_call, <<"count">>, [A]}) ->
    case expr_type(A) of
        attrset -> ok;
        nsset -> ok;
        elementset -> ok;
        _ -> error({bad_arg_type, <<"count">>, A})
    end,
    S1 = ?atoks(S0, [{'(', 1}, {atom, 1, 'length'}, {'(', 1}]),
    S2 = compile_expr(S1, A),
    ?atoks(S2, [{')', 1}, {')', 1}]);
compile_expr(_S0, Expr) ->
    error({unsupported_expr, Expr}).

expr_type(X) when is_list(X) ->
    case last_axis(child, X) of
        attribute -> attrset;
        namespace -> nsset;
        text -> scalar;
        _ -> elementset
    end;
expr_type(I) when is_integer(I) -> scalar;
expr_type(B) when is_binary(B) -> scalar;
expr_type({var, _N}) -> scalar;
expr_type({negate, _A}) -> scalar;
expr_type({union, A, B}) ->
    case {expr_type(A), expr_type(B)} of
        {scalar, _} -> error(union_of_scalar);
        {_, scalar} -> error(union_of_scalar);
        {boolean, _} -> error(union_of_boolean);
        {_, boolean} -> error(union_of_boolean);
        {X, X} -> X;
        _ -> error(union_mismatch)
    end;
expr_type({Op, _A, _B}) when (Op =:= add) or (Op =:= subtract) or
    (Op =:= multiply) or (Op =:= 'div') or (Op =:= 'mod') -> scalar;
expr_type({function_call, <<"last">>, []}) -> boolean;
expr_type({function_call, <<"position">>, []}) -> scalar;
expr_type({function_call, <<"count">>, [_A]}) -> scalar;
expr_type({function_call, <<"id">>, [_Id]}) -> elementset;
expr_type({function_call, <<"not">>, [_A]}) -> boolean;
expr_type({_Op, _A, _B}) -> boolean.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

root_test() ->
    XPath = xmlrat_xpath_parse:parse("/"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Root = #xml_element{tag = <<"foo">>},
    Res = Fun([Root]),
    ?assertMatch([#xml_element{content = [Root]}], Res).

child_1_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Root = {xml_element, <<"foo">>, [], [{xml_element, <<"bar">>, [], []}]},
    Res = Fun([Root]),
    ?assertMatch([Root], Res).

child_2_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/bar"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Child = {xml_element, <<"bar">>, [], []},
    Root = {xml_element, <<"foo">>, [], [Child]},
    Res = Fun([Root]),
    ?assertMatch([Child], Res).

child_empty_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/asdf"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Child = {xml_element, <<"bar">>, [], []},
    Root = {xml_element, <<"foo">>, [], [Child]},
    Res = Fun([Root]),
    ?assertMatch([], Res).

child_index_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/bar[2]"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Child1 = {xml_element, <<"bar">>, [{xml_attribute, <<"index">>, 1}], []},
    Child2 = {xml_element, <<"bar">>, [{xml_attribute, <<"index">>, 2}], []},
    Root = {xml_element, <<"foo">>, [], [Child1, Child2]},
    Res = Fun([Root]),
    ?assertMatch([Child2], Res).

child_star_index_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/*[1]"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Child1 = {xml_element, <<"bar">>, [{xml_attribute, <<"index">>, 1}], []},
    Child2 = {xml_element, <<"bar">>, [{xml_attribute, <<"index">>, 2}], []},
    Root = {xml_element, <<"foo">>, [], [Child1, Child2]},
    Res = Fun([Root]),
    ?assertMatch([Child1], Res).

child_last_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/bar[last()]"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Child1 = {xml_element, <<"bar">>, [{xml_attribute, <<"index">>, 1}], []},
    Child2 = {xml_element, <<"bar">>, [{xml_attribute, <<"index">>, 2}], []},
    Root = {xml_element, <<"foo">>, [], [Child1, Child2]},
    Res = Fun([Root]),
    ?assertMatch([Child2], Res).

child_last_after_pred_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/bar[@use = '1'][last()]"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Child1 = {xml_element, <<"bar">>, [{xml_attribute, <<"use">>, <<"1">>}], []},
    Child2 = {xml_element, <<"bar">>, [{xml_attribute, <<"use">>, <<"1">>}], []},
    Child3 = {xml_element, <<"bar">>, [{xml_attribute, <<"use">>, <<"0">>}], []},
    Root = {xml_element, <<"foo">>, [], [Child1, Child2, Child3]},
    Res = Fun([Root]),
    ?assertMatch([Child2], Res).

child_last_after_pred_2_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/bar[@use = '1' and last()]"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Child1 = {xml_element, <<"bar">>, [{xml_attribute, <<"use">>, <<"1">>}], []},
    Child2 = {xml_element, <<"bar">>, [{xml_attribute, <<"use">>, <<"1">>}], []},
    Child3 = {xml_element, <<"bar">>, [{xml_attribute, <<"use">>, <<"0">>}], []},
    Root = {xml_element, <<"foo">>, [], [Child1, Child2, Child3]},
    Res = Fun([Root]),
    ?assertMatch([], Res).

attr_axis_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/@bar"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Attr = {xml_attribute, <<"bar">>, [<<"hi">>]},
    Root = {xml_element, <<"foo">>, [Attr], []},
    Res = Fun([Root]),
    ?assertMatch([Attr], Res).

attr_compare_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo[@bar = 'hi']"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Attr = {xml_attribute, <<"bar">>, <<"hi">>},
    Root = {xml_element, <<"foo">>, [Attr], []},
    Res = Fun([Root]),
    ?assertMatch([Root], Res).

attr_compare_false_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo[@bar = 'what']"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Attr = {xml_attribute, <<"bar">>, <<"hi">>},
    Root = {xml_element, <<"foo">>, [Attr], []},
    Res = Fun([Root]),
    ?assertMatch([], Res).

text_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo[@bar = 'hi']/text()"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Attr = {xml_attribute, <<"bar">>, <<"hi">>},
    Root = {xml_element, <<"foo">>, [Attr], [<<"hi there">>]},
    Res = Fun([Root]),
    ?assertMatch(<<"hi there">>, Res).

name_test() ->
    XPath = xmlrat_xpath_parse:parse("/*[@bar = 'hi']/name()"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Attr = {xml_attribute, <<"bar">>, <<"hi">>},
    Root = {xml_element, <<"foo">>, [Attr], [<<"hi there">>]},
    Res = Fun([Root]),
    ?assertMatch(<<"foo">>, Res).

multi_name_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/*/name()"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    E0 = {xml_element, {<<"ns">>, <<"bar">>}, [], []},
    E1 = {xml_element, <<"test">>, [], []},
    E2 = {xml_element, <<"aaaa">>, [], []},
    Root = {xml_element, <<"foo">>, [], [E0, E1, E2]},
    Res = Fun([Root]),
    ?assertMatch([{<<"ns">>, <<"bar">>}, <<"test">>, <<"aaaa">>], Res).

local_name_test() ->
    XPath = xmlrat_xpath_parse:parse("/*[@bar = 'hi']/local-name()"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    Attr = {xml_attribute, <<"bar">>, <<"hi">>},
    Root = {xml_element, {<<"ns">>, <<"foo">>}, [Attr], [<<"hi there">>]},
    Res = Fun([Root]),
    ?assertMatch(<<"foo">>, Res).

child_compare_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo[bar = 'hi']/baz/text()"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    {ok, Root} = xmlrat_parse:string("<?xml version='1.0'?>
        <foo bar='what'>
          <bar>hi</bar>
          <baz>test</baz>
        </foo>"),
    Res = Fun(Root),
    ?assertMatch(<<"test">>, Res).

namespace_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/ns:baz/text()"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath, #{
        default => <<"uri:default:">>,
        <<"ns">> => <<"uri:ns:">>
        }),
    {ok, Root} = xmlrat_parse:string("<?xml version='1.0'?>
        <foo xmlns='uri:default:'>
          <bar>hi</bar>
          <baz xmlns='uri:ns:'>test</baz>
        </foo>"),
    Res = Fun(Root),
    ?assertMatch(<<"test">>, Res).

namespace_2_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/ns:baz/text()"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath, #{
        default => <<"uri:default:">>,
        <<"ns">> => <<"uri:ns:">>
        }),
    {ok, Root} = xmlrat_parse:string("<?xml version='1.0'?>
        <foo xmlns='uri:default:' xmlns:what='uri:ns:'>
          <bar>hi</bar>
          <what:baz>test</what:baz>
        </foo>"),
    Res = Fun(Root),
    ?assertMatch(<<"test">>, Res).

namespace_attr_test() ->
    XPath = xmlrat_xpath_parse:parse("/d:foo/d:bar[@ns:thing='test']/@d:id"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath, #{
        <<"d">> => <<"uri:default:">>,
        <<"ns">> => <<"uri:ns:">>
        }),
    {ok, Root} = xmlrat_parse:string("<?xml version='1.0'?>
        <foo xmlns='uri:default:' xmlns:what='uri:ns:'>
          <bar what:thing='test' id='1'>hi</bar>
          <bar what:thing='test2' id='2'>hi</bar>
        </foo>"),
    Res = Fun(Root),
    io:format("res = ~p\n", [Res]),
    ?assertMatch([{xml_attribute, {_, <<"id">>, _}, <<"1">>}], Res).

recurse_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo//bar[@thing='test']/@id"),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    {ok, Root} = xmlrat_parse:string("<?xml version='1.0'?>
        <foo>
          <baz>
            <bar thing='test' id='1'/>
          </baz>
          <barr>
            <thing>
              <bar thing='test2' id='2'/>
              <bar thing='test' id='3'/>
            </thing>
          </barr>
          <bar thing='test' id='4'/>
          <bar thing='test2' id='5'/>
        </foo>"),
    Res = Fun(Root),
    io:format("res = ~p\n", [Res]),
    IDs = [V || {xml_attribute, <<"id">>, V} <- Res],
    ?assertMatch([<<"1">>, <<"3">>, <<"4">>], lists:sort(IDs)).

id_test() ->
    XPath = xmlrat_xpath_parse:parse("id(\"4\")/@thing"),
    io:format("~p\n", [XPath]),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    {ok, Root} = xmlrat_parse:string("<?xml version='1.0'?>
        <foo>
          <baz>
            <bar thing='test' id='1'/>
          </baz>
          <barr>
            <thing>
              <bar thing='test2' id='2'/>
              <bar thing='test' id='3'/>
            </thing>
          </barr>
          <bar thing='test' id='4'/>
          <bar thing='test2' id='5'/>
        </foo>"),
    Res = Fun(Root),
    ?assertMatch([#xml_attribute{value = <<"test">>}], Res).

not_tag_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo/*[not(self::baz)]"),
    io:format("~p\n", [XPath]),
    {ok, Fun, _} = xmlrat_xpath_compile:compile_fun(XPath),
    {ok, Root} = xmlrat_parse:string("<?xml version='1.0'?>
        <foo>
          <baz>
            <bar thing='test' id='1'/>
          </baz>
          <barr>
            <thing>
              <bar thing='test2' id='2'/>
              <bar thing='test' id='3'/>
            </thing>
          </barr>
          <bar thing='test' id='4'/>
          <bar thing='test2' id='5'/>
        </foo>"),
    Res = Fun(Root),
    Elems = [Tag || #xml_element{tag = Tag} <- Res],
    ?assertMatch([<<"barr">>, <<"bar">>, <<"bar">>], Elems).

var_test() ->
    XPath = xmlrat_xpath_parse:parse("/foo//bar[@thing=$testvar]/@id"),
    io:format("~p\n", [XPath]),
    {ok, _, Fun} = xmlrat_xpath_compile:compile_fun(XPath),
    {ok, Root} = xmlrat_parse:string("<?xml version='1.0'?>
        <foo>
          <baz>
            <bar thing='test' id='1'/>
          </baz>
          <barr>
            <thing>
              <bar thing='test2' id='2'/>
              <bar thing='test' id='3'/>
            </thing>
          </barr>
          <bar thing='test' id='4'/>
          <bar thing='test2' id='5'/>
        </foo>"),
    Res = Fun(Root, #{<<"testvar">> => <<"test2">>}),
    Elems = [V || #xml_attribute{value = V} <- Res],
    ?assertMatch([<<"5">>, <<"2">>], Elems).

-endif.
