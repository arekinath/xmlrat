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

%% @doc A parse transform which provides attributes for compiling custom XML
%%      processing functions.
%%
%% This parse transform defines several new attributes:
%% <ul>
%%   <li><code>-xpath(...).</code> compiles an XPath expression to a matching
%%       function of a given name (like {@link xmlrat_xpath:compile/1}).</li>
%%   <li><code>-xpath_record(...).</code> generates a function which runs
%%       multiple XPath expressions against a document and places their results
%%       into fields of a record. Supports type coercion based on the declared
%%       types of the record fields.</li>
%%   <li><code>-xml_record(...).</code> generates a function which takes a
%%       record as input and produces an XML document, based on the
%%       {@link xmlrat_mini_xslt} syntax.</li>
%% </ul>
%%
%% You can enable these in your module by including a <code>-compile()</code>
%% attribute directly after your <code>-module()</code> declaration. You will
%% also need to include the <code>records.hrl</code> header:
%%
%% <pre>
%% -module(my_module).
%% -compile({parse_transform, xmlrat_parse_transform}).
%% -include_lib("xmlrat/include/records.hrl").
%% </pre>
%%
%% == Attributes ==
%%
%% === -xpath() ===
%%
%% Compiles an XPath expression to an Erlang function (like
%% {@link xmlrat_xpath:compile/1}).
%%
%% <pre>
%% -xpath({FunctionName :: atom(),
%%         XPath :: string() | binary()}).
%% -xpath({FunctionName :: atom(),
%%         XPath :: string() | binary(),
%%         Namespaces :: #{binary() | default => uri()}}).
%% -spec FunctionName(document()) -> xpath_result().
%% -spec FunctionName(document(), varbinds()) -> xpath_result().
%% </pre>
%%
%% The <code>-xpath(...)</code> attribute generates both an arity-1 and arity-2
%% variant of the function with the provided name.
%%
%% === -xpath_record() ===
%%
%% Generates a function which deserialises XML into an Erlang record using
%% XPath expressions and the type signature of the record itself.
%%
%% Each field of the record is mapped to an XPath expression in the argument
%% <code>XPathExprs</code> to the attribute. The output of each expression is
%% coerced into the type declared in the relevant <code>-record()</code>
%% attribute.
%%
%% <pre>
%% -record(recname, {
%%     optional_field :: undefined | binary(),
%%     required_field :: integer(),
%%     list_field :: [binary()],
%%     nested_field :: #recname2{}
%%   }).
%% -xpath_record({FunctionName :: atom(),
%%                RecordName :: atom(),
%%                XPathExprs :: #{atom() => string() | binary()}}).
%% -xpath_record({FunctionName :: atom(),
%%                RecordName :: atom(),
%%                XPathExprs :: #{field() => string() | binary()},
%%                Namespaces :: #{binary() | default => uri()}}).
%% -spec FunctionName(document()) -> #RecordName{}.
%% </pre>
%%
%% The target record must be defined before the <code>-xpath_record()</code>
%% attribute. Type aliases are supported in record fields, as long as the
%% alias is local and defined in the current file.
%%
%% If any nested fields are present (with a declared type of another record),
%% their XPath expression must evaluate to a node set, and another
%% <code>-xpath_record()</code> attribute with <code>RecordName</code> set to
%% that record must appear in the same file before this attribute.
%%
%% === -xml_record() ===
%%
%% Generates a function which serialises an Erlang record into an XML document
%% (or part of one), using an XSLT-like template. Documentation for the
%% template format is available in {@link xmlrat_mini_xslt}.
%%
%% The template is provided as a string or binary to the attribute, which will
%% parse it at compile-time. The generated code consists of the relevant
%% <code>#xml_element{}</code> etc records from
%% <code>xmlrat/include/records.hrl</code>. Substitutions are compiled
%% completely to expressions within the record hierarchy.
%%
%% Like <code>-xpath_record()</code>, the <code>-xml_record()</code> attribute
%% uses the declared types of record fields to generate correct type coercion
%% for each piece of data injected into the template.
%%
%% <pre>
%% -record(recname, {
%%     optional_field :: undefined | binary(),
%%     required_field :: integer(),
%%     list_field :: [binary()],
%%     nested_field :: #recname2{}
%%   }).
%% -xml_record({FunctionName :: atom(),
%%              RecordName :: atom(),
%%              Template :: binary() | string()}}).
%% -xml_record({FunctionName :: atom(),
%%              RecordName :: atom(),
%%              Template :: binary() | string(),
%%              Namespaces :: #{binary() | default => uri()}}).
%% -spec FunctionName(#RecordName{}) -> document().
%% </pre>
-module(xmlrat_parse_transform).

-export([parse_transform/2, parse_transform_info/0]).

-export_type([xpath/0]).

-type xpath() :: [term()].

-define(tplns, #{
    <<"mxsl">> => <<"https://cooperi.net/xmlrat/mini-xslt/">>
    }).

-record(?MODULE, {
    opts :: [term()],                       % compiler options
    utypes = #{} :: #{atom() => term()},    % user-defined types
    records = #{} :: #{atom() => term()},   % records seen so far
    decoders = #{} :: #{atom() => atom()},  % record decoders we've compiled
    encoders = #{} :: #{atom() => atom()}   % record encoders
    }).

-spec parse_transform_info() -> #{'error_location' => 'column' | 'line'}.
parse_transform_info() ->
    #{error_location => column}.

-spec parse_transform([erl_parse:abstract_form()], [compile:option()]) ->
    [erl_parse:abstract_form()].
parse_transform(Forms, Options) ->
    S0 = #?MODULE{opts = Options},
    transform_all(Forms, S0).

is_optional({type, _, union, Opts}) ->
    lists:any(fun
        ({atom, _, undefined}) -> true;
        (_) -> false
    end, Opts);
is_optional(_) -> false.

transform_all([], _) -> [];
transform_all([Form0 | Rest], S0 = #?MODULE{}) ->
    {Forms1, S1} = transform(Form0, S0),
    Forms1 ++ transform_all(Rest, S1).

transform(F = {attribute, _L, record, {RecName, Fields}}, S0) ->
    #?MODULE{records = R0} = S0,
    FieldLookup = lists:foldl(fun
        ({typed_record_field, RF, VType}, Acc) ->
            case RF of
                {record_field, LL, {atom, _, Name}} ->
                    Acc#{Name => {{atom, LL, undefined}, VType}};
                {record_field, _, {atom, _, Name}, Default} ->
                    Acc#{Name => {Default, VType}}
            end;
        ({record_field, _, {atom, _, _Name}}, Acc) ->
            Acc;
        ({record_field, _, {atom, _, _Name}, _Default}, Acc) ->
            Acc;
        (_, Acc) ->
            Acc
    end, #{}, Fields),
    R1 = R0#{RecName => FieldLookup},
    S1 = S0#?MODULE{records = R1},
    {[F], S1};
transform(F = {attribute, _L, record, _Args}, _S0) ->
    error({unknown_record_format, F});
transform(F = {attribute, _L, type, {Name, InnerType, []}}, S0) ->
    #?MODULE{utypes = T0} = S0,
    T1 = T0#{Name => InnerType},
    S1 = S0#?MODULE{utypes = T1},
    {[F], S1};

transform({attribute, L, xpath, {FName, Expr}}, S0) ->
    transform({attribute, L, xpath, {FName, Expr, #{}}}, S0);
transform({attribute, L, xpath, {FName, Expr, NS}}, S0) ->
    XPath = xmlrat_xpath_parse:parse(Expr),
    FuncForms = xmlrat_xpath_compile:to_function_forms(FName, L, XPath, NS),
    {FuncForms, S0};
transform({attribute, _L, xpath, Args}, _S0) ->
    error({invalid_xpath, Args});

transform({attribute, L, xpath_record, {FName, RecName, FieldMap}}, S0) ->
    transform({attribute, L, xpath_record, {FName, RecName, FieldMap, #{}}}, S0);
transform({attribute, L, xpath_record, {FName, RecName, FieldMap, NS}}, S0) ->
    #?MODULE{records = R, utypes = UT, decoders = D0} = S0,
    case R of
        #{RecName := RF} -> ok;
        _ -> RF = #{}, error({undefined_record, RecName})
    end,
    BaseName = [$_ | atom_to_list(FName)],
    FieldLookup = maps:fold(fun (Field, Expr, Acc) ->
        FFName = list_to_atom(BaseName ++ "_" ++ atom_to_list(Field)),
        XPath = xmlrat_xpath_parse:parse(Expr),
        Forms = xmlrat_xpath_compile:to_function_forms(FFName, L, XPath, NS),
        Acc#{Field => {FFName, Forms}}
    end, #{}, FieldMap),
    PackFields = maps:fold(fun (Field, {FFName, _Forms}, Acc) ->
        #{Field := {Default, VType0}} = RF,
        VType1 = expand_utypes(VType0, UT),
        FieldForm = erl_syntax:record_field(
            erl_syntax:atom(Field),
            field_value_tree(Field, FFName, Default, VType1, D0)),
        [FieldForm | Acc]
    end, [], FieldLookup),
    Body = [
        erl_syntax:record_expr(
            erl_syntax:atom(RecName), PackFields)
    ],
    Clauses = [
        erl_syntax:clause(
            [erl_syntax:variable('Doc')], none, Body)
    ],
    FuncTree = erl_syntax:function(erl_syntax:atom(FName), Clauses),
    TopFuncForm0 = erl_syntax:revert(FuncTree),
    TopFuncForm1 = erl_parse:map_anno(fun (_) ->
        erl_anno:set_generated(true, L)
    end, TopFuncForm0),
    FuncForms = maps:fold(fun (_Field, {_FFName, Forms}, Acc) ->
        Acc ++ Forms
    end, [TopFuncForm1], FieldLookup),
    D1 = D0#{RecName => FName},
    S1 = S0#?MODULE{decoders = D1},
    {FuncForms, S1};
transform({attribute, _L, xpath_record, Args}, _S0) ->
    error({invalid_xpath_record, Args});

transform({attribute, L, xml_record, {FName, RecName, XmlTpl}}, S0) ->
    transform({attribute, L, xml_record, {FName, RecName, XmlTpl, #{}}}, S0);
transform({attribute, L, xml_record, {FName, RecName, XmlTpl, NS}}, S0) ->
    #?MODULE{records = R, utypes = UT, encoders = E0} = S0,
    case R of
        #{RecName := RF} -> ok;
        _ -> RF = #{}, error({undefined_record, RecName})
    end,
    Opts = #{
        namespaces => maps:merge(?tplns, NS),
        allow_unknown_entities => true
    },
    case xmlrat_parse:string(XmlTpl, Opts) of
        {ok, Doc} -> ok;
        {error, Why} ->
            Doc = [],
            error({template_parse_fail, Why})
    end,
    FieldVars = maps:fold(fun (Field, {Default, VType}, Acc) ->
        VarName = list_to_atom(
            string:titlecase(atom_to_list(RecName)) ++
            string:titlecase(atom_to_list(Field))),
        SubVarName = list_to_atom(
            "Sub" ++
            string:titlecase(atom_to_list(RecName)) ++
            string:titlecase(atom_to_list(Field))),
        Var = erl_syntax:variable(VarName),
        SubVar = erl_syntax:variable(SubVarName),
        Acc#{Field => {Default, VType, Var, SubVar}}
    end, #{}, RF),
    UnpackFields = maps:fold(fun (Field, {_Default, _VType, Var, _SVar}, Acc) ->
        [erl_syntax:record_field(erl_syntax:atom(Field),
                                 Var) | Acc]
    end, [], FieldVars),
    UnpackArg = erl_syntax:record_expr(erl_syntax:atom(RecName), UnpackFields),
    FieldMatches = maps:fold(fun (_Field, {Default, VType0, Var, SubVar}, Acc) ->
        VType1 = expand_utypes(VType0, UT),
        Tree = efield_value_tree(Var, Default, VType1, E0),
        Match = erl_syntax:match_expr(SubVar, Tree),
        [Match | Acc]
    end, [], FieldVars),
    FieldMap = maps:fold(fun (Field, {_Default, _VType, _Var, SubVar}, Acc) ->
        Acc#{atom_to_binary(Field) => SubVar}
    end, #{}, FieldVars),
    Body = FieldMatches ++ [
        erl_syntax:match_expr(
            erl_syntax:variable('Doc'),
            xmlrat_mini_xslt:to_expr(Doc, FieldMap)),
        erl_syntax:match_expr(
            erl_syntax:variable('NS'),
            erl_syntax:abstract(NS)),
        erl_syntax:match_expr(
            erl_syntax:variable('Opts1'),
            erl_syntax:map_expr(erl_syntax:variable('Opts0'),
                [erl_syntax:map_field_assoc(erl_syntax:atom(namespaces),
                                            erl_syntax:variable('NS'))
                 ])),
        erl_syntax:match_expr(
            erl_syntax:tuple([
                erl_syntax:atom(ok),
                erl_syntax:variable('Doc1')]),
            erl_syntax:application(
                erl_syntax:atom(xmlrat_parse), erl_syntax:atom(postprocess),
                [erl_syntax:variable('Doc'), erl_syntax:variable('Opts1')])),
        erl_syntax:application(
            erl_syntax:atom(xmlrat_parse), erl_syntax:atom(clean_whitespace),
            [erl_syntax:application(
                erl_syntax:atom(xmlrat_c14n),
                erl_syntax:atom(normalise_namespaces),
                [erl_syntax:variable('Doc1'),
                 erl_syntax:map_expr([])])])
    ],
    Clauses = [
        erl_syntax:clause([UnpackArg, erl_syntax:variable('Opts0')], none,
            Body)
    ],
    FuncTree = erl_syntax:function(erl_syntax:atom(FName), Clauses),

    FuncForm0 = erl_syntax:revert(FuncTree),
    FuncForm1 = erl_parse:map_anno(fun (_) ->
        erl_anno:set_generated(true, L)
    end, FuncForm0),

    WFuncTree = erl_syntax:function(erl_syntax:atom(FName), [
        erl_syntax:clause([erl_syntax:variable('Rec')], none,
            [erl_syntax:application(erl_syntax:atom(FName), [
                erl_syntax:variable('Rec'), erl_syntax:map_expr([])])])
        ]),
    WFuncForm0 = erl_syntax:revert(WFuncTree),
    WFuncForm1 = erl_parse:map_anno(fun (_) ->
        erl_anno:set_generated(true, L)
    end, WFuncForm0),

    E1 = E0#{RecName => FName},
    S1 = S0#?MODULE{encoders = E1},
    {[FuncForm1,WFuncForm1], S1};
transform({attribute, _L, xml_record, Args}, _S0) ->
    error({invalid_xml_gen, Args});

transform(Other, S0) ->
    {[Other], S0}.

expand_utypes({user_type, _, T, []}, UT) ->
    case UT of
        #{T := Def} -> Def;
        _ -> error({unknown_type, T})
    end;
expand_utypes({type, L, union, Opts}, UT) ->
    {type, L, union, [expand_utypes(X, UT) || X <- Opts]};
expand_utypes({type, L, list, ElemTypes}, UT) ->
    {type, L, list, [expand_utypes(X, UT) || X <- ElemTypes]};
expand_utypes(Other, _UT) -> Other.

expand_subunions([]) -> [];
expand_subunions([{type, _L, union, Opts} | Rest]) ->
    Opts ++ expand_subunions(Rest);
expand_subunions([Next | Rest]) ->
    [Next | expand_subunions(Rest)].

to_scalar(Var) ->
    erl_syntax:application(
        erl_syntax:atom(xmlrat_xpath_utils),
        erl_syntax:atom(to_scalar),
        [Var]).

catch_chain([Term]) ->
    Term;
catch_chain([Term | Rest]) ->
    Var = erl_syntax:variable(list_to_atom("Var" ++
        integer_to_list(erlang:unique_integer([positive])))),
    erl_syntax:case_expr(
        erl_syntax:catch_expr(Term),
        [erl_syntax:clause(
            [erl_syntax:tuple([
                erl_syntax:atom('EXIT'),
                erl_syntax:underscore()])],
            none,
            [catch_chain(Rest)]),
         erl_syntax:clause(
            [Var], none,
            [Var])]).

wrap_convert(Tree0, {type, _, binary, []}, _D) ->
    to_scalar(Tree0);
wrap_convert(Tree0, {type, _, string, []}, _D) ->
    erl_syntax:application(
        erl_syntax:atom(unicode),
        erl_syntax:atom(characters_to_list),
        [to_scalar(Tree0), erl_syntax:atom(utf8)]);
wrap_convert(Tree0, {type, _, integer, []}, _D) ->
    erl_syntax:application(
        erl_syntax:atom(binary_to_integer),
        [to_scalar(Tree0)]);
wrap_convert(Tree0, {type, _, atom, []}, _D) ->
    erl_syntax:application(
        erl_syntax:atom(binary_to_existing_atom),
        [to_scalar(Tree0)]);
wrap_convert(Tree0, {type, _, boolean, []}, _D) ->
    erl_syntax:case_expr(to_scalar(Tree0), [
        erl_syntax:clause([erl_syntax:binary([])], none, [erl_syntax:atom(false)]),
        erl_syntax:clause([erl_syntax:atom(undefined)], none, [erl_syntax:atom(false)]),
        erl_syntax:clause([erl_syntax:list([])], none, [erl_syntax:atom(false)]),
        erl_syntax:clause([erl_syntax:binary([erl_syntax:binary_field(erl_syntax:string("false"))])], none, [erl_syntax:atom(false)]),
        erl_syntax:clause([erl_syntax:underscore()], none, [erl_syntax:atom(true)])
        ]);
wrap_convert(Tree0, {remote_type, _, [{atom,_,xmlrat}, {atom,_,tag}, []]}, _D) ->
    Tree0;
wrap_convert(Tree0, {type, _, record, [{atom, _, Rec}]}, D) ->
    case D of
        #{Rec := DecoderFunc} -> ok;
        _ -> DecoderFunc = none, error({non_xpath_record, Rec})
    end,
    Flattened = erl_syntax:application(
        erl_syntax:atom(lists), erl_syntax:atom(flatten),
        [erl_syntax:list([Tree0])]),
    erl_syntax:application(
        erl_syntax:atom(DecoderFunc),
        [Flattened]);
wrap_convert(Tree0, {type, _, list, [T]}, D) ->
    erl_syntax:list_comp(
        wrap_convert(erl_syntax:variable('X'), T, D),
        [erl_syntax:generator(
            erl_syntax:variable('X'),
            Tree0)]);
wrap_convert(Tree0, {type, L, union, Opts}, D) ->
    WithoutUndef = lists:filter(fun
        ({atom, _, undefined}) -> false;
        (_) -> true
    end, expand_subunions(Opts)),
    Types = lists:usort(
        [{T, A} || {type, _, T, A} <- WithoutUndef, is_list(A)]),
    EnumValTypes = lists:usort([T || {T, _Loc, _V} <- WithoutUndef]),
    EnumErrClause = erl_syntax:clause(
        [erl_syntax:underscore()], none,
        [erl_syntax:application(
            erl_syntax:atom(error),
            [erl_syntax:tuple([
                erl_syntax:atom(invalid_enum_value),
                Tree0])])]),
    case {Types, EnumValTypes} of
        {[_|_], []} ->
            Exprs = [wrap_convert(Tree0, {type, L, Type, Args}, D)
                || {Type,Args} <- Types],
            catch_chain(Exprs);
        {[], [integer]} ->
            Clauses = lists:foldl(fun ({integer, _, V}, Acc) ->
                Clause = erl_syntax:clause(
                    [erl_syntax:binary([
                        erl_syntax:binary_field(
                            erl_syntax:string(integer_to_list(V)))])],
                    none,
                    [erl_syntax:integer(V)]),
                [Clause | Acc]
            end, [EnumErrClause], WithoutUndef),
            erl_syntax:case_expr(to_scalar(Tree0), Clauses);
        {[], [atom]} ->
            Clauses = lists:foldl(fun ({atom, _, V}, Acc) ->
                Clause = erl_syntax:clause(
                    [erl_syntax:binary([
                        erl_syntax:binary_field(
                            erl_syntax:string(atom_to_list(V)))])],
                    none,
                    [erl_syntax:atom(V)]),
                [Clause | Acc]
            end, [EnumErrClause], WithoutUndef),
            erl_syntax:case_expr(to_scalar(Tree0), Clauses);
        {[], _} ->
            error({mixed_enum_types, EnumValTypes})
    end.

field_value_tree(Field, FFName, Default, VType, D0) ->
    FieldVarName = list_to_atom("Field" ++
        string:titlecase(atom_to_list(Field))),
    FieldVar = erl_syntax:variable(FieldVarName),
    DefForm = case {Default, is_optional(VType)} of
        {{atom, _, undefined}, false} ->
            erl_syntax:application(
                erl_syntax:atom(error),
                [erl_syntax:tuple([
                    erl_syntax:atom(required_field),
                    erl_syntax:atom(Field)])]);
        _ ->
            {ok, [Form]} = erl_parse:parse_exprs([Default, {dot, 0}]),
            Form
    end,
    Clauses = [
        erl_syntax:clause(
            [erl_syntax:list([])], none,
            [DefForm]),
        erl_syntax:clause(
            [erl_syntax:binary([])], none,
            [DefForm]),
        erl_syntax:clause(
            [FieldVar], none,
            [wrap_convert(FieldVar, VType, D0)])
    ],
    erl_syntax:case_expr(
        erl_syntax:application(
            erl_syntax:atom(FFName),
            [erl_syntax:variable('Doc')]),
        Clauses).

wrap_econvert(Tree0, {type, _, binary, []}, _D) ->
    Tree0;
wrap_econvert(Tree0, {type, _, string, []}, _D) ->
    erl_syntax:application(
        erl_syntax:atom(unicode), erl_syntax:atom(characters_to_binary),
        [Tree0, erl_syntax:atom(utf8)]);
wrap_econvert(Tree0, {type, _, integer, []}, _D) ->
    erl_syntax:application(
        erl_syntax:atom(integer_to_binary),
        [Tree0]);
wrap_econvert(Tree0, {type, _, atom, []}, _D) ->
    erl_syntax:application(
        erl_syntax:atom(atom_to_binary),
        [Tree0]);
wrap_econvert(Tree0, {type, _, boolean, []}, _D) ->
    Tree0;
wrap_econvert(Tree0, {remote_type, _, [{atom,_,xmlrat}, {atom,_,tag}, []]}, _D) ->
    Tree0;
wrap_econvert(Tree0, {type, _, record, [{atom, _, Rec}]}, E) ->
    case E of
        #{Rec := EncoderFunc} -> ok;
        _ -> EncoderFunc = none, error({non_xml_record, Rec})
    end,
    erl_syntax:application(
        erl_syntax:atom(EncoderFunc),
        [Tree0, erl_syntax:variable('Opts0')]);
wrap_econvert(Tree0, {type, _, list, [T]}, D) ->
    erl_syntax:list_comp(
        wrap_econvert(erl_syntax:variable('X'), T, D),
        [erl_syntax:generator(
            erl_syntax:variable('X'),
            Tree0)]);
wrap_econvert(Tree0, {type, L, union, Opts}, D) ->
    WithoutUndef = lists:filter(fun
        ({atom, _, undefined}) -> false;
        (_) -> true
    end, expand_subunions(Opts)),
    Types = lists:usort(
        [{T, A} || {type, _, T, A} <- WithoutUndef, is_list(A)]),
    EnumValTypes = lists:usort([T || {T, _Loc, _V} <- WithoutUndef]),
    case {Types, EnumValTypes} of
        {[_|_], []} ->
            Exprs = [wrap_econvert(Tree0, {type, L, Type, Args}, D)
                || {Type, Args} <- Types],
            catch_chain(Exprs);
        {[], [integer]} ->
            Clauses = lists:foldl(fun ({integer, _, V}, Acc) ->
                Clause = erl_syntax:clause(
                    [erl_syntax:integer(V)], none,
                    [erl_syntax:binary([
                        erl_syntax:binary_field(
                            erl_syntax:string(integer_to_list(V)))])]),
                [Clause | Acc]
            end, [], WithoutUndef),
            erl_syntax:case_expr(Tree0, Clauses);
        {[], [atom]} ->
            Clauses = lists:foldl(fun ({atom, _, V}, Acc) ->
                Clause = erl_syntax:clause(
                    [erl_syntax:atom(V)], none,
                    [erl_syntax:binary([
                        erl_syntax:binary_field(
                            erl_syntax:string(atom_to_list(V)))])]),
                [Clause | Acc]
            end, [], WithoutUndef),
            erl_syntax:case_expr(Tree0, Clauses);
        {[], _} ->
            error({mixed_enum_types, EnumValTypes})
    end.

efield_value_tree(Var, _Default, VType, E0) ->
    case is_optional(VType) of
        true ->
            erl_syntax:case_expr(Var, [
                erl_syntax:clause([erl_syntax:atom(undefined)], none,
                    [erl_syntax:list([])]),
                erl_syntax:clause([erl_syntax:underscore()], none,
                    [wrap_econvert(Var, VType, E0)])
            ]);
        _ ->
            wrap_econvert(Var, VType, E0)
    end.
