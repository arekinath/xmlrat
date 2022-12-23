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

%% @doc Implements the "mxsl" subset/dialect of XSLT used for compiled XML
%%      templates.
%%
%% This template language is used in the <code>-xml_record()</code> attribute
%% provided by {@link xmlrat_parse_transform}.
%%
%% == Introduction ==
%%
%% The MXSL language is designed to look and feel a lot like XSLT, but with
%% some modifications (due to the fact that the input data is Erlang records
%% and not XML/XPath), and some abbreviations to make templates easier to
%% read and write.
%%
%% As well as the normal XSLT-style use of namespaced elements to substitute
%% values (e.g. <code>&lt;mxsl:value-of field='...'/&gt;</code>), MXSL also
%% supports using XML entities named after each record field for substitution.
%%
%% A short example of an MXSL template, showing both an XSLT-style substitution
%% and an entity substitution:
%% <pre>
%%   &lt;KeyInfo&gt;
%%     &lt;mxsl:if defined='name'&gt;
%%       &lt;KeyName&gt;&lt;mxsl:value-of field='name'/&gt;&lt;/KeyName&gt;
%%     &lt;/mxsl:if&gt;
%%     &lt;KeyType Algorithm='&amp;algorithm;'/&gt;
%%   &lt;/KeyInfo&gt;
%% </pre>
%%
%% The <code>mxsl:</code> namespace URI is
%% <code>https://cooperi.net/xmlrat/mini-xslt/</code>. Templates can either
%% use the pre-defined namespace prefix <code>mxsl:</code>, or define their
%% own in the regular way using <code>xmlns:*</code> attributes.
%%
%% == MXSL element reference ==
%%
%% === &lt;mxsl:value-of&gt; ===
%%
%% Substitutes with the value of a record field. The <code>mxsl:value-of</code>
%% element will be deleted, replaced with the record field's type-coerced value.
%%
%% Attributes:
%% <ul>
%%  <li><code>field</code>: specifies the name of the record field to
%%      substitute</li>
%% </ul>
%% Content:
%% <ul>
%%   <li>none</li>
%% </ul>
%%
%% === &lt;mxsl:attribute&gt; ===
%%
%% Adds an attribute to the parent element, with the new attribute's value
%% set by a record field. Can also be nested inside a
%% <code>&lt;mxsl:if&gt;</code> element (will add the attribute to the
%% grandparent).
%%
%% Attributes:
%% <ul>
%%  <li><code>name</code>: specifies the name of the attribute to add</li>
%%  <li><code>namespace</code>: specifies the namespace prefix of the
%%      attribute (optional)</li>
%%  <li><code>field</code>: specifies the name of the record field whose value
%%      will placed in the attribute</li>
%% </ul>
%% Content:
%% <ul>
%%   <li>none</li>
%% </ul>
%%
%% === &lt;mxsl:if&gt; ===
%%
%% Conditionally applies or includes some elements if a record field is
%% set to a value other than <code>undefined</code>, or set to boolean
%% <code>true</code>.
%%
%% Attributes:
%% <ul>
%%  <li><code>defined</code>: specifies the record field whose value will
%%      checked for <code>undefined</code></li>
%%  <li><code>true</code>: specifies the record field whose value will be
%%      checked for boolean <code>true</code></li>
%% </ul>
%% Content:
%% <ul>
%%   <li><code>&lt;mxsl:attribute&gt;</code></li>
%%   <li>any content element</li>
%% </ul>
%%
%% === &lt;mxsl:for-each&gt; ===
%%
%% Repeats a sub-tree of the document once for each element in a list. The
%% current element is bound as a "fake" record field (and can be referenced
%% by either <code>&lt;mxsl:value-of&gt;</code> etc or entities).
%%
%% Attributes:
%% <ul>
%%  <li><code>field</code>: specifies the name of the record field whose value
%%      will be iterated over</li>
%%  <li><code>as</code>: specifies the name of the pseudo-field which will be
%%      bound to each individual element in the list</li>
%% </ul>
%% Content:
%% <ul>
%%   <li>any content or MXSL element</li>
%% </ul>
%%
%% === &lt;mxsl:tag&gt; ===
%%
%% Generates an element with a dynamic tag name based on a record field.
%%
%% Attributes:
%% <ul>
%%  <li><code>mxsl:field</code>: specifies the record field whose contents will
%%      be used to rename this tag.</li>
%% </ul>
%% Content:
%% <ul>
%%   <li>any content or MXSL element</li>
%% </ul>
%%
%% The <code>mxsl:field</code> attribute will be elided from the output, but
%% all other attributes of the tag will be inherited by the final output tag.
%%
%% == Entities ==
%%
%% Within any element content or attribute value, entities may be used to refer
%% to the value of record fields. The entity name matches the record field
%% name exactly: e.g. <code>&amp;foobar;</code> refers to the value of record
%% field <code>foobar</code>.
%%
%% When used in an attribute value, if the field is set to
%% <code>undefined</code>, and the attribute value consists only of the field
%% entity, the entire attribute will be elided from the output.
%%
-module(xmlrat_mini_xslt).

-include_lib("xmlrat/include/records.hrl").

-export([to_expr/2]).

-define(mxsl, "https://cooperi.net/xmlrat/mini-xslt/").

-type subs_map() :: #{binary() => erl_syntax:syntaxTree()}.

%% @private
-spec to_expr(xmlrat:document(), subs_map()) -> erl_syntax:syntaxTree().
to_expr(Doc, Subs) ->
    ChildExprs = compile(Doc, Subs),
    erl_syntax:list(ChildExprs).

attrs_to_map(Attrs) ->
    A0 = lists:foldl(fun
        (#xml_attribute{name = {_, Name, _}, value = V}, Acc) ->
            Acc#{Name => V};
        (#xml_attribute{name = Name, value = V}, Acc) ->
            Acc#{Name => V};
        (_, Acc) ->
            Acc
    end, #{}, Attrs),
    lists:foldl(fun
        (#xml_attribute{name = {_, _, <<?mxsl, Name/binary>>}, value = V}, Acc) ->
            Acc#{Name => V};
        (_, Acc) ->
            Acc
    end, A0, Attrs).

remove_mxsl_attrs(Attrs) ->
    lists:filter(fun
        (#xml_attribute{name = {_, _, <<?mxsl, _/binary>>}}) -> false;
        (_) -> true
    end, Attrs).

string_bin(Bin) ->
    erl_syntax:binary([
        erl_syntax:binary_field(
            erl_syntax:string(
                unicode:characters_to_list(Bin, utf8)))
        ]).

name_to_expr({default, Name, URI}) ->
    erl_syntax:tuple([
        erl_syntax:atom(default),
        string_bin(Name),
        string_bin(URI)]);
name_to_expr({NS, Name, URI}) ->
    erl_syntax:tuple([
        string_bin(NS),
        string_bin(Name),
        string_bin(URI)]);
name_to_expr({default, Name}) ->
    erl_syntax:tuple([
        erl_syntax:atom(default),
        string_bin(Name)]);
name_to_expr({NS, Name}) ->
    erl_syntax:tuple([
        string_bin(NS),
        string_bin(Name)]);
name_to_expr(Name) ->
    string_bin(Name).

compile_dyn_attributes([], _) -> {[], []};
compile_dyn_attributes([Next | Rest], Subs) ->
    {Attrs0, Kids0} = compile_dyn_attributes(Rest, Subs),
    case Next of
        #xml_element{tag = {_, _, <<?mxsl, "if">>},
                     attributes  = Attrs,
                     content = Content0} ->
            {IfAttrs, Content1} = compile_dyn_attributes(Content0, Subs),
            case IfAttrs of
                [] ->
                    {Attrs0, [Next | Kids0]};
                _ ->
                    AttrMap = attrs_to_map(Attrs),
                    case AttrMap of
                        #{<<"true">> := Field} ->
                            case Subs of
                                #{Field := Expr} ->
                                    Wrapped = [erl_syntax:case_expr(
                                        Expr,
                                        [erl_syntax:clause(
                                            [erl_syntax:atom(false)], none,
                                            [erl_syntax:binary([])]),
                                         erl_syntax:clause(
                                            [erl_syntax:atom(true)], none,
                                            [X])
                                        ]) || X <- IfAttrs],
                                    E1 = Next#xml_element{content = Content1},
                                    {Wrapped ++ Attrs0, [E1 | Kids0]};
                                _ ->
                                    error({undefined_field, Field})
                            end;
                        #{<<"defined">> := Field} ->
                            case Subs of
                                #{Field := Expr} ->
                                    Wrapped = [erl_syntax:case_expr(
                                        Expr,
                                        [erl_syntax:clause(
                                            [erl_syntax:atom(undefined)], none,
                                            [erl_syntax:binary([])]),
                                         erl_syntax:clause(
                                            [erl_syntax:list([])], none,
                                            [erl_syntax:binary([])]),
                                         erl_syntax:clause(
                                            [erl_syntax:underscore()], none,
                                            [X])
                                        ]) || X <- IfAttrs],
                                    E1 = Next#xml_element{content = Content1},
                                    {Wrapped ++ Attrs0, [E1 | Kids0]};
                                _ ->
                                    error({undefined_field, Field})
                            end;
                        _ ->
                            error({bad_args, mxsl_if, AttrMap})
                    end
            end;

        #xml_element{tag = {_, _, <<?mxsl, "attribute">>},
                     attributes = Attrs,
                     content = Content0} ->
            Content1 = compile(Content0, Subs),
            AttrMap = attrs_to_map(Attrs),
            NameExpr = case AttrMap of
                #{<<"name">> := AttrName, <<"namespace">> := AttrNS} ->
                    erl_syntax:tuple([
                        string_bin(AttrNS),
                        string_bin(AttrName)
                        ]);
                #{<<"name">> := AttrName} ->
                    string_bin(AttrName);
                _ ->
                    error({bad_args, mxsl_attribute, AttrMap})
            end,
            Fields = [
                erl_syntax:record_field(
                    erl_syntax:atom(name),
                    NameExpr),
                erl_syntax:record_field(
                    erl_syntax:atom(value),
                    erl_syntax:application(
                        erl_syntax:atom(iolist_to_binary),
                        [erl_syntax:list(Content1)]))
            ],
            Attr = erl_syntax:record_expr(
                erl_syntax:atom(xml_attribute),
                Fields),
            {[Attr | Attrs0], Kids0};
        _ ->
            {Attrs0, [Next | Kids0]}
    end.

compile([], _) -> [];
compile([Next0 | Rest], Subs) ->
    Next1 = case Next0 of
        {entity, N} ->
            case Subs of
                #{N := Expr} -> [Expr];
                _ -> error({unknown_entity, N})
            end;
        #xml_namespace{name = default, uri = U} ->
            [erl_syntax:record_expr(
                erl_syntax:atom(xml_namespace),
                [erl_syntax:record_field(erl_syntax:atom(name),
                    erl_syntax:atom(default)),
                 erl_syntax:record_field(erl_syntax:atom(uri),
                    string_bin(U))
                ])];
        #xml_namespace{name = N, uri = U} ->
            [erl_syntax:record_expr(
                erl_syntax:atom(xml_namespace),
                [erl_syntax:record_field(erl_syntax:atom(name),
                    string_bin(N)),
                 erl_syntax:record_field(erl_syntax:atom(uri),
                    string_bin(U))
                ])];
        #xml_attribute{name = N, value = [{entity, Field}]} ->
            case Subs of
                #{Field := Expr} ->
                    Record = erl_syntax:record_expr(
                        erl_syntax:atom(xml_attribute),
                        [erl_syntax:record_field(erl_syntax:atom(name),
                            name_to_expr(N)),
                         erl_syntax:record_field(erl_syntax:atom(value),
                            Expr)
                        ]),
                    [erl_syntax:case_expr(
                        Expr,
                        [erl_syntax:clause(
                            [erl_syntax:atom(undefined)], none,
                            [erl_syntax:binary([])]),
                         erl_syntax:clause(
                            [erl_syntax:list([])], none,
                            [erl_syntax:binary([])]),
                         erl_syntax:clause(
                            [erl_syntax:underscore()], none,
                            [Record])
                        ])];
                _ ->
                    error({undefined_field, Field})
            end;
        #xml_attribute{name = N, value = V0} when is_list(V0) ->
            V1 = compile(V0, Subs),
            [erl_syntax:record_expr(
                erl_syntax:atom(xml_attribute),
                [erl_syntax:record_field(erl_syntax:atom(name),
                    name_to_expr(N)),
                 erl_syntax:record_field(erl_syntax:atom(value),
                    erl_syntax:application(
                        erl_syntax:atom(iolist_to_binary),
                        [erl_syntax:list(V1)]))
                ])];
        #xml_attribute{name = N, value = V} when is_binary(V) ->
            [erl_syntax:record_expr(
                erl_syntax:atom(xml_attribute),
                [erl_syntax:record_field(erl_syntax:atom(name),
                    name_to_expr(N)),
                 erl_syntax:record_field(erl_syntax:atom(value),
                    string_bin(V))
                ])];

        #xml_element{tag = {_, _, <<?mxsl, "if">>},
                     attributes = Attrs,
                     content = Content0} ->
            AttrMap = attrs_to_map(Attrs),
            case AttrMap of
                #{<<"true">> := Field} ->
                    case Subs of
                        #{Field := Expr} ->
                            [erl_syntax:case_expr(
                                Expr,
                                [erl_syntax:clause(
                                    [erl_syntax:atom(false)], none,
                                    [erl_syntax:binary([])]),
                                 erl_syntax:clause(
                                    [erl_syntax:atom(true)], none,
                                    [erl_syntax:list(compile(Content0, Subs))])
                                ])];
                        _ ->
                            error({undefined_field, Field})
                    end;
                #{<<"defined">> := Field} ->
                    case Subs of
                        #{Field := Expr} ->
                            [erl_syntax:case_expr(
                                Expr,
                                [erl_syntax:clause(
                                    [erl_syntax:atom(undefined)], none,
                                    [erl_syntax:binary([])]),
                                 erl_syntax:clause(
                                    [erl_syntax:list([])], none,
                                    [erl_syntax:binary([])]),
                                 erl_syntax:clause(
                                    [erl_syntax:underscore()], none,
                                    [erl_syntax:list(compile(Content0, Subs))])
                                ])];
                        _ ->
                            error({undefined_field, Field})
                    end;
                _ ->
                    error({bad_args, mxsl_if, AttrMap})
            end;

        #xml_element{tag = {_, _, <<?mxsl, "for-each">>},
                     attributes = Attrs,
                     content = Content0} ->
            AttrMap = attrs_to_map(Attrs),
            case AttrMap of
                #{<<"field">> := Field, <<"as">> := VarField} ->
                    case Subs of
                        #{Field := Expr} ->
                            VarFieldName = unicode:characters_to_list(
                                VarField, utf8),
                            VarName = list_to_atom(
                                "VarField" ++ string:titlecase(VarFieldName)),
                            Var = erl_syntax:variable(VarName),
                            Subs1 = Subs#{VarField => Var},
                            [erl_syntax:application(
                                erl_syntax:atom(lists),
                                erl_syntax:atom(flatten),
                                [erl_syntax:list_comp(
                                    erl_syntax:list(compile(Content0, Subs1)),
                                    [erl_syntax:generator(
                                        Var, Expr)])])];
                        _ ->
                            error({undefined_field, Field})
                    end;
                _ ->
                    error({bad_args, mxsl_for_each, AttrMap})
            end;

        #xml_element{tag = {_, _, <<?mxsl, "value-of">>},
                     attributes = Attrs,
                     content = []} ->
            AttrMap = attrs_to_map(Attrs),
            case AttrMap of
                #{<<"field">> := Field} ->
                    case Subs of
                        #{Field := Expr} -> [Expr];
                        _ -> error({invalid_substitution, Field})
                    end;
                _ ->
                    error({bad_args, mxsl_value_of, AttrMap})
            end;
        #xml_element{tag = {_, _, <<?mxsl, "value-of">>}} ->
            error({bad_args, mxsl_value_of, must_be_empty});

        #xml_element{tag = {_, _, <<?mxsl, "tag">>},
                     attributes = Attrs0,
                     content = Content0} ->
            AttrMap = attrs_to_map(Attrs0),
            case AttrMap of
                #{<<"field">> := Field} ->
                    case Subs of
                        #{Field := Expr} ->
                            Attrs1 = remove_mxsl_attrs(Attrs0),
                            Attrs2 = compile(Attrs1, Subs),
                            {DynAttrs, Content1} = compile_dyn_attributes(
                                Content0, Subs),
                            Content2 = erl_syntax:application(
                                erl_syntax:atom(lists),
                                erl_syntax:atom(flatten),
                                [erl_syntax:list(compile(Content1, Subs))]),
                            Attrs3 = Attrs2 ++ DynAttrs,
                            [erl_syntax:record_expr(
                                erl_syntax:atom(xml_element),
                                [erl_syntax:record_field(erl_syntax:atom(tag),
                                    Expr),
                                 erl_syntax:record_field(erl_syntax:atom(attributes),
                                    erl_syntax:list(Attrs3)),
                                 erl_syntax:record_field(erl_syntax:atom(content),
                                    Content2)
                                ])];
                        _ ->
                            error({undefined_field, Field})
                    end;
                _ ->
                    error({bad_args, mxsl_tag, AttrMap})
            end;

        #xml_element{tag = {_, _, <<?mxsl, Name/binary>>}} ->
            error({unsupported_mxsl_tag, Name});

        #xml_element{tag = Tag, attributes = Attrs0, content = Content0} ->
            Attrs1 = compile(Attrs0, Subs),
            {DynAttrs, Content1} = compile_dyn_attributes(Content0, Subs),
            Content2 = erl_syntax:application(
                erl_syntax:atom(lists),
                erl_syntax:atom(flatten),
                [erl_syntax:list(compile(Content1, Subs))]),
            Attrs2 = Attrs1 ++ DynAttrs,
            [erl_syntax:record_expr(
                erl_syntax:atom(xml_element),
                [erl_syntax:record_field(erl_syntax:atom(tag),
                    name_to_expr(Tag)),
                 erl_syntax:record_field(erl_syntax:atom(attributes),
                    erl_syntax:list(Attrs2)),
                 erl_syntax:record_field(erl_syntax:atom(content),
                    Content2)
                ])];

        Other ->
            [erl_syntax:abstract(Other)]
    end,
    Next1 ++ compile(Rest, Subs).
