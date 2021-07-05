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

%% @doc Serialise XML documents from parsed structures.
%%
%% This module is used to serialise an XML document (in the same form which
%% {@link xmlrat_parse} would produce) back to binaries.
%%
%% It supports some variations on the standard XML formatting, and includes
%% a rudimentary pretty-printer / indentation normaliser.
-module(xmlrat_generate).

-include("include/records.hrl").

-export([string/1, string/2]).

-record(?MODULE, {
    comments = true :: boolean(),
    squotes = true :: boolean(),
    selfclose = true :: boolean(),
    doctypes = true :: boolean(),
    trimattrs = false :: boolean()
    }).

-type options() :: #{
    normalise_whitespace => boolean(),
    indent => boolean(),
    indentation_unit => binary(),
    comments => boolean(),
    doctypes => boolean(),
    single_quotes => boolean(),
    self_closing_tags => boolean(),
    trim_attributes => boolean() }.
%% <ul>
%%   <li><code>normalise_whitespace</code>: if true, run
%%       {@link xmlrat_parse:clean_whitespace/1} on the document before
%%       serialising it</li>
%%   <li><code>indent</code>: if true, pretty-print / re-indent the document
%%       before serialising</li>
%%   <li><code>indentation_unit</code>: the unit of whitespace used for
%%       indentation when <code>indent</code> is <code>true</code>. Defaults
%%       to <code>&lt;&lt;"  "&gt;&gt;</code> (2 spaces).</li>
%%   <li><code>comments</code>: if false, elide comments from the output</li>
%%   <li><code>doctypes</code>: if false, elide DTDs from the output</li>
%%   <li><code>single_quotes</code>: if false, disable the use of single-quotes
%%       around attribute values (by default single quotes are used for values
%%       which include double-quote characters)</li>
%%   <li><code>self_closing_tags</code>: if false, disable the use of
%%       self-closing tags (<code>&lt;foobar/&gt;</code>): instead always
%%       generate a separate open and close tag</li>
%%   <li><code>trim_atttributes</code>: if true, trim whitespace from the start
%%       and end of all attribute values</li>
%% </ul>

%% @doc Serialises a document to a binary string.
-spec string(xmlrat:document()) -> binary().
string(Root0) ->
    string(Root0, #{}).

%% @doc Serialises a document to a binary string, with options.
-spec string(xmlrat:document(), options()) -> binary().
string(Root0, Opts) ->
    {ok, Root1} = xmlrat_parse:postprocess(Root0, #{}),
    WSNorm = maps:get(normalise_whitespace, Opts, false),
    Root2 = case WSNorm of
        false -> Root1;
        true -> xmlrat_parse:clean_whitespace(Root1)
    end,
    Indent = maps:get(indent, Opts, false),
    Unit = maps:get(indentation_unit, Opts, <<"  ">>),
    Root3 = case Indent of
        false -> Root2;
        true -> reduce_binaries(indent(0, Unit, Root2))
    end,
    M = #?MODULE{comments = maps:get(comments, Opts, true),
                 squotes = maps:get(single_quotes, Opts, true),
                 selfclose = maps:get(self_closing_tags, Opts, true),
                 doctypes = maps:get(doctypes, Opts, true),
                 trimattrs = maps:get(trim_attributes, Opts, false)},
    iolist_to_binary(stringify(Root3, M)).

reindent_lines(Indent, [Line | Rest]) when
                                (byte_size(Line) + byte_size(Indent) > 80) ->
    SplitAround = 80 - byte_size(Indent),
    Scope = {SplitAround - 20, 21},
    SplitAt = case binary:match(Line, [<<" ">>], [{scope, Scope}]) of
        {Pos, 1} -> Pos;
        nomatch -> SplitAround
    end,
    <<Line0:SplitAt/binary, Line1/binary>> = Line,
    reindent_lines(Indent, [Line0, Line1 | Rest]);
reindent_lines(_Indent, []) -> [];
reindent_lines(Indent, [Line | Rest]) ->
    case string:trim(Line, both) of
        <<>> ->
            [<<>> | reindent_lines(Indent, Rest)];
        Trimmed ->
            [[Indent, Trimmed] | reindent_lines(Indent, Rest)]
    end.

reindent_bin(Indent, Bin0) ->
    Lines0 = binary:split(Bin0, [<<"\n">>], [global]),
    Lines1 = reindent_lines(Indent, Lines0),
    NonEmpty = [X || X <- Lines1, X =/= <<>>],
    {iolist_to_binary(lists:join(<<$\n>>, Lines1)), length(NonEmpty)}.

trim_front([<<>> | Rest]) ->
    trim_front(Rest);
trim_front(List) -> List.

trim_back([]) -> [];
trim_back(List) ->
    case lists:last(List) of
        <<>> -> trim_back(lists:droplast(List));
        _ -> List
    end.

trim_ends(C0) ->
    C1 = reduce_binaries(C0),
    C2 = case C1 of
        [First0 | Rest] when is_binary(First0) ->
            FLines0 = binary:split(First0, [<<"\n">>], [global]),
            FLines1 = trim_front(FLines0),
            [iolist_to_binary(lists:join(<<$\n>>, FLines1)) | Rest];
        _ ->
            C1
    end,
    case C2 of
        [] -> [];
        _ ->
            case lists:last(C2) of
                Last0 when is_binary(Last0) ->
                    LLines0 = binary:split(Last0, [<<"\n">>], [global]),
                    LLines1 = trim_back(LLines0),
                    lists:droplast(C2) ++ [
                        iolist_to_binary(lists:join(<<$\n>>, LLines1))];
                _ ->
                    C2
            end
    end.

-spec indent(integer(), binary(), xmlrat:document()) -> xmlrat:document().
indent(_Level, _Unit, []) ->
    [];
indent(0, Unit, [B | Rest]) when is_binary(B) ->
    indent(0, Unit, Rest);
indent(Level, Unit, [Next0 | Rest]) ->
    Indent = binary:copy(Unit, Level),
    Next1 = case Next0 of
        _ when is_binary(Next0) ->
            case reindent_bin(Indent, Next0) of
                {<<>>, _} -> [];
                {Other, 0} -> [Other];
                {Other, _N} -> [Other, <<"\n">>]
            end;

        #xml_element{attributes = Attrs0, content = Content0} ->
            SubIndent = binary:copy(Unit, Level + 2),
            Attrs1 = lists:map(fun
                (B) when is_binary(B) ->
                    case binary:matches(B, <<"\n">>) of
                        [_|_] -> <<"\n", SubIndent/binary>>;
                        _ -> <<" ">>
                    end;
                (Other) -> Other
            end, Attrs0),
            Content1 = case Content0 of
                [] ->
                    [];
                [B2] when is_binary(B2) and (byte_size(B2) < 50) ->
                    case string:trim(B2, both) of
                        <<>> -> [];
                        B2T -> [B2T]
                    end;
                _ ->
                    CC0 = indent(Level + 1, Unit, Content0),
                    CC1 = trim_ends(CC0),
                    [<<"\n">>] ++ CC1 ++ [<<"\n", Indent/binary>>]
            end,
            Content2 = reduce_binaries(Content1),
            [Indent, Next0#xml_element{attributes = Attrs1,
                                       content = Content2}, <<"\n">>];

        #xml_comment{text = Text0} ->
            SubIndent = binary:copy(Unit, Level + 1),
            Lines0 = binary:split(Text0, [<<"\n">>], [global]),
            Lines1 = [[SubIndent, string:trim(L, both)] || L <- Lines0],
            Text1 = iolist_to_binary(lists:join(<<$\n>>, Lines1)),
            [Indent, Next0#xml_comment{text = Text1}, <<"\n">>];

        #xml_pi{options = Text0} when is_binary(Text0) ->
            SubIndent = binary:copy(Unit, Level + 1),
            Lines0 = binary:split(Text0, [<<"\n">>], [global]),
            Lines1 = [[SubIndent, string:trim(L, both)] || L <- Lines0],
            Text1 = iolist_to_binary(lists:join(<<$\n>>, Lines1)),
            [Indent, Next0#xml_pi{options = Text1}, <<"\n">>];

        #xml_pi{options = Attrs0} when is_list(Attrs0) ->
            Attrs1 = indent(Level + 2, Unit, Attrs0),
            [Indent, Next0#xml_pi{options = Attrs1}, <<"\n">>];

        _ ->
            [Indent, Next0, <<"\n">>]
    end,
    reduce_binaries(Next1) ++ indent(Level, Unit, Rest).

stringify_name({default, Name, _Uri}) ->
    Name;
stringify_name({NS, Name, _Uri}) ->
    [NS, <<$:>>, Name];
stringify_name({NS, Name}) ->
    [NS, <<$:>>, Name];
stringify_name(Name) when is_binary(Name) ->
    Name.

stringify_quoted_string(V0, #?MODULE{squotes = UseSingleQuotes,
                                     trimattrs = TrimAttrs}) ->
    V1 = binary:replace(V0, <<$&>>, <<"&amp;">>, [global]),
    V2 = binary:replace(V1, <<$<>>, <<"&lt;">>, [global]),
    V3 = binary:replace(V2, <<$\n>>, <<"&#xA;">>, [global]),
    V4 = binary:replace(V3, <<$\t>>, <<"&#x9;">>, [global]),
    V5 = binary:replace(V4, <<$\r>>, <<"&#xD;">>, [global]),
    V6 = case TrimAttrs of
        true -> string:trim(V5, both);
        false -> V5
    end,
    case binary:match(V6, [<<$">>]) of
        nomatch ->
            [<<$">>, V6, <<$">>];
        _ when UseSingleQuotes ->
            case binary:match(V6, [<<$'>>]) of
                nomatch ->
                    [<<$'>>, V6, <<$'>>];
                _ ->
                    V7 = binary:replace(V6, <<$'>>, <<"&apos;">>, [global]),
                    V8 = binary:replace(V7, <<$">>, <<"&quot;">>, [global]),
                    [<<$">>, V8, <<$">>]
            end;
        _ ->
            V7 = binary:replace(V6, <<$'>>, <<"&apos;">>, [global]),
            V8 = binary:replace(V7, <<$">>, <<"&quot;">>, [global]),
            [<<$">>, V8, <<$">>]
    end.

stringify([], #?MODULE{}) ->
    [];
stringify([Last], M = #?MODULE{}) ->
    stringify(Last, M);
stringify([A = #xml_attribute{}, B = #xml_attribute{} | Rest], M) ->
    stringify([A, attrspace, B | Rest], M);
stringify([A = #xml_namespace{}, B = #xml_namespace{} | Rest], M) ->
    stringify([A, attrspace, B | Rest], M);
stringify([A = #xml_attribute{}, B = #xml_namespace{} | Rest], M) ->
    stringify([A, attrspace, B | Rest], M);
stringify([A = #xml_namespace{}, B = #xml_attribute{} | Rest], M) ->
    stringify([A, attrspace, B | Rest], M);
stringify([Next | Rest], M) ->
    [stringify(Next, M) | stringify(Rest, M)];

stringify(attrspace, #?MODULE{}) ->
    <<" ">>;

stringify(B0, #?MODULE{}) when is_binary(B0) ->
    B1 = binary:replace(B0, <<$&>>, <<"&amp;">>, [global]),
    B2 = binary:replace(B1, <<$<>>, <<"&lt;">>, [global]),
    binary:replace(B2, <<$>>>, <<"&gt;">>, [global]);

stringify(#xml_attribute{name = Name0, value = Value0}, M = #?MODULE{}) ->
    Name1 = stringify_name(Name0),
    Value1 = iolist_to_binary(Value0),
    Value2 = stringify_quoted_string(Value1, M),
    [Name1, <<$=>>, Value2];

stringify(#xml_namespace{name = default, uri = URI0}, M = #?MODULE{}) ->
    URI1 = iolist_to_binary(URI0),
    URI2 = stringify_quoted_string(URI1, M),
    [<<"xmlns=">>, URI2];
stringify(#xml_namespace{name = NS, uri = URI0}, M = #?MODULE{}) ->
    Name = stringify_name({<<"xmlns">>, NS}),
    URI1 = iolist_to_binary(URI0),
    URI2 = stringify_quoted_string(URI1, M),
    [Name, <<$=>>, URI2];

stringify(#xml_comment{text = Txt}, #?MODULE{comments = true}) ->
    [<<"<!--">>, Txt, <<"-->">>];
stringify(#xml_comment{text = _Txt}, #?MODULE{comments = false}) ->
    [];

stringify(#xml_doctype{}, #?MODULE{doctypes = false}) ->
    [];

stringify(#xml_pi{target = Target, options = B}, _) when is_binary(B) ->
    BS = case B of
        <<>> -> <<>>;
        _ -> [<<" ">>, B]
    end,
    [<<"<?">>, Target, BS, <<"?>">>];
stringify(#xml_pi{target = Target, options = Opts}, M0) ->
    OptString = case Opts of
        [] -> [];
        _ -> [<<" ">> | stringify(Opts, M0)]
    end,
    [<<"<?">>, Target, OptString, <<"?>">>];

stringify(#xml{version = Ver, encoding = Enc, standalone = SD}, _) ->
    OptString = [
        case Enc of
            undefined -> [];
            _ -> [<<" encoding=\"">>, Enc, <<$">>]
        end,
        case SD of
            undefined -> [];
            yes -> <<" standalone=\"yes\"">>;
            no -> <<" standalone=\"no\"">>
        end
    ],
    [<<"<?xml version=\"">>, Ver, <<"\"">>, OptString, <<"?>">>];

stringify(#xml_element{tag = Tag0, attributes = Attrs0, content = []},
                                            M0 = #?MODULE{selfclose = true}) ->
    Tag1 = stringify_name(Tag0),
    Attrs1 = case Attrs0 of
        [] -> [];
        [B | _] when is_binary(B) -> stringify(Attrs0, M0);
        _ -> [<<" ">> | stringify(Attrs0, M0)]
    end,
    [<<$<>>, Tag1, Attrs1, <<"/>">>];
stringify(#xml_element{tag = Tag0, attributes = Attrs0, content = Content0}, M0) ->
    Tag1 = stringify_name(Tag0),
    Attrs1 = case Attrs0 of
        [] -> [];
        [B | _] when is_binary(B) -> stringify(Attrs0, M0);
        _ -> [<<" ">> | stringify(Attrs0, M0)]
    end,
    Content1 = stringify(Content0, M0),
    [<<$<>>, Tag1, Attrs1, <<$>>>, Content1, <<"</">>, Tag1, <<$>>>].

reduce_binaries([]) -> [];
reduce_binaries([Bin0, Bin1 | Rest]) when is_binary(Bin0) and is_binary(Bin1) ->
    reduce_binaries([<<Bin0/binary, Bin1/binary>> | Rest]);
reduce_binaries([<<>> | Rest]) ->
    reduce_binaries(Rest);
reduce_binaries([Other | Rest]) ->
    [Other | reduce_binaries(Rest)].

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

stringify_xmldecl_test() ->
    Doc = [#xml{version = <<"1.0">>,
                encoding = <<"utf-8">>}],
    Res = string(Doc),
    ?assertMatch(<<"<?xml version=\"1.0\" encoding=\"utf-8\"?>">>,
                 Res).

stringify_element_test() ->
    Doc = [#xml{version = <<"1.0">>,
                encoding = <<"utf-8">>},
           #xml_element{tag = <<"foo">>}],
    Res = string(Doc),
    ?assertMatch(<<"<?xml version=\"1.0\" encoding=\"utf-8\"?><foo/>">>,
                 Res).

stringify_element_indent_test() ->
    Doc = [#xml{version = <<"1.0">>,
                encoding = <<"utf-8">>},
           #xml_element{tag = <<"foo">>, content = [
                #xml_element{tag = <<"bar">>, content = [<<"   hi">>]},
                #xml_element{tag = <<"baz">>}
           ]}],
    Res = string(Doc, #{indent => true, normalise_whitespace => true}),
    io:format("~s\n", [Res]),
    ?assertMatch(<<
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<foo>\n"
        "  <bar>hi</bar>\n"
        "  <baz/>\n"
        "</foo>\n">>, Res).

indent_2_test() ->
    String = <<
        "<doc attr='foo' \n"
        "     otherattr='bar' >\n"
        "  <bar foobar='test'> </bar>\n"
        " <baz>\n"
        "\n"
        "         <test> something</test>\n"
        "</baz></doc>\n"
        >>,
    {ok, Doc} = xmlrat_parse:string(String),
    Res0 = xmlrat_generate:string(Doc),
    StringDQ = binary:replace(String, [<<$'>>], <<$">>, [global]),
    ?assertMatch(StringDQ, Res0),
    Res1 = xmlrat_generate:string(Doc, #{
        normalise_whitespace => true,
        indent => true
        }),
    io:format("\n\n~s\n\n~p\n\n~p\n\n", [Res1, Doc, indent(0, <<"  ">>, xmlrat_parse:clean_whitespace(Doc))]),
    ?assertMatch(<<
        "<doc attr=\"foo\"\n"
        "    otherattr=\"bar\">\n"
        "  <bar foobar=\"test\"/>\n"
        "\n"
        "  <baz>\n"
        "    <test>something</test>\n"
        "  </baz>\n"
        "</doc>\n">>, Res1).

stringify_elem_attrs_test() ->
    Doc = [#xml{version = <<"1.0">>,
                encoding = <<"utf-8">>},
           #xml_element{tag = <<"foo">>, attributes = [
                          #xml_attribute{name = <<"id">>, value = <<"1">>}],
                        content = [
                #xml_element{tag = <<"bar">>, attributes = [
                    #xml_attribute{name = <<"attr">>, value = <<" what ">>},
                    #xml_attribute{name = <<"baz">>, value = <<"\";&">>}
                ]}
           ]}],
    Res = string(Doc),
    ?assertMatch(<<"<?xml version=\"1.0\" encoding=\"utf-8\"?><foo id=\"1\">"
        "<bar attr=\" what \" baz='\";&amp;'/></foo>">>,
        Res).

stringify_elem_attrs_2_test() ->
    Doc = [#xml{version = <<"1.0">>,
                encoding = <<"utf-8">>},
           #xml_element{tag = <<"foo">>, attributes = [
                          #xml_attribute{name = <<"id">>, value = <<"1">>}],
                        content = [
                #xml_element{tag = <<"bar">>, attributes = [
                    #xml_attribute{name = <<"attr">>, value = <<"  what ">>},
                    #xml_attribute{name = <<"baz">>, value = <<"\";&">>}
                ]}
           ]}],
    Res = string(Doc, #{
        single_quotes => false,
        normalise_whitespace => true,
        trim_attributes => true}),
    ?assertMatch(<<"<?xml version=\"1.0\" encoding=\"utf-8\"?><foo id=\"1\">"
        "<bar attr=\"what\" baz=\"&quot;;&amp;\"/></foo>">>,
        Res).

-endif.
