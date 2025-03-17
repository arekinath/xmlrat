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
-module(xmlrat_xpath_test).

-compile({parse_transform, xmlrat_parse_transform}).
-compile(nowarn_unused_function).

-export([
    match_test/1, match_foobar/1, match_nstest_item/1,
    match_nstest/1, gen_nstest_item/1, gen_nstest/1]).

-include_lib("xmlrat/include/records.hrl").

-type uid() :: binary().

-type thing() :: foo | bar | baz.

-record(nstestitem, {
    id :: integer(),
    testing = false :: boolean(),
    number :: undefined | integer(),
    values :: [binary()]
    }).
-type testitem() :: #nstestitem{}.

-record(foobar, {
    a :: integer(),
    b :: undefined | uid(),
    c = foo :: thing()
    }).
-record(nstest, {
    name :: binary(),
    items :: [testitem()]
    }).

-define(namespaces, #{
    <<"root">> => <<"urn:root:">>,
    <<"test">> => <<"urn:test:">>
    }).

-xpath({match_test, "/foo/bar/@id"}).

-xpath_record({match_foobar, foobar, #{
    a => "/foobar/attr[@name = 'a']/@value",
    b => "/foobar/attr[@name = 'b']/text()",
    c => "/foobar/@c"
    }}).

-xpath_record({match_nstest_item, nstestitem, #{
    id => "/test:item/@id",
    testing => "/test:item/@testing",
    number => "/test:item/@number",
    values => "/test:item/test:value"
    }, ?namespaces}).

-xpath_record({match_nstest, nstest, #{
    name => "/root:nstest/@name",
    items => "/root:nstest/test:item"
    }, ?namespaces}).

-xml_record({gen_nstest_item, nstestitem,
    "<test:item xmlns:test='urn:test:'>"
        "<mxsl:attribute name='id'><mxsl:value-of field='id'/></mxsl:attribute>"
        "<mxsl:if true='testing'>"
            "<mxsl:attribute name='testing'>yes</mxsl:attribute>"
        "</mxsl:if>"
        "<mxsl:if defined='number'>"
            "<mxsl:attribute name='number'>&number;</mxsl:attribute>"
        "</mxsl:if>"
        "<mxsl:for-each field='values' as='x'>"
            "<test:value>&x;</test:value>"
        "</mxsl:for-each>"
    "</test:item>"}).
-xml_record({gen_nstest, nstest,
    "<nstest xmlns='urn:root:' name='&name;'>&items;</nstest>"}).

-record(intl_str, {
    tag :: xmlrat:tag(),
    lang :: binary(),
    text :: binary()
    }).
-xpath_record({match_intl_str, intl_str, #{
    tag => "/*/name()",
    lang => "/*/@xml:lang",
    text => "/*/text()"
    }, #{<<"ns">> => <<"/ns/">>}}).
-xml_record({gen_intl_str, intl_str,
    "<mxsl:tag mxsl:field='tag' xml:lang='&lang;'>&text;</mxsl:tag>",
    #{<<"ns">> => <<"/ns/">>}}).

-record(extensible, {
    name :: binary(),
    extension :: undefined | xmlrat:document()
    }).
-xpath_record({match_extensible, extensible, #{
    name => "/Extensible/@Name",
    extension => "/Extensible/Extension/*"
    }}).
-xml_record({gen_extensible, extensible,
    "<Extensible Name='&name;'>"
        "<mxsl:if defined='extension'>"
            "<Extension>&extension;</Extension>"
        "</mxsl:if>"
    "</Extensible>"}).

-record(intl_thing, {
    name :: [xmlrat:tagged_record(#intl_str{}, {ns, name})],
    descr = [] :: [xmlrat:tagged_record(#intl_str{}, description)]
    }).
-xpath_record({match_intl_thing, intl_thing, #{
    name => "/thing/ns:name",
    descr => "/thing/description"
    }, #{<<"ns">> => <<"/ns/">>}}).
-xml_record({gen_intl_thing, intl_thing,
    "<thing>"
        "&name;"
        "&descr;"
    "</thing>", #{<<"ns">> => <<"/ns/">>}}).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

basic_test() ->
    {ok, Doc} = xmlrat_parse:string("<foo><bar id='1'/></foo>"),
    ?assertMatch([#xml_attribute{value = <<"1">>}], match_test(Doc)).

record_test() ->
    {ok, Doc} = xmlrat_parse:string("<foobar c='bar'>"
        "<attr name='a' value='3'/>"
        "<attr name='b'>something</attr>"
        "</foobar>"),
    Rec = match_foobar(Doc),
    ?assertMatch(#foobar{a = 3, b = <<"something">>, c = bar}, Rec).

record_missing_ok_test() ->
    {ok, Doc} = xmlrat_parse:string("<foobar c='bar'>"
        "<attr name='a' value='3'/>"
        "<attr name='x'>something</attr>"
        "</foobar>"),
    Rec = match_foobar(Doc),
    ?assertMatch(#foobar{a = 3, b = undefined, c = bar}, Rec).

record_missing_default_test() ->
    {ok, Doc} = xmlrat_parse:string("<foobar>"
        "<attr name='a' value='3'/>"
        "<attr name='x'>something</attr>"
        "</foobar>"),
    Rec = match_foobar(Doc),
    ?assertMatch(#foobar{a = 3, b = undefined, c = foo}, Rec).

record_missing_error_test() ->
    {ok, Doc} = xmlrat_parse:string("<foobar>"
        "<attr name='y' value='3'/>"
        "<attr name='x'>something</attr>"
        "</foobar>"),
    ?assertError({required_field, a}, match_foobar(Doc)).

record_ns_test() ->
    {ok, Doc} = xmlrat_parse:string("<nstest name='foo' xmlns='urn:root:' xmlns:foo='urn:test:'>"
        "<foo:item id='500' testing='false'>"
        "<foo:value>abcd</foo:value>"
        "<foo:value>hijk</foo:value>"
        "</foo:item>"
        "<foo:item id='501' testing='true'>"
        "<foo:value>aaaa</foo:value>"
        "</foo:item>"
        "<foo:item id='502'><foo:value></foo:value></foo:item>"
        "</nstest>"),
    Rec = match_nstest(Doc),
    ?assertMatch(#nstest{name = <<"foo">>, items = _}, Rec),
    ?assertMatch([#nstestitem{id = 500, testing = false, values = [<<"abcd">>, <<"hijk">>]},
                  #nstestitem{id = 501, testing = true, values = [<<"aaaa">>]},
                  #nstestitem{id = 502, testing = false, values = [<<>>]}],
                  Rec#nstest.items).

record_enum_test() ->
    {ok, Doc} = xmlrat_parse:string("<foobar c='xyz'>"
        "<attr name='a' value='3'/>"
        "<attr name='b'>something</attr>"
        "</foobar>"),
    ?assertError({invalid_enum_value, [#xml_attribute{value = <<"xyz">>}]},
        match_foobar(Doc)).

gen_item_test() ->
    Doc = gen_nstest_item(
        #nstestitem{id = 501, values = [<<"foo">>, <<"bar">>]}),
    Rec = match_nstest_item(Doc),
    ?assertMatch(#nstestitem{id = 501, values = [<<"foo">>, <<"bar">>]}, Rec).

gen_test() ->
    Item1 = #nstestitem{id = 501, values = [<<"foo">>, <<"bar">>]},
    Item2 = #nstestitem{id = 510, testing = true, values = [<<"baz">>]},
    Doc = gen_nstest(#nstest{name = <<"what">>, items = [Item1, Item2]}),
    io:format("~s\n", [xmlrat_generate:string(Doc, #{indent => true})]),
    Rec = match_nstest(Doc),
    ?assertMatch(#nstest{name = <<"what">>, items = [Item1, Item2]}, Rec).

intl_str_test() ->
    {ok, Doc} = xmlrat_parse:string("<something xml:lang='en'>hello</something>"),
    Rec = match_intl_str(Doc),
    ?assertMatch(#intl_str{tag = <<"something">>, lang = <<"en">>,
        text = <<"hello">>}, Rec),
    Doc2 = gen_intl_str(Rec),
    Rec2 = match_intl_str(Doc2),
    ?assertMatch(Rec, Rec2),
    {ok, Doc3} = xmlrat_parse:string("<foo:bar xmlns:foo='urn:foo:' xml:lang='jp'>what</foo:bar>"),
    Rec3 = match_intl_str(Doc3),
    ?assertMatch(#intl_str{tag = {<<"foo">>, <<"bar">>, _}, lang = <<"jp">>,
        text = <<"what">>}, Rec3),
    Doc4 = gen_intl_str(Rec3),
    CDoc3 = xmlrat_c14n:string(Doc3),
    ?assertMatch(CDoc3, xmlrat_c14n:string(Doc4)).

intl_thing_test() ->
    {ok, Doc} = xmlrat_parse:string("<thing xmlns:ns='/ns/'><ns:name xml:lang='en'>hello</ns:name><ns:name xml:lang='de'>hallo</ns:name></thing>"),
    Rec = match_intl_thing(Doc),
    ?assertMatch(#intl_thing{name = [#intl_str{lang = <<"en">>, text = <<"hello">>},
                                     #intl_str{lang = <<"de">>, text = <<"hallo">>}]}, Rec),
    Rec2 = #intl_thing{name = [#intl_str{lang = <<"en">>, text = <<"hello">>}],
                       descr = [#intl_str{text = <<"what is this">>}]},
    Doc2 = gen_intl_thing(Rec2),
    {ok, Doc3} = xmlrat_parse:string("<thing xmlns:ns='/ns/'><ns:name xml:lang='en'>hello</ns:name><description>what is this</description></thing>"),
    CDoc3 = xmlrat_c14n:string(Doc3),
    ?assertMatch(CDoc3, xmlrat_c14n:string(Doc2)).

ext_test() ->
    {ok, Doc} = xmlrat_parse:string("<Extensible Name='testing'>"
        "<Extension><Foobar>123</Foobar></Extension>"
        "</Extensible>"),
    Rec = match_extensible(Doc),
    ?assertMatch(#extensible{name = <<"testing">>}, Rec),
    #extensible{extension = ExtDoc} = Rec,
    ?assertMatch([#xml_element{tag = <<"Foobar">>}], ExtDoc),
    Rec2 = #extensible{name = <<"foo">>},
    Doc2 = gen_extensible(Rec2),
    {ok, Doc2M} = xmlrat_parse:string("<Extensible Name='foo' />"),
    Doc2MC = xmlrat_c14n:string(Doc2M),
    ?assertMatch(Doc2MC, xmlrat_c14n:string(Doc2)),
    Rec3 = #extensible{name = <<"foo">>, extension = [
        #xml_element{tag = <<"Elem0">>},
        #xml_element{tag = <<"Elem1">>, attributes = [
            #xml_attribute{name = <<"Attr">>, value = <<"val">>}]}]},
    Doc3 = gen_extensible(Rec3),
    {ok, Doc3M} = xmlrat_parse:string(
        "<Extensible Name='foo'>"
            "<Extension>"
                "<Elem0 />"
                "<Elem1 Attr='val' />"
            "</Extension>"
        "</Extensible>"),
    Doc3MC = xmlrat_c14n:string(Doc3M),
    ?assertMatch(Doc3MC, xmlrat_c14n:string(Doc3)).

-endif.
