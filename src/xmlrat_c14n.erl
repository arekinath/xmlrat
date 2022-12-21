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

%% @doc Implementation of XML Exclusive Canonicalization (C14N).
%%
%% See <a href='https://www.w3.org/TR/xml-exc-c14n/'>W3C Recommendation:
%% Exclusive XML Canonicalization Version 1.0</a>.
%%
%% This serialises an XML document into a canonical form suitable for signing
%% or other forms of verification/validation that require byte-identical
%% representations at both ends of a process.
-module(xmlrat_c14n).

-compile({parse_transform, xmlrat_parse_transform}).

-include_lib("xmlrat/include/records.hrl").

-export([string/1, string/2]).

-export([normalise_namespaces/2]).

-type options() :: #{
    force_namespaces => #{xmlrat:nsname() => boolean()},
    comments => boolean() }.
%% Options, as given to {@link string/2}.

%% @doc Serialises an XML document in canonical form (without comments).
-spec string(xmlrat:document()) -> binary().
string(D0) ->
    string(D0, #{}).

-define(default_namespaces, #{
    <<"xml">> => <<"http://www.w3.org/XML/1998/namespace">>,
    <<"xmlns">> => <<"http://www.w3.org/2000/xmlns/">>
    }).

%% @doc Serialises an XML document in canonical form, with configurable
%%      options.
-spec string(xmlrat:document(), options()) -> binary().
string(D0, Opts) ->
    ForceNS = maps:get(force_namespaces, Opts, #{}),
    D1 = normalise_namespaces(ForceNS, ?default_namespaces,
                              #{default => true}, D0),
    D2 = normalise_attrs(D1),
    D3 = remove_xml_decl(D2),
    D4 = strip_toplevel_comments(D3, Opts),
    D5 = remove_leading_whitespace(D4),
    D6 = normalise_toplevel_whitespace(D5),
    D7 = xmlrat_generate:string(D6, #{
        single_quotes => false,
        comments => maps:get(comments, Opts, false),
        doctypes => false,
        self_closing_tags => false
        }),
    normalise_newlines(D7).

-spec normalise_newlines(binary()) -> binary().
normalise_newlines(Bin0) ->
    binary:replace(Bin0, <<"\r">>, <<"&#xD;">>, [global]).

-spec strip_toplevel_comments(xmlrat:document(), options()) -> xmlrat:document().
strip_toplevel_comments(List, Opts) ->
    case maps:get(comments, Opts, false) of
        false ->
            [X || X <- List, (not is_tuple(X)) orelse
                (element(1, X) =/= xml_comment)];
        true ->
            List
    end.

-spec normalise_toplevel_whitespace(xmlrat:document()) -> xmlrat:document().
normalise_toplevel_whitespace(List) ->
    NoBins = [X || X <- List, not is_binary(X)],
    lists:join(<<"\n">>, NoBins).

-spec remove_leading_whitespace(xmlrat:component() | [xmlrat:component()] | [xmlrat:content()]) -> xmlrat:component() | [xmlrat:component()] | [xmlrat:content()].
remove_leading_whitespace(E0 = #xml_element{attributes = A0, content = C0}) ->
    A1 = remove_trailing_whitespace_list(remove_leading_whitespace_list(A0)),
    C1 = lists:map(fun
        (V) when is_binary(V) -> V;
        (V) -> remove_leading_whitespace(V)
    end, C0),
    E0#xml_element{attributes = A1, content = C1};
remove_leading_whitespace(E0 = #xml_pi{options = O0}) when is_list(O0) ->
    O1 = remove_leading_whitespace_list(O0),
    E0#xml_pi{options = O1};
remove_leading_whitespace(L0) when is_list(L0) ->
    L1 = remove_leading_whitespace_list(L0),
    lists:map(fun
        (V) when is_binary(V) -> V;
        (V) -> remove_leading_whitespace(V)
    end, L1);
remove_leading_whitespace(Other) -> Other.

remove_leading_whitespace_list([Bin0 | Rest]) when is_binary(Bin0) ->
    case string:trim(Bin0, leading) of
        <<>> -> remove_leading_whitespace(Rest);
        Bin1 -> [Bin1 | Rest]
    end;
remove_leading_whitespace_list(Rest) -> Rest.

remove_trailing_whitespace_list([]) -> [];
remove_trailing_whitespace_list([X]) -> [X];
remove_trailing_whitespace_list(List) ->
    case lists:last(List) of
        B0 when is_binary(B0) ->
            lists:reverse(
                remove_leading_whitespace_list(lists:reverse(List)));
        _ -> List
    end.

-spec remove_xml_decl(xmlrat:document()) -> xmlrat:document().
remove_xml_decl([]) -> [];
remove_xml_decl([#xml{} | Rest]) ->
    remove_xml_decl(Rest);
remove_xml_decl([#xml_doctype{} | Rest]) ->
    remove_xml_decl(Rest);
remove_xml_decl([Next | Rest]) ->
    [Next | remove_xml_decl(Rest)].

-spec normalise_attrs(xmlrat:document()) -> xmlrat:document().
normalise_attrs([]) -> [];
normalise_attrs([Next0 | Rest]) ->
    Next1 = normalise_attrs_one(Next0),
    [Next1 | normalise_attrs(Rest)].

normalise_attrs_one(E0 = #xml_element{attributes = Attrs0, content = C0}) ->
    NS0 = [N || N = #xml_namespace{} <- Attrs0],
    NS1 = lists:sort(fun (A, B) ->
        #xml_namespace{name = AN} = A,
        #xml_namespace{name = BN} = B,
        if
            (AN =:= default) and not (BN =:= default) -> true;
            (BN =:= default) and not (AN =:= default) -> false;
            AN < BN -> true;
            BN < AN -> false;
            true -> true
        end
    end, NS0),
    Attrs1 = [A || A = #xml_attribute{} <- Attrs0],
    Attrs2 = lists:sort(fun (A, B) ->
        #xml_attribute{name = AN} = A,
        #xml_attribute{name = BN} = B,
        case {AN, BN} of
            {{_, _, URIA}, {_, _, URIB}} ->
                (URIA =< URIB);
            {AN, {_, _, _URI}} when is_binary(AN) ->
                true;
            {{_, _, _URIA}, BN} when is_binary(BN) ->
                false;
            {AN, BN} when is_binary(AN) and is_binary(BN) ->
                (AN =< BN)
        end
    end, Attrs1),
    C1 = normalise_attrs(C0),
    E0#xml_element{attributes = NS1 ++ Attrs2, content = C1};
normalise_attrs_one(Other) -> Other.

-type usedmap() :: #{nsname() => true}.
-spec used_namespaces(usedmap(), xmlrat:component()) -> usedmap().
used_namespaces(Used0, #xml_attribute{name = {NS, _, _}}) ->
    Used0#{NS => true};
used_namespaces(Used0, #xml_attribute{name = {NS, _}}) ->
    Used0#{NS => true};
used_namespaces(Used0, #xml_attribute{name = N}) when is_binary(N) ->
    Used0#{default => true};
used_namespaces(Used0, #xml_element{tag = {NS, _, _}, attributes = Attrs}) ->
    Used1 = Used0#{NS => true},
    lists:foldl(fun (Attr, Acc) ->
        used_namespaces(Acc, Attr)
    end, Used1, Attrs);
used_namespaces(Used0, #xml_element{tag = {NS, _}, attributes = Attrs}) ->
    Used1 = Used0#{NS => true},
    lists:foldl(fun (Attr, Acc) ->
        used_namespaces(Acc, Attr)
    end, Used1, Attrs);
used_namespaces(Used0, #xml_element{tag = N, attributes = Attrs}) when is_binary(N)->
    Used1 = Used0#{default => true},
    lists:foldl(fun (Attr, Acc) ->
        used_namespaces(Acc, Attr)
    end, Used1, Attrs);
used_namespaces(Used0, _Other) -> Used0.

-spec used_namespaces(xmlrat:component()) -> usedmap().
used_namespaces(Obj) -> used_namespaces(#{}, Obj).

-type nsname() :: default | xmlrat:nsname().

-type force_ns() :: #{nsname() => boolean()}.
-type ns_active() :: #{nsname() => boolean()}.
-type ns_state() :: #{nsname() => xmlrat:uri()}.

-type norm_opts() :: #{force_namespaces => #{nsname() => boolean()},
                       namespaces => #{nsname() => xmlrat:uri()}}.

%% @private
-spec normalise_namespaces(xmlrat:document(), norm_opts()) -> xmlrat:document().
normalise_namespaces(Doc, Opts) ->
    F = maps:get(force_namespaces, Opts, #{}),
    AddNS = maps:get(namespaces, Opts, #{}),
    NS0 = maps:merge(?default_namespaces, AddNS),
    NSA0 = #{default => true},
    normalise_namespaces(F, NS0, NSA0, Doc).

-spec normalise_namespaces(force_ns(), ns_state(), ns_active(), xmlrat:document()) -> xmlrat:document().
normalise_namespaces(_F, _NS0, _NSA0, []) -> [];
normalise_namespaces(F, NS0, NSA0, [Next0 | Rest]) ->
    Next1 = case Next0 of
        #xml_element{attributes = Attrs0, content = Content0} ->
            NS1 = gather_namespaces(NS0, [Next0 | Attrs0]),
            NSALocal = used_namespaces(Next0),
            NSAGen = maps:merge(F, NSALocal),
            Attrs1 = lists:filter(fun
                (#xml_namespace{}) -> false;
                (_Other) -> true
            end, Attrs0),
            Attrs2 = maps:fold(fun

                % For the default namespace (xmlns=''), generate it only if it's
                % changed URIs from the parent context.
                (default, _, Acc) ->
                    OldDefault = maps:get(default, NS0, <<>>),
                    NewDefault = maps:get(default, NS1, <<>>),
                    if
                        (OldDefault =:= NewDefault) ->
                            Acc;
                        true ->
                            [#xml_namespace{name = default, uri = NewDefault}
                             | Acc]
                    end;

                % Ignore the "xml:" namespaces
                (<<"xml">>, _, Acc) ->
                    Acc;

                % For other types of namespaces, we generate an attribute if
                % the URI has changed, OR if it was inactive in our parent
                % (this pushes namespaces down to the smallest nodeset where
                % they're used)
                (NS, _, Acc) ->
                    OldURI = maps:get(NS, NS0, <<>>),
                    OldActive = maps:get(NS, NSA0, false),
                    #{NS := NewURI} = NS1,
                    if
                        OldActive and (OldURI =:= NewURI) ->
                            Acc;
                        true ->
                            [#xml_namespace{name = NS, uri = NewURI} | Acc]
                    end
            end, Attrs1, NSAGen),
            NSA1 = maps:merge(NSA0, NSAGen),
            Content1 = normalise_namespaces(F, NS1, NSA1, Content0),
            Next0#xml_element{attributes = Attrs2, content = Content1};
        _ ->
            Next0
    end,
    [Next1 | normalise_namespaces(F, NS0, NSA0, Rest)].

-spec gather_namespaces(ns_state(), xmlrat:document()) -> ns_state().
gather_namespaces(NS0, []) -> NS0;
gather_namespaces(NS0, [Next | Rest]) ->
    case Next of
        #xml_element{tag = {NS, Name, URI}} ->
            NSURI = binary:part(URI, 0, byte_size(URI) - byte_size(Name)),
            gather_namespaces(NS0#{NS => NSURI}, Rest);
        #xml_attribute{name = {NS, Name, URI}} ->
            NSURI = binary:part(URI, 0, byte_size(URI) - byte_size(Name)),
            gather_namespaces(NS0#{NS => NSURI}, Rest);
        #xml_namespace{name = NS, uri = <<>>} ->
            gather_namespaces(maps:remove(NS, NS0), Rest);
        #xml_namespace{name = NS, uri = URI} ->
            gather_namespaces(NS0#{NS => URI}, Rest);
        _ ->
            gather_namespaces(NS0, Rest)
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

c14n_3_1_test() ->
    {ok, Doc} = xmlrat_parse:string(<<"<?xml version=\"1.0\"?>\n\n"
        "<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n"
        "<doc>Hello, world!<!-- Comment 1 --></doc>\n\n"
        "<?pi-without-data     ?>\n\n"
        "<!-- Comment 2 -->\n\n"
        "<!-- Comment 3 -->">>),
    io:format("~p\n", [Doc]),
    ?assertMatch(<<
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n"
        "<doc>Hello, world!</doc>\n"
        "<?pi-without-data?>">>,
        string(Doc, #{comments => false})),

    ?assertMatch(<<
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n"
        "<doc>Hello, world!<!-- Comment 1 --></doc>\n"
        "<?pi-without-data?>\n"
        "<!-- Comment 2 -->\n"
        "<!-- Comment 3 -->">>,
        string(Doc, #{comments => true})).

c14n_3_2_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<doc>\n"
        "   <clean>   </clean>\n"
        "   <dirty>   A   B   </dirty>\n"
        "   <mixed>\n"
        "      A\n"
        "      <clean>   </clean>\n"
        "      B\n"
        "      <dirty>   A   B   </dirty>\n"
        "      C\n"
        "   </mixed>\n"
        "</doc>">>),

    ?assertMatch(<<
        "<doc>\n"
        "   <clean>   </clean>\n"
        "   <dirty>   A   B   </dirty>\n"
        "   <mixed>\n"
        "      A\n"
        "      <clean>   </clean>\n"
        "      B\n"
        "      <dirty>   A   B   </dirty>\n"
        "      C\n"
        "   </mixed>\n"
        "</doc>">>,
        string(Doc, #{comments => true})).

c14n_3_3_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<!DOCTYPE doc [<!ATTLIST e9 attr CDATA \"default\">]>\n"
        "<doc>\n"
        "   <e1   />\n"
        "   <e2   ></e2>\n"
        "   <e3   name = \"elem3\"   id=\"elem3\"   />\n"
        "   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n"
        "   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n"
        "      xmlns:b=\"http://www.ietf.org\"\n"
        "      xmlns:a=\"http://www.w3.org\"\n"
        "      xmlns=\"http://example.org\"/>\n"
        "   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n"
        "      <e7 xmlns=\"http://www.ietf.org\">\n"
        "         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n"
        "            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n"
        "         </e8>\n"
        "      </e7>\n"
        "   </e6>\n"
        "</doc>">>),

    ?assertMatch(<<
        "<doc>\n"
        "   <e1></e1>\n"
        "   <e2></e2>\n"
        "   <e3 id=\"elem3\" name=\"elem3\"></e3>\n"
        "   <e4 id=\"elem4\" name=\"elem4\"></e4>\n"
        "   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n"
        "   <e6>\n"
        "      <e7 xmlns=\"http://www.ietf.org\">\n"
        "         <e8 xmlns=\"\">\n"
        "            <e9></e9>\n"
        "         </e8>\n"
        "      </e7>\n"
        "   </e6>\n"
        "</doc>">>,
        string(Doc, #{comments => true})).

c14n_3_4_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<!DOCTYPE doc [\n"
        "<!ATTLIST normId id ID #IMPLIED>\n"
        "<!ATTLIST normNames attr NMTOKENS #IMPLIED>\n"
        "]>\n"
        "<doc>\n"
        "   <text>First line&#x0d;&#10;Second line</text>\n"
        "   <value>&#x32;</value>\n"
        "   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n"
        "   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n"
        "   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n"
        "   <normNames attr='   A   &#x20;&#13;&#xa;&#9;   B   '/>\n"
        "   <normId id=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n"
        "</doc>">>),
    io:format("~p\n", [Doc]),
    ?assertMatch(<<
        "<doc>\n"
        "   <text>First line&#xD;\n"
        "Second line</text>\n"
        "   <value>2</value>\n"
        "   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n"
        "   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n"
        % these lines differ from the spec, because we don't process DTDs yet
        %"   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n"
        %"   <normNames attr=\"A &#xD;&#xA;&#x9; B\"></normNames>\n"
        %"   <normId id=\"' &#xD;&#xA;&#x9; '\"></normId>\n"
        "   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n"
        "   <normNames attr=\"   A    &#xD;&#xA;&#x9;   B   \"></normNames>\n"
        "   <normId id=\" '    &#xD;&#xA;&#x9;   ' \"></normId>\n"
        "</doc>">>,
        string(Doc, #{comments => true})).

default_ns_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<foo:a xmlns:foo=\"urn:foo:\">"
        "<b xmlns=\"urn:bar:\">"
        "<c xmlns=\"urn:bar:\" />"
        "</b>"
        "<c xmlns=\"urn:bar:\">"
        "<d />"
        "</c>"
        "<foo:e>"
        "<f xmlns=\"urn:foo:\">"
        "<foo:x>blah</foo:x>"
        "</f></foo:e>"
        "</foo:a>">>),

    ?assertMatch(<<
        "<foo:a xmlns:foo=\"urn:foo:\">"
        "<b xmlns=\"urn:bar:\">"
        "<c></c>"
        "</b>"
        "<c xmlns=\"urn:bar:\">"
        "<d></d>"
        "</c>"
        "<foo:e>"
        "<f xmlns=\"urn:foo:\">"
        "<foo:x>blah</foo:x>"
        "</f>"
        "</foo:e>"
        "</foo:a>">>,
        string(Doc, #{comments => true})),

    {ok, Doc2} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<saml2p:Response "
            "xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
            "ID=\"_83dbf3f1-53c2-4f49-b294-7c19cbf2b77b\" "
            "Version=\"2.0\" "
            "IssueInstant=\"2013-10-30T11:15:47.517Z\" "
            "Destination=\"https://10.10.18.25/saml/consume\">"
        "<Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" "
            "Version=\"2.0\" "
            "ID=\"_debe5f4e-4343-4f95-b997-89db5a483202\" "
            "IssueInstant=\"2013-10-30T11:15:47.517Z\">"
                "<Issuer>foo</Issuer>"
                "<Subject>"
                    "<NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"/>"
                    "<SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                    "<SubjectConfirmationData NotOnOrAfter=\"2013-10-30T12:15:47.517Z\" "
                        "Recipient=\"https://10.10.18.25/saml/consume\"/>"
                    "</SubjectConfirmation>"
                "</Subject>"
        "</Assertion>"
        "</saml2p:Response>">>),

    ?assertMatch(<<
        "<saml2p:Response "
            "xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
            "Destination=\"https://10.10.18.25/saml/consume\" "
            "ID=\"_83dbf3f1-53c2-4f49-b294-7c19cbf2b77b\" "
            "IssueInstant=\"2013-10-30T11:15:47.517Z\" "
            "Version=\"2.0\">"
                "<Assertion "
                    "xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" "
                    "ID=\"_debe5f4e-4343-4f95-b997-89db5a483202\" "
                    "IssueInstant=\"2013-10-30T11:15:47.517Z\" "
                    "Version=\"2.0\">"
                        "<Issuer>foo</Issuer>"
                        "<Subject>"
                            "<NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"></NameID>"
                            "<SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                                "<SubjectConfirmationData "
                                    "NotOnOrAfter=\"2013-10-30T12:15:47.517Z\" "
                                    "Recipient=\"https://10.10.18.25/saml/consume\">"
                                "</SubjectConfirmationData>"
                            "</SubjectConfirmation>"
                        "</Subject>"
                "</Assertion>"
        "</saml2p:Response>">>,
        string(Doc2, #{comments => true})).

c14n_inclns_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<foo:a xmlns:foo=\"urn:foo:\" xmlns:bar=\"urn:bar:\">"
        "<foo:b bar:nothing=\"something\">foo</foo:b>"
        "</foo:a>">>),

    ?assertMatch(<<
        "<foo:a xmlns:foo=\"urn:foo:\">"
        "<foo:b xmlns:bar=\"urn:bar:\" bar:nothing=\"something\">foo</foo:b>"
        "</foo:a>">>,
        string(Doc, #{comments => false})),

    ?assertMatch(<<
        "<foo:a xmlns:bar=\"urn:bar:\" xmlns:foo=\"urn:foo:\">"
        "<foo:b bar:nothing=\"something\">foo</foo:b>"
        "</foo:a>">>,
        string(Doc, #{
            comments => false,
            force_namespaces => #{<<"bar">> => true}
        })).

-xpath({extract_elem2, "//n1:elem2",
    #{<<"n1">> => <<"http://example.net">>}}).

c14n_exc_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<n2:pdu xmlns:n1=\"http://example.com\" "
            "xmlns:n2=\"http://foo.example\" "
            "xml:lang=\"fr\" "
            "xml:space=\"retain\" >"
                "<n1:elem2 xmlns:n1=\"http://example.net\" "
                    "xml:lang=\"en\">"
                        "<n3:stuff xmlns:n3=\"ftp://example.org\"/>"
                "</n1:elem2>"
        "</n2:pdu>">>),
    [Elem2] = extract_elem2(Doc),
    ?assertMatch(<<
        "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">"
        "<n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>"
        "</n1:elem2>">>,
        string([Elem2])).

c14n_exc_2_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<n2:pdu xmlns:n1=\"http://example.com\" "
            "xmlns=\"http://example.net\" "
            "xmlns:n2=\"http://foo.example\" "
            "xml:lang=\"fr\" "
            "xml:space=\"retain\" >"
                "<elem2 xml:lang=\"en\">"
                        "<n3:stuff xmlns:n3=\"ftp://example.org\"/>"
                "</elem2>"
        "</n2:pdu>">>),
    [Elem2] = extract_elem2(Doc),
    ?assertMatch(<<
        "<elem2 xmlns=\"http://example.net\" xml:lang=\"en\">"
        "<n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>"
        "</elem2>">>,
        string([Elem2])).

-xpath({strip_sig_kids, "/*/*[not(self::Signature)]"}).

strip_sig(Doc) ->
    NewRootKids = strip_sig_kids(Doc),
    lists:map(fun
        (Root = #xml_element{content = _}) ->
            Root#xml_element{content = NewRootKids};
        (Other) ->
            Other
    end, Doc).

extra_whitespace_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\" encoding=\"US-ASCII\"?>\n"
        "<!DOCTYPE doc [\n"
        "<!ATTLIST Data Id ID #IMPLIED>\n"
        "<!ATTLIST Info ID ID #IMPLIED>\n"
        "]>\n"
        "<doc>\n"
        "\t<Data>xyz</Data>\n"
        "\t<Data>pqr</Data>\n"
        "\t<Data Id=\"foo\">abc</Data>\n"
        "\t<Data Id=\"baz\">456</Data>\n"
        "\t<Info ID=\"bar\">123</Info>\n"
        "\t<Info ID=\"qux\">789</Info>\n"
        "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"thesig\">\n"
        "</Signature>\n"
        "</doc>\n">>),
    Subset = strip_sig(Doc),
    ?assertMatch(<<
        "<doc>\n"
        "\t<Data>xyz</Data>\n"
        "\t<Data>pqr</Data>\n"
        "\t<Data Id=\"foo\">abc</Data>\n"
        "\t<Data Id=\"baz\">456</Data>\n"
        "\t<Info ID=\"bar\">123</Info>\n"
        "\t<Info ID=\"qux\">789</Info>\n"
        "\n"
        "</doc>">>,
        string(Subset)).

-endif.
