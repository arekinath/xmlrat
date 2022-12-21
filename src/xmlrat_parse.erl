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

%% @doc Parse XML documents.
%%
%% This module contains functions for parsing XML documents. By default, the
%% xmlrat XML parser attempts to parse and expand namespaces, and expands
%% parameters and entities as long as they are small (&lt;4kbytes).
%%
%% The parser's implementation of XML entities and parameters is a subset of
%% the XML 1.0 specification: parameters may not expand to any part of the
%% definition of another entity or parameter, and parameters and entities must
%% be defined after any other parameter or entity they refer to.
%%
%% No support for DTDs beyond basic parsing is included, including no support
%% for DTD validation (this has been a source of many vulnerabilities in XML
%% parsers).
%%
%% No support for following external references of any kind is included,
%% whether via DTDs, parameters or entities.
%%
%% The parser also refuses to parse large binaries by default (&gt;256kbytes)
%% but both this limit and the entity size limit can be configured in the
%% options given to {@link file/2} or {@link string/2}.
%%
%% Both the {@link file/1} and {@link string/1} functions will attempt basic
%% character encoding sniffing on the input. This is limited to UTF family
%% encodings, ASCII and ISO-8859-1 (Latin-1). The parser always normalises
%% input data to UTF-8 (so binaries within the returned document are UTF-8
%% encoded).
-module(xmlrat_parse).

-include_lib("xmlrat/include/records.hrl").

-export([
    string/1, string/2, file/1, file/2,
    postprocess/2,
    clean_whitespace/1
    ]).

-define(default_entities, #{
    <<"lt">> => <<$<>>,
    <<"gt">> => <<$>>>,
    <<"amp">> => <<$&>>,
    <<"apos">> => <<$'>>,
    <<"quot">> => <<$">>
    }).

-define(default_namespaces, #{
    <<"xml">> => <<"http://www.w3.org/XML/1998/namespace">>,
    <<"xmlns">> => <<"http://www.w3.org/2000/xmlns/">>
    }).

-type filename() :: string() | binary().
-type bytes() :: integer().

-type options() :: #{
    entities => #{binary() => term()},
    allow_unknown_entities => boolean(),
    namespaces => #{xmlrat:nsname() => xmlrat:uri()},
    expand_namespaces => boolean(),
    elide_empty_attributes => boolean(),
    entity_size_limit => bytes(),
    size_limit => bytes() }.
%% Options which can be given as the final argument to {@link file/2} or
%% {@link string/2}.
%%
%% <ul>
%%  <li><code>entities</code> provides an initial set of pre-defined entities
%%      to expand in the document. The basic set of XML 1.0 entities (
%%      <code>lt</code>, <code>gt</code>, <code>amp</code> etc) can be
%%      overridden by this map, as well.</li>
%%  <li><code>allow_unknown_entities</code> instructs the parser to leave
%%      unresolved <code>{entity, xmlname()}</code> tuples in attribute values
%%      or element content as they are if the entity definition cannot be
%%      found.</li>
%%  <li><code>namespaces</code> provides an initial set of pre-defined
%%      namespaces to expand in the document.</li>
%%  <li><code>expand_namespaces</code> allows disabling namespace parsing and
%%      expansion. If set to <code>false</code>, the returned document will
%%      have names and tags always in the single-binary or xmlnsname form (see
%%      {@link xmlrat:xmlname()}).</li>
%%  <li><code>elide_empty_attributes</code> instructs the parser to elide
%%      (remove) any attributes whose value is empty</li>
%%  <li><code>entity_size_limit</code> sets the maximum size of entities which
%%      will be expanded. If an entity in the document exceeds this size,
%%      parsing will be aborted and an error will be returned.</li>
%%  <li><code>size_limit</code> sets the maximum size of XML document which
%%      {@link file/2} or {@link string/2} will parse. Any input binary larger
%%      than this will return an error and not be parsed.</li>
%% </ul>

%% @doc Parses a file as an XML document.
-spec file(filename()) -> {ok, xmlrat:document()} | {error, term()}.
file(Filename) -> file(Filename, #{}).

%% @doc Parses a file as an XML document, with configurable options.
-spec file(filename(), options()) -> {ok, xmlrat:document()} | {error, term()}.
file(Filename, Opts) ->
    case file:read_file(Filename) of
        {ok, Data} ->
            string(Data, Opts);
        Err = {error, _} ->
            Err
    end.

%% @doc Parses a string as an XML document.
-spec string(string() | binary()) -> {ok, xmlrat:document()} | {error, term()}.
string(StringOrBinary) -> string(StringOrBinary, #{}).

%% @doc Parses a string as an XML document, with configurable options.
-spec string(string() | binary(), options()) ->
    {ok, xmlrat:document()} | {error, term()}.
string(String, Opts) when is_list(String) ->
    string(unicode:characters_to_binary(String, utf8), Opts);

string(Binary, Opts) when is_binary(Binary) ->
    Lim = maps:get(size_limit, Opts, 256*1024),
    if
        (byte_size(Binary) >= Lim) ->
            {error, document_size_limit};
        true ->
            case convert_to_utf8(Binary) of
                E = {error, _} ->
                    E;
                {ok, BinaryUtf8} ->
                    case (catch xmlrat_generic_parse:parse(BinaryUtf8)) of
                        {'EXIT', Why} ->
                            {error, Why};
                        {fail, Why} ->
                            {error, Why};
                        D0 when is_list(D0) ->
                            case (catch postprocess(D0, Opts)) of
                                {'EXIT', Why} ->
                                    {error, Why};
                                {ok, D1} ->
                                    {ok, D1}
                            end
                    end
            end
    end.

convert_to_utf8(Binary) ->
    Encoding = case (catch xmlrat_xmldecl_parse:parse(Binary)) of
        {'EXIT', _Why} -> utf8;
        {fail, _Why} -> utf8;
        #xml{version = <<"1.0">>, encoding = undefined} ->
            utf8;
        #xml{version = <<"1.0">>, encoding = Enc} ->
            case string:lowercase(Enc) of
                <<"utf-8">> -> utf8;
                <<"iso-8859-1">> -> latin1;
                <<"us-ascii">> -> latin1;
                <<"utf-16">> -> utf16;
                <<"utf-32">> -> utf32
            end
    end,
    HighChars = [ C || <<C>> <= Binary, C > 16#80 ],
    case HighChars of
        [] when (Encoding =:= utf8) or (Encoding =:= latin1) ->
            {ok, Binary};
        _ ->
            case unicode:characters_to_list(Binary, Encoding) of
                E = {error, _, _} -> {error, {unicode, E}};
                E = {incomplete, _, _} -> {error, {unicode, E}};
                Chars ->
                    EscapedChars = iolist_to_binary(lists:map(fun
                        (Char) when (Char < 16#80) -> Char;
                        (Char) -> [$&, $#, $x] ++
                            integer_to_list(Char, 16) ++ [$;]
                    end, Chars)),
                    {ok, EscapedChars}
            end
    end.

%% @private
postprocess(D0, Opts) ->
    EntSizeLimit = maps:get(entity_size_limit, Opts, 4096),
    Params = gather_params(#{}, D0, EntSizeLimit),
    Entities0 = maps:merge(?default_entities, maps:get(entities, Opts, #{})),
    Entities1 = gather_entities(Params, Entities0, D0, EntSizeLimit),
    D1 = expand_entities(Entities1, Params, D0, Opts),
    D2 = case Opts of
        #{expand_namespaces := false} ->
            D1;
        _ ->
            NS0 = maps:merge(maps:get(namespaces, Opts, #{}),
                ?default_namespaces),
            expand_namespaces(NS0, D1)
    end,
    {ok, D2}.

gather_entities(_P, E0, [], _SizeLim) -> E0;
gather_entities(P, E0, [Next | Rest], SizeLim) ->
    E1 = case Next of
        {xml_doctype, _Name, #{subset := DTD}} ->
            gather_entities(P, E0, DTD, SizeLim);
        {xmld_entity, Name, L0} when is_list(L0) ->
            L1 = expand_entities(E0, P, L0, #{}),
            case iolist_to_binary(L1) of
                B when byte_size(B) >= SizeLim ->
                    error({entity_size_limit, Name});
                B ->
                    E0#{Name => iolist_to_binary(B)}
            end;
        _ ->
            E0
    end,
    gather_entities(P, E1, Rest, SizeLim).

gather_params(E0, [], _SizeLim) -> E0;
gather_params(E0, [Next | Rest], SizeLim) ->
    E1 = case Next of
        {xml_doctype, _Name, #{subset := DTD}} ->
            gather_params(E0, DTD, SizeLim);
        {xmld_parameter, Name, L0} when is_list(L0) ->
            L1 = expand_entities(?default_entities, E0, L0, #{}),
            case iolist_to_binary(L1) of
                B when byte_size(B) >= SizeLim ->
                    error({param_size_limit, Name});
                B ->
                    E0#{Name => B}
            end;
        _ ->
            E0
    end,
    gather_params(E1, Rest, SizeLim).

expand_entities(_Ents, _Params, [], _Opts) -> [];
expand_entities(Ents, Params, [Next0 | Rest], Opts) ->
    AllowUnknown = maps:get(allow_unknown_entities, Opts, false),
    Next1 = case Next0 of
        {entity, <<"#x", Hex/binary>>} ->
            N = binary_to_integer(Hex, 16),
            unicode:characters_to_binary([N], utf8);
        {entity, <<"#", Dec/binary>>} ->
            N = binary_to_integer(Dec, 10),
            unicode:characters_to_binary([N], utf8);
        {entity, N} ->
            case Ents of
                #{N := Exp} -> lists:flatten([Exp]);
                _ when AllowUnknown -> [Next0];
                _ -> error({unknown_entity, N})
            end;
        {parameter, N} ->
            case Params of
                #{N := Exp} -> [Exp];
                _ -> error({unknown_param, N})
            end;
        #xml_attribute{value = Value0} when is_list(Value0) ->
            Collapse = maps:get(elide_empty_attributes, Opts, false),
            Value1 = reduce_binary(
                expand_entities(Ents, Params, Value0, Opts)),
            case {Collapse, Value0, Value1} of
                {true, [{entity, _}], <<>>} ->
                    [];
                _ ->
                    [Next0#xml_attribute{value = Value1}]
            end;
        #xml_namespace{uri = Value0} when is_list(Value0) ->
            Value1 = expand_entities(Ents, Params, Value0, Opts),
            [Next0#xml_namespace{uri = iolist_to_binary(Value1)}];
        #xml_pi{options = Attrs0} when is_list(Attrs0) ->
            Attrs1 = expand_entities(Ents, Params, Attrs0, Opts),
            [Next0#xml_pi{options = Attrs1}];
        #xml_element{attributes = Attrs0,
                     content = Content0} when is_list(Attrs0) ->
            Attrs1 = expand_entities(Ents, Params, Attrs0, Opts),
            Content1 = expand_entities(Ents, Params, Content0, Opts),
            [Next0#xml_element{attributes = Attrs1,
                              content = reduce_binaries(Content1)}];
        Other -> [Other]
    end,
    Next1 ++ expand_entities(Ents, Params, Rest, Opts).

reduce_binary(List0) ->
    case reduce_binaries(List0) of
        [] -> <<>>;
        [B] when is_binary(B) -> B;
        List1 -> List1
    end.

reduce_binaries([]) -> [];
reduce_binaries([Bin0, Bin1 | Rest]) when is_binary(Bin0) and is_binary(Bin1) ->
    reduce_binaries([<<Bin0/binary, Bin1/binary>> | Rest]);
reduce_binaries([<<>> | Rest]) ->
    reduce_binaries(Rest);
reduce_binaries([Other | Rest]) ->
    [Other | reduce_binaries(Rest)].

%% @doc Removes whitespace from a document, simplifying it for output.
%%
%% Removes whitespace:
%% <ul>
%%   <li>immediately before newlines</li>
%%   <li>at the start and end of tag bodies (other than newlines and leading
%%       whitespace on each line)</li>
%%   <li>before and after sets of attributes</li>
%%   <li>between attributes</li>
%% </ul>
-spec clean_whitespace(xmlrat:document()) -> xmlrat:document().
clean_whitespace([]) -> [];
clean_whitespace([Bin | Rest]) when is_binary(Bin) ->
    case clean_whitespace_bin(Bin) of
        <<>> -> clean_whitespace(Rest);
        NewBin -> [NewBin | clean_whitespace(Rest)]
    end;
clean_whitespace([E0 = #xml_element{} | Rest]) ->
    #xml_element{attributes = Attrs0, content = Content0} = E0,
    Attrs1 = clean_attr_whitespace(Attrs0),
    Content1 = clean_whitespace(Content0),
    E1 = E0#xml_element{attributes = Attrs1, content = Content1},
    [E1 | clean_whitespace(Rest)];
clean_whitespace([E0 = #xml_comment{} | Rest]) ->
    #xml_comment{text = Text0} = E0,
    Text1 = clean_whitespace_bin(Text0),
    E1 = E0#xml_comment{text = Text1},
    [E1 | clean_whitespace(Rest)];
clean_whitespace([E0 = #xml_pi{} | Rest]) ->
    E1 = case E0 of
        #xml_pi{options = Opts0} when is_binary(Opts0) ->
            Opts1 = clean_whitespace_bin(Opts0),
            E0#xml_pi{options = Opts1};
        #xml_pi{options = OptAttrs0} when is_list(OptAttrs0) ->
            OptAttrs1 = clean_attr_whitespace(OptAttrs0),
            E0#xml_pi{options = OptAttrs1}
    end,
    [E1 | clean_whitespace(Rest)];
clean_whitespace([Other | Rest]) ->
    [Other | clean_whitespace(Rest)].

clean_whitespace_bin(Bin) when is_binary(Bin) ->
    Lines0 = binary:split(Bin, [<<"\n">>], [global]),
    Last = lists:last(Lines0),
    Lines1 = lists:droplast(Lines0),
    Lines2 = lists:map(fun (L) ->
        string:trim(L, trailing)
    end, Lines1),
    Lines3 = Lines2 ++ [Last],
    iolist_to_binary(lists:join(<<"\n">>, Lines3)).

clean_attr_whitespace([]) -> [];
clean_attr_whitespace(List0) ->
    List1 = reduce_binaries(List0),
    List2 = case lists:last(List1) of
        B when is_binary(B) ->
            lists:droplast(List1);
        _ ->
            List1
    end,
    lists:map(fun
        (B) when is_binary(B) ->
            clean_attr_whitespace_bin(B);
        (Other) ->
            Other
    end, List2).

clean_attr_whitespace_bin(Bin) when is_binary(Bin) ->
    Lines0 = binary:split(Bin, [<<"\n">>], [global]),
    case Lines0 of
        [_] ->
            % No newline: condense this to a single space
            <<" ">>;
        _ ->
            % Remove any whitespace on all lines except the last line
            % Leave the last line unmodified (consider it indentation)
            WithoutLast = lists:droplast(Lines0),
            Lines1 = [<<>> || _X <- WithoutLast] ++ [lists:last(Lines0)],
            iolist_to_binary(lists:join(<<"\n">>, Lines1))
    end.

expand_namespace_name(_NS0, N = {_, _, _}) -> N;
expand_namespace_name(NS0, Name) when is_binary(Name) ->
    case NS0 of
        #{default := BaseURI} ->
            URI = iolist_to_binary([BaseURI, Name]),
            {default, Name, URI};
        _ ->
            Name
    end;
expand_namespace_name(NS0, {NS, Name}) ->
    case NS0 of
        #{NS := BaseURI} ->
            URI = iolist_to_binary([BaseURI, Name]),
            {NS, Name, URI};
        _ ->
            error({undefined_namespace, NS})
    end.

expand_namespaces(_NS0, []) -> [];
expand_namespaces(NS0, [Next0 | Rest]) ->
    Next1 = case Next0 of
        {xml_attribute, Name0, Value} ->
            Name1 = expand_namespace_name(NS0, Name0),
            {xml_attribute, Name1, Value};
        {xml_element, Name0, Attrs0, Content0} ->
            NS1 = gather_namespaces(NS0, Attrs0),
            Name1 = expand_namespace_name(NS1, Name0),
            Attrs1 = expand_namespaces(NS1, Attrs0),
            Content1 = expand_namespaces(NS1, Content0),
            {xml_element, Name1, Attrs1, Content1};
        _ ->
            Next0
    end,
    [Next1 | expand_namespaces(NS0, Rest)].

gather_namespaces(NS0, []) -> NS0;
gather_namespaces(NS0, [Next | Rest]) ->
    case Next of
        {xml_namespace, NS, <<>>} ->
            gather_namespaces(maps:remove(NS, NS0), Rest);
        {xml_namespace, NS, URI} ->
            gather_namespaces(NS0#{NS => URI}, Rest);
        _ ->
            gather_namespaces(NS0, Rest)
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-endif.
