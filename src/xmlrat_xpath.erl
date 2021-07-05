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

%% @doc Compile and execute XPath 1.0 expressions at runtime.
%%
%% This module provides support for compiling a subset of XPath 1.0 to Erlang
%% code. The generated code consists of successive pattern matches and list
%% comprehensions, plus some calls to runtime helpers as needed for predicates
%% with position matches in them.
%%
%% The subset of XPath 1.0 implemented is chosen to be as "safe" as possible --
%% it should avoid any accidental exponential expansion in memory usage or
%% time, and compiles to simple pattern matches as much as possible. Being a
%% fully compliant XPath implementation is a non-goal.
%%
%% It's important to note that every XPath expression this module compiles
%% will result in a new Erlang module being loaded by the code server. These
%% are a finite resource, so you should avoid dynamically compiling an arbitray
%% number of input expressions (e.g. don't accept XPath expressions from user
%% input).
%%
%% Expressions support being parametrised by using variables (see the type
%% {@link varbinds()}).
%%
%% Supported XPath 1.0 syntax features:
%% <ul>
%%   <li><code>/</code> (absolute) step</li>
%%   <li><code>//</code> recursive children step</li>
%%   <li><code>self::</code>, <code>child::</code>, and <code>attribute::</code>
%%       axes (and abbreviations like <code>/elem</code> or <code>@attr</code>)</li>
%%   <li>position predicates (<code>/foo[1]</code>)</li>
%%   <li>boolean expression predicates, including coercion to boolean from
%%       strings, integers, node sets and attribute sets</li>
%%   <li><code>and</code>, <code>or</code> operators</li>
%%   <li>equality operator</li>
%%   <li><code>not()</code> function</li>
%%   <li>other functions:<ul>
%%       <li><code>last()</code></li>
%%       <li><code>position()</code></li>
%%       <li><code>count(nodeset | attrset)</code></li>
%%       <li><code>id(string)</code> (does not use DTD)</li>
%%       </ul></li>
%% </ul>
-module(xmlrat_xpath).

-export([
    compile/1, compile/2,
    run/2, run/3
    ]).

-export_type([xpath_ref/0]).

-record(xpath_ref, {
    mod :: module()
    }).
-opaque xpath_ref() :: #xpath_ref{}.

-type nsmap() :: #{xmlrat:nsname() => xmlrat:uri()}.
%% Map of namespaces used in the XPath expression itself (does not have to match
%% the namespace set used by the document).

-type compile_options() :: #{namespaces => nsmap()}.

-type xpath() :: string() | binary().
%% An XPath 1.0 expression.

parse(XPath) ->
    case (catch xmlrat_xpath_parse:parse(XPath)) of
        {'EXIT', Why} ->
            {error, Why};
        {fail, Why} ->
            {error, Why};
        Expr ->
            {ok, Expr}
    end.

%% @doc Compiles an XPath expression to Erlang code.
%%
%% Returns an <code>xpath_ref()</code> which can be passed to
%% <code>run()</code>.
-spec compile(xpath()) -> {ok, xpath_ref()} | {error, term()}.
compile(XPath) ->
    compile(XPath, #{}).

%% @doc Compiles an XPath expression to Erlang code, with options.
-spec compile(xpath(), compile_options()) -> {ok, xpath_ref()} | {error, term()}.
compile(XPath, Opts) ->
    NS = maps:get(namespaces, Opts, #{}),
    case parse(XPath) of
        {ok, Expr} ->
            case (catch xmlrat_xpath_compile:compile_module(Expr, NS)) of
                {ok, Mod} ->
                    {ok, #xpath_ref{mod = Mod}};
                {'EXIT', Why} ->
                    {error, Why}
            end;
        E = {error, _} ->
            E
    end.

-type xpath_result() ::
    [xmlrat:element()] | [xmlrat:attribute()] | binary() | [xmlrat:content()].

%% @doc Executes an XPath expression over an input document.
-spec run(xpath() | xpath_ref(), xmlrat:document()) ->
    {ok, xpath_result()} | {error, term()}.
run(#xpath_ref{mod = Mod}, Doc) ->
    {ok, Mod:match(Doc)};
run(XPath, Doc) ->
    case compile(XPath) of
        {ok, #xpath_ref{mod = Mod}} ->
            Res = Mod:match(Doc),
            code:delete(Mod),
            code:purge(Mod),
            {ok, Res};
        E = {error, _} ->
            E
    end.

-type varbinds() :: #{binary() => binary() | integer()}.
%% Bound variables for use within an XPath expression.
%%
%% For example, after compiling the XPath expression
%% <code>/foo[@bar = $var]</code>, you could execute it with different values
%% in place of <code>$var</code> by using:
%% <pre>
%% xmlrat_xpath:run(Expr, Doc, #{variables =>
%%   #{&lt;&lt;"var"&gt;&gt; => &lt;&lt;"1"&gt;&gt;}})
%% </pre>
%% etc.

-type run_options() :: #{
    namespaces => nsmap(),
    variables => varbinds()}.
%% Options used with <code>run/3</code>.

%% @doc Executes an XPath expression over an input document, with options.
-spec run(xpath() | xpath_ref(), xmlrat:document(), run_options()) ->
    {ok, xpath_result()} | {error, term()}.
run(#xpath_ref{mod = Mod}, Doc, Opts) ->
    VarBinds = maps:get(variables, Opts, #{}),
    {ok, Mod:match(Doc, VarBinds)};
run(XPath, Doc, Opts) ->
    VarBinds = maps:get(variables, Opts, #{}),
    case compile(XPath, Opts) of
        {ok, #xpath_ref{mod = Mod}} ->
            Res = Mod:match(Doc, VarBinds),
            code:delete(Mod),
            code:purge(Mod),
            {ok, Res};
        E = {error, _} ->
            E
    end.
