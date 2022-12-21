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

%% @doc Types and functions relating to Document Type Declarations (DTDs).
-module(xmlrat_dtd).

%% @headerfile "../include/records.hrl"
-include_lib("xmlrat/include/records.hrl").

-export_type([
    doctype/0, info/0, contentspec/0, attrdef/0, attrtype/0,
    attrdefault/0
    ]).

-type doctype() :: #xml_doctype{}.
-type info() :: #{
  external_id => xmlrat:extid(),
  subset => dtd()
  }.

-type dtd() :: [decl()].
-type decl() :: decl_element() | decl_attlist() | decl_entity() |
  decl_notation() | xmlrat:pi() | xmlrat:comment().

-type decl_element() :: #xmld_element{}.
-type contentspec() :: empty | any | {mixed, [xmlrat:tag()]} | kidspec().
-type xarity() :: zero_or_one | zero_or_more | one_or_more | one.
-type kidspec() ::
  {xarity(), xmlrat:tag()} |
  {xarity(), kidspec()} |
  {choice, [kidspec()]} |
  {seq, [kidspec()]}.

-type decl_attlist() :: #xmld_attlist{}.
-type attrdef() :: #xmld_attr{}.
-type attrtype() :: cdata | {one|many, id|idref|entity|nmtoken} |
  {enum, [binary()]}.
-type attrdefault() :: required | implied | binary().

-type decl_entity() :: #xmld_entity{} | #xmld_parameter{}.

-type decl_notation() :: #xmld_notation{}.
