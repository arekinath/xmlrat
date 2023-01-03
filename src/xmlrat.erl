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

%% @doc Base types representing XML documents and their components.
-module(xmlrat).

%% @headerfile "../include/records.hrl"
-include_lib("xmlrat/include/records.hrl").

-export_type([
    document/0, element/0
    ]).

-export_type([
    xmlver/0, attrname/0, attrvalue/0, nsname/0, uri/0,
    pitarget/0, piopts/0, tag/0, attribute/0, namespace/0, content/0,
    extid/0, pubid/0, component/0, tagged_record/2
    ]).

-type tagged_record(T, _Tag) :: T.
%% A record type which contains a field named `tag', set to the given XML
%% tag name. Enables the use of generic records for a set of XML tags with
%% different names but the same underlying type.

-type document() :: [component()].
%% An XML document, consisting of components.

-type component() :: prolog() | element() | comment() | pi() | whitespace().
%% A top-level component within an XML document.

-type whitespace() :: binary().
%% A binary consisting of whitespace characters (<code>[ \r\n\t]</code> etc)

-type prolog() :: xmldecl() | xmlrat_dtd:doctype().
%% A prolog component, which can appear before the first XML element in a
%% document.

-type element() :: #xml_element{}.
%% An XML element, which has a tag, attributes, and content.

-type content() :: binary() | {entity, binary()} | {parameter, binary()} |
  element() | pi() | comment().
%% Possible types of content within an XML document.

-type attribute() :: #xml_attribute{}.
%% An XML attribute, which is attached to an element, describing some property
%% of that element.

-type namespace() :: #xml_namespace{}.
%% An XML namespace (<code>xmlns:*</code> attribute), describing a namespace
%% which is available on an element and its children.

-type attrvalue() :: binary() |
  [binary() | {entity, binary()} | {parameter, binary()}].
%% The value of an XML attribute.

-type xmlnsname() :: {nsname(), binary()}.
%% An XML name scoped to a namespace, but the namespace has not yet been
%% resolved (e.g. because it isn't defined, but the options given to the parser
%% allow undefined namespaces).

-type xmlnsuriname() :: {nsname(), binary(), uri()}.
%% An XML name scoped to a namespace, fully resolved with the final URI
%% available.

-type xmlname() :: binary() | xmlnsname() | xmlnsuriname().
%% An XML name (may be for an element or attribute, or other concept). May have
%% namespace information attached.

-type tag() :: xmlname().
%% The tag of an XML element.

-type attrname() :: xmlname().
%% The name of an attribute.

-type nsname() :: default | binary().
%% The name of a namespace. Can be the atom <code>default</code> to indicate
%% that no namespace name was given (but a default namespace is in force for
%% the given scope).

-type uri() :: binary().
%% A URI, encoded as a UTF-8 binary.

-type pubid() :: binary().

-type extid() :: {system, uri()} | {public, pubid(), uri()}.

-type comment() :: #xml_comment{}.
%% A comment in an XML document, containing arbitrary character data.

-type pi() :: #xml_pi{}.
%% An XML processing instruction.

-type pitarget() :: binary().
%% The name of a processing instruction's "target" (the first part, specifying
%% the kind of PI it is, e.g. <code>&lt;&lt;"xml-stylesheet"&gt;&gt;</code>).

-type piopts() :: binary() | [attribute()].
%% The parameters to the PI. If these parsed successfully as if they were XML
%% attributes, then the second form is used. Otherwise, the raw parameters as
%% a binary are given.

-type xmldecl() :: #xml{}.
%% The XML document declaration (<code>&lt;?xml version="1.0"...?&gt;</code>).
-type xmlver() :: binary().
%% XML version, must be <code>&lt;&lt;"1.0"&gt;&gt;</code>
-type encoding() :: binary().
%% Encoding, e.g. <code>&lt;&lt;"utf-8"&gt;&gt;</code>
