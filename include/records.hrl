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

-record(xml, {
    version = <<"1.0">> :: xmlrat:xmlver(),
    encoding :: undefined | xmlrat:encoding(),
    standalone :: undefined | yes | no
    }).

-record(xml_attribute, {
    name :: xmlrat:attrname(),
    value :: xmlrat:attrvalue()
    }).

-record(xml_namespace, {
    name :: default | xmlrat:nsname(),
    uri :: xmlrat:uri() | xmlrat:attrvalue()
    }).

-record(xml_comment, {
    text :: binary()
    }).

-record(xml_pi, {
    target :: xmlrat:pitarget(),
    options :: xmlrat:piopts()
    }).

-record(xml_element, {
    tag :: xmlrat:tag(),
    attributes = [] :: [xmlrat:attribute() | xmlrat:namespace() | xmlrat:whitespace()],
    content = [] :: [xmlrat:content()]
    }).

-record(xml_doctype, {
    name :: xmlrat:xmlname(),
    info = #{} :: xmlrat_dtd:info()
    }).

-record(xmld_element, {
    tag :: xmlrat:tag(),
    content :: xmlrat_dtd:contentspec()
    }).

-record(xmld_attlist, {
    tag :: xmlrat:tag(),
    attributes = [] :: [xmlrat_dtd:attrdef()]
    }).

-record(xmld_attr, {
    name :: xmlrat:attrname(),
    type = cdata :: xmlrat_dtd:attrtype(),
    default = required :: xmlrat_dtd:attrdefault()
    }).

-record(xmld_entity, {
    name :: xmlrat:xmlname(),
    content :: binary() | xmlrat:extid() |
               {xmlrat:extid(), {ndata, xmlrat:xmlname()}}
    }).

-record(xmld_parameter, {
    name :: xmlrat:xmlname(),
    content :: binary() | xmlrat:extid()
    }).

-record(xmld_notation, {
    name :: xmlrat:xmlname(),
    id :: xmlrat:extid() | {public, xmlrat:pubid()}
    }).
