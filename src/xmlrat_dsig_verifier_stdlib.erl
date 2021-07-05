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

%% @doc The default <code>xmlrat_dsig_verifier</code> implementation, which uses
%%      the built-in <code>public_key</code> module.
%%
-module(xmlrat_dsig_verifier_stdlib).

-include_lib("public_key/include/public_key.hrl").

-behaviour(xmlrat_dsig_verifier).

-export([retrieve_key/3, validate_key/4, validate_cert/3]).

-spec retrieve_key(xmlrat_dsig_verifier:options(),
    xmlrat_dsig_verifier:key_details(), xmlrat_dsig_verifier:algo()) ->
    {ok, xmlrat_dsig_verifier:pubkey()} | {error, term()}.
%% @doc Retrieves a key based on metadata about the key.
%%
%% Ccalled when the XML-DSIG payload does not include a certificate or the key
%% itself. The {@link validate_key/2} callback will also be called for this key
%% after retrieval.
retrieve_key(_Opts, _Details, _Algo) ->
    {error, no_key_db}.

%% @doc Validate a bare public key.
%%
%% The public key was either included in the XML DSIG payload or retrieved
%% via {@link retrieve_key/3} (not called if an X.509 certificate was included).
-spec validate_key(xmlrat_dsig_verifier:options(), xmlrat_dsig_verifier:pubkey(),
    xmlrat_dsig_verifier:key_details(), xmlrat_dsig_verifier:algo())
        -> ok | {error, term()}.
validate_key(#{danger_trust_any_key := true}, _PubKey, _Details, _Algo) ->
    ok.

%% @doc Validate an X.509 certificate included in the XML DSIG payload.
-spec validate_cert(xmlrat_dsig_verifier:options(), xmlrat_dsig_verifier:cert(),
    xmlrat_dsig_verifier:algo()) -> ok | {error, term()}.
validate_cert(#{danger_trust_any_cert := true}, _Cert, _Algo) ->
    ok.
