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

%% @doc Behaviour for callback modules which verify the keys used to sign
%%      XML-DSIG payloads.
%%
%% The key retrieval and validation operations are replaceable so that consumers
%% of this library may implement their own forms of key storage or validation
%% (e.g. retrieving keys from a database based on the key name or fingerprint,
%% or doing custom certificate validation).
%%
%% The default implementation of this behaviour can be seen in
%% {@link xmlrat_dsig_verifier_stdlib}.
-module(xmlrat_dsig_verifier).

-include_lib("public_key/include/public_key.hrl").

-export_type([options/0, algo/0, key_details/0, pubkey/0, cert/0]).

-type options() :: map().
-type pubkey_algo() :: xmlrat_dsig:pubkey_algo().
-type hash_algo() :: xmlrat_dsig:hash_algo().
-type algo() :: {pubkey_algo(), hash_algo()}.
-type key_details() :: #{name => binary()}.

-type pubkey() :: xmlrat_dsig:pubkey().
%% See {@link xmlrat_dsig:pubkey()}

-type cert() :: xmlrat_dsig:cert().
%% See {@link xmlrat_dsig:cert()}

-callback retrieve_key(options(), key_details(), algo()) ->
    {ok, pubkey()} | {error, term()}.
%% Retrieves a key based on metadata about the key (called when the XML-DSIG
%% payload does not include a certificate or the key itself). The validate_key/2
%% callback will also be called for this key after retrieval.

-callback validate_key(options(), pubkey(), key_details(), algo()) -> ok | {error, term()}.
%% Validate a bare public key which was included in the XML DSIG payload (not
%% called if an X.509 certificate was included).

-callback validate_cert(options(), cert(), algo()) -> ok | {error, term()}.
%% Validate an X.509 certificate included in the XML DSIG payload.
