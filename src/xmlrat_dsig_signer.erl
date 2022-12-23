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

%% @doc Behaviour for callback modules which sign XML-DSIG payloads.
%%
%% The signing operation is replaceable so that consumers of this library
%% may use keys not stored in the memory of the Erlang process (e.g.
%% stored in a hardware token accessed via PKCS11 or the <code>ssh-agent</code>
%% protocol).
%%
%% The default implementation of this behaviour can be seen in
%% {@link xmlrat_dsig_signer_stdlib}.
-module(xmlrat_dsig_signer).

-include_lib("public_key/include/public_key.hrl").

-export_type([options/0, msg/0, algo/0, signature/0, key_details/0]).

-type options() :: map().
-type msg() :: binary().
-type signature() :: binary().
-type pubkey_algo() :: xmlrat_dsig:pubkey_algo().
-type hash_algo() :: xmlrat_dsig:hash_algo().
-type algo() :: {pubkey_algo(), hash_algo()}.
-type pubkey() :: xmlrat_dsig:pubkey().
-type cert() :: xmlrat_dsig:cert().
-type key_details() :: xmlrat_dsig:key_details().

-callback algorithms(options()) -> {ok, [algo()]} | {error, term()}.
%% Returns a list of algorithms supported by this signing instance.

-callback key_details(options()) -> {ok, key_details()} | {error, term()}.
%% Returns information about the signing key which should be included in
%% the signature metadata. At least one of the keys in the
%% <code>key_details()</code> map must be set.

-callback sign(options(), msg(), algo()) ->
    {ok, signature()} | {error, next_algo} | {error, term()}.
%% Signs a message using one of the algorithms retrieved via algorithms/1.
