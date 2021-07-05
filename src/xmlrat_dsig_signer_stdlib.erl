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

%% @doc The default <code>xmlrat_dsig_signer</code> implementation, which uses
%%      the built-in <code>public_key</code> module and private keys provided
%%      in options.
-module(xmlrat_dsig_signer_stdlib).

-include_lib("public_key/include/public_key.hrl").

-behaviour(xmlrat_dsig_signer).

-export([algorithms/1, sign/3, key_details/1]).

%% @doc Returns a list of algorithms supported by this signing instance.
-spec algorithms(Opts :: xmlrat_dsig_signer:options()) ->
    {ok, [xmlrat_dsig_signer:algo()]} | {error, term()}.
algorithms(#{private_key := #'RSAPrivateKey'{}}) ->
    {ok, [{rsa, sha512}, {rsa, sha384}, {rsa, sha256}, {rsa, sha}]};
algorithms(#{private_key := #'ECPrivateKey'{}}) ->
    {ok, [{ecdsa, sha256}, {ecdsa, sha}]};
algorithms(#{private_key := #'DSAPrivateKey'{}}) ->
    {ok, [{dsa, sha256}, {dsa, sha}]};
algorithms(_) ->
    {error, invalid_key_options}.

%% @doc Returns information about the signing key which should be included in
%% the signature metadata.
%%
%% At least one of the keys in the <code>key_details()</code> map must be set.
-spec key_details(Opts :: xmlrat_dsig_signer:options()) ->
    {ok, xmlrat_dsig_signer:key_details()} | {error, term()}.
key_details(#{private_key := #'RSAPrivateKey'{modulus = M,
                                              publicExponent = E}}) ->
    {ok, #{
        public_key => #'RSAPublicKey'{modulus = M, publicExponent = E}
    }};
key_details(#{private_key := #'ECPrivateKey'{parameters = Params,
                                             publicKey = Point}}) ->
    {ok, #{
        public_key => {#'ECPoint'{point = Point}, Params}
    }}.

%% @doc Signs a message using one of the algorithms retrieved via algorithms/1.
-spec sign(Opts :: xmlrat_dsig_signer:options(),
    Message :: xmlrat_dsig_signer:msg(), Algo :: xmlrat_dsig_signer:algo()) ->
    {ok, xmlrat_dsig_signer:signature()} | {error, next_algo} | {error, term()}.
sign(#{private_key := Key}, Msg, {_PubAlgo, HashAlgo}) ->
    {ok, public_key:sign(Msg, HashAlgo, Key)}.
