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

%% @doc Implementation of XML Digital Signature (DSIG).
%%
%% See <a href='https://www.w3.org/TR/xmldsig-core1/'>W3C Recommendation:
%% XML Signature Syntax and Processing Version 1.1</a>.
%%
%% Features supported:
%% <ul>
%%   <li>Sign and validate enveloped signatures</li>
%%   <li>Sign and validate detached signatures</li>
%%   <li>Signatures on specific elements by ID</li>
%%   <li>C14N transforms</li>
%%   <li>KeyInfo for RSA and ECDSA keys, with or without X.509 certificates</li>
%%   <li>RSA at standard key lengths</li>
%%   <li>EC curves: NIST P-256, NIST P-384, NIST P-521</li>
%%   <li>Hash functions: SHA2-512, SHA2-384, SHA2-256, SHA-1</li>
%% </ul>
%%
%% The behaviours {@link xmlrat_dsig_signer} and {@link xmlrat_dsig_verifier}
%% allow providing a callback module to customise the behaviour of
%% <code>xmlrat_dsig</code> with respect to obtaining and using private keys and
%% validating public keys and certificates.
-module(xmlrat_dsig).

-include_lib("xmlrat/include/records.hrl").
-include_lib("xmlrat/include/dsig.hrl").
-include_lib("public_key/include/public_key.hrl").

-compile({parse_transform, xmlrat_parse_transform}).

-export([
    verify/2, verify/3, sign/2,
    parse_key/1, generate_key/1
    ]).

% These are exported to silence the "unused function" warnings.
-export([
    match_id/1, encode_xform/1, encode_ref/1, encode_keyvalue_rsa/1,
    encode_keyvalue_ec/1, encode_keyinfo/1
    ]).

-export_type([
    pubkey_algo/0, hash_algo/0, pubkey/0,
    cert/0, key_details/0
    ]).

-type base64() :: binary().
-type uri() :: binary().

-type pubkey_algo() :: rsa | dsa | ecdsa | hmac.
-type hash_algo() :: sha | sha256 | sha384 | sha512.
-type pubkey() :: #'RSAPublicKey'{} |
    {integer(), #'Dss-Parms'{}} |
    {#'ECPoint'{}, {namedCurve, tuple() | atom()}}.
-type cert() :: #'OTPCertificate'{}.
-type key_details() :: #{
    public_key => pubkey(),
    certificate => cert(),
    name => binary()
    }.

-record(transform, {
    algo :: uri(),
    force_ns :: undefined | binary()
    }).

-record(reference, {
    uri :: undefined | uri(),
    xforms :: [#transform{}],
    digest_meth :: uri(),
    digest :: base64()
    }).

-record(keyvalue_rsa, {
    modulus :: base64(),
    exponent :: base64()
    }).

-record(keyvalue_ec, {
    curve :: uri(),
    pubkey :: base64()
    }).

-record(keyinfo, {
    name :: undefined | binary(),
    certs :: undefined | [base64()],
    key :: undefined | #keyvalue_rsa{} | #keyvalue_ec{}
    }).

-record(signedinfo, {
    c14n_meth :: uri(),
    sig_meth :: uri(),
    refs :: [#reference{}]
    }).

-record(signature, {
    id :: undefined | binary(),
    info :: #signedinfo{},
    sig :: base64(),
    key :: #keyinfo{}
    }).

-type verify_options() :: #{
    verifier_options => map(),
    verifier => module()
    }.

%% @doc Parse a ds:KeyInfo element.
%%
%% Converts a <code>ds:KeyInfo</code> element into the more friendly
%% {@link key_details()} map, containing decoded certificates and public
%% keys.
-spec parse_key(xmlrat:document()) -> {ok, key_details()} | {error, term()}.
parse_key(Doc) ->
    case (catch decode_keyinfo(Doc)) of
        {'EXIT', Why} ->
            {error, Why};
        #keyinfo{name = undefined, certs = undefined, key = undefined} ->
            {error, insufficient_key_info};
        #keyinfo{name = N, certs = undefined, key = undefined} when is_binary(N) ->
            {ok, #{name => N}};
        #keyinfo{certs = [CertB64 | _]} ->
            CertBin = base64:decode(CertB64),
            Cert = #'OTPCertificate'{} =
                public_key:pkix_decode_cert(CertBin, otp),
            PubKey = cert_to_pubkey(Cert),
            {ok, #{certificate => Cert, public_key => PubKey}};
        #keyinfo{name = N, key = KeyValue} ->
            Details0 = case N of
                undefined -> #{};
                _ -> #{name => N}
            end,
            PubKey = keyvalue_to_pubkey(KeyValue),
            {ok, Details0#{public_key => PubKey}}
    end.

%% @doc Generate a ds:KeyInfo element.
%%
%% Inverse of {@link parse_key/1}. Converts a {@link key_details()} map into
%% a <code>ds:KeyInfo</code> element.
-spec generate_key(key_details()) -> {ok, xmlrat:document()} | {error, term()}.
generate_key(#{certificate := Cert}) ->
    Der = public_key:pkix_encode('OTPCertificate', Cert, otp),
    B64 = base64:encode(Der),
    case (catch encode_keyinfo(#keyinfo{certs = [B64]})) of
        {'EXIT', Why} -> {error, Why};
        Enc -> {ok, Enc}
    end;
generate_key(KD = #{public_key := PubKey}) ->
    KV = pubkey_to_keyvalue(PubKey),
    KI0 = #keyinfo{key = KV},
    KI1 = case KD of
        #{name := Name} -> KI0#keyinfo{name = Name};
        _ -> KI0
    end,
    case (catch encode_keyinfo(KI1)) of
        {'EXIT', Why} -> {error, Why};
        Enc -> {ok, Enc}
    end.

%% @doc Verifies an enveloped XML-DSIG signature.
%%
%% The signature may not cover every part of the subject document, so this
%% function (and {@link verify/3}) return a <code>VerifiedSubset</code> document
%% containing just the parts covered by the signature. Parent elements of
%% covered elements are preserved, but have all their attributes and other
%% content (other than the signed parts) removed.
-spec verify(xmlrat:document(), verify_options()) ->
    {ok, VerifiedSubset :: xmlrat:document()} | {error, term()}.
verify(Doc, Opts) ->
    case extract_sig(Doc) of
        SigDoc = [_SigElem] ->
            SignedDoc = strip_sig(Doc),
            verify(SignedDoc, SigDoc, Opts);
        [] ->
            {error, no_signature_element}
    end.

%% @doc Verifies a detached XML-DSIG signature.
-spec verify(xmlrat:document(), xmlrat:document(), verify_options()) ->
    {ok, VerifiedSubset :: xmlrat:document()} | {error, term()}.
verify(SignedDoc, SigDoc, Opts) ->
    % First, parse the signature and its contained information.
    case (catch decode_sig(SigDoc)) of
        {'EXIT', Why} ->
            {error, Why};

        #signature{info = SignedInfo, sig = SignatureB64, key = KeyInfo} ->
            #signedinfo{c14n_meth = C14NMethURI,
                        sig_meth = SigMethURI} = SignedInfo,
            case C14NMethURI of
                ?dsig_XML_c14n_exc -> ok;
                ?dsig_XML_c14n_10 -> ok;
                ?dsig_XML_c14n_11 -> ok;
                _ -> error({unsupported_c14n_method, C14NMethURI})
            end,
            SigAlgo = algo_from_uri(SigMethURI),

            % Next: make sure we have a valid public key signing this payload.
            case get_validated_pubkey(Opts, SigAlgo, KeyInfo) of
                E = {error, _Why} ->
                    E;

                {ok, PubKey} ->
                    % Now we can verify the signature on the SignedInfo.
                    SigInfo = [_SigInfoElem] = extract_siginfo(SigDoc),
                    CanonSignedInfo = xmlrat_c14n:string(SigInfo),
                    {_, SigHash} = SigAlgo,
                    Signature = base64:decode(SignatureB64),
                    Result = public_key:verify(CanonSignedInfo, SigHash,
                        Signature, PubKey),
                    case Result of
                        false ->
                            {error, invalid_signature};

                        true ->
                            % And finally, we verify the digest of each
                            % reference.
                            #signedinfo{refs = Refs} = SignedInfo,
                            ValidRefs = lists:all(fun (Ref) ->
                                verify_reference(SignedDoc, Ref)
                            end, Refs),
                            case ValidRefs of
                                false ->
                                    {error, invalid_digest};
                                true ->
                                    RefSub = referenced_subset(SignedDoc, Refs),
                                    {ok, RefSub}
                            end
                    end
            end
    end.

% HACK: we look for any attributes named like "id" rather than actually looking
%       at the DTD or XSD. this is kinda hacky, but works fine for pretty much
%       all reasonable users of dsig (and very few generate a useful DTD).
-xpath({match_id, "//*[@ID = $id or @Id = $id or @id = $id]"}).

%% Returns the referenced subset of a document
%% This consists of the elements covered by a reference, plus all of their
%% children, plus their parents (but parents will have attributes removed if
%% the element is not covered by any reference)
-spec referenced_subset(xmlrat:document(), [#reference{}]) -> xmlrat:document().
referenced_subset([], _Refs) -> [];
referenced_subset([E0 = #xml_element{} | Rest], Refs) ->
    MatchesRef = lists:any(fun (Ref) -> matches_ref(E0, Ref) end, Refs),
    case MatchesRef of
        true ->
            [E0 | referenced_subset(Rest, Refs)];
        false ->
            #xml_element{content = C0} = E0,
            C1 = referenced_subset(C0, Refs),
            case C1 of
                [] ->
                    referenced_subset(Rest, Refs);
                _ ->
                    E1 = E0#xml_element{attributes = [], content = C1},
                    [E1 | referenced_subset(Rest, Refs)]
            end
    end;
referenced_subset([_ | Rest], Refs) ->
    referenced_subset(Rest, Refs).

-spec matches_ref(xmlrat:element(), #reference{}) -> boolean().
matches_ref(E = #xml_element{}, #reference{uri = URI}) ->
    case URI of
        undefined ->
            true;
        <<>> ->
            true;
        <<"#", ID/binary>> ->
            case match_id([E], #{<<"id">> => ID}) of
                [E] -> true;
                _ -> false
            end
    end.

%% Verify a reference against (part of, or the entire) signed document given.
-spec verify_reference(xmlrat:document(), #reference{}) -> boolean().
verify_reference(SignedDoc, Ref) ->
    #reference{uri = URI,
               xforms = XForms,
               digest_meth = DigestMethURI,
               digest = TheirDigestB64} = Ref,
    % If the URI is empty or not given, that means the outer document
    % (enveloped) or the whole message document (separate).
    DigestDoc = case URI of
        undefined ->
            SignedDoc;
        <<>> ->
            SignedDoc;
        <<"#", ID/binary>> ->
            match_id(SignedDoc, #{<<"id">> => ID})
        % TODO: support other forms of the URI? there are other ways to specify
        %       an ID?
    end,
    % Usually the transforms include a c14n variant, so we'll get a binary back
    % from run_xforms/2. If it doesn't, though, this is still valid, and we
    % should just do regular c14n (no comments) with no options on the result.
    CanonMsg0 = run_xforms(DigestDoc, XForms),
    CanonMsg1 = case CanonMsg0 of
        _ when is_binary(CanonMsg0) -> CanonMsg0;
        [_|_] -> xmlrat_c14n:string(CanonMsg0)
    end,
    DigestAlgo = hash_algo_from_uri(DigestMethURI),
    OurDigest = crypto:hash(DigestAlgo, CanonMsg1),
    TheirDigest = base64:decode(TheirDigestB64),
    hash_compare(OurDigest, TheirDigest).

%% Runs a list of transforms.
-spec run_xforms(xmlrat:document() | binary(), [#transform{}]) ->
    xmlrat:document() | binary().
run_xforms(Doc, []) -> Doc;
run_xforms(Doc0, [Next | Rest]) ->
    Doc1 = run_xform(Doc0, Next),
    run_xforms(Doc1, Rest).

-spec run_xform(xmlrat:document(), #transform{}) -> xmlrat:document() | binary().
run_xform(Doc, #transform{algo = ?dsig_enveloped}) ->
    Doc;
run_xform(Doc, #transform{algo = Alg, force_ns = undefined}) when
        (Alg =:= ?dsig_XML_c14n_exc) or (Alg =:= ?dsig_XML_c14n_10) or
        (Alg =:= ?dsig_XML_c14n_11) ->
    xmlrat_c14n:string(Doc);
run_xform(Doc, #transform{algo = Alg, force_ns = ForceNS0}) when
        (Alg =:= ?dsig_XML_c14n_exc) or (Alg =:= ?dsig_XML_c14n_10) or
        (Alg =:= ?dsig_XML_c14n_11) ->
    ForceNS1 = binary:split(ForceNS0, [<<" ">>, <<"\t">>, <<",">>],
        [global, trim_all]),
    ForceNS2 = lists:foldl(fun
        (<<"default">>, Acc) -> Acc#{default => true};
        (NS, Acc) -> Acc#{NS => true}
    end, #{}, ForceNS1),
    xmlrat_c14n:string(Doc, #{force_namespaces => ForceNS2});
run_xform(Doc, #transform{algo = ?dsig_XML_c14n_11}) ->
    xmlrat_c14n:string(Doc);
run_xform(_Doc, #transform{algo = URI}) ->
    error({unsupported_transform, URI}).

-type keyvalue() :: #keyvalue_rsa{} | #keyvalue_ec{}.

-spec keyvalue_to_pubkey(keyvalue()) -> pubkey().
keyvalue_to_pubkey(#keyvalue_rsa{modulus = ModB64, exponent = ExpB64}) ->
    Mod = base64:decode(ModB64),
    Exp = base64:decode(ExpB64),
    <<Modulus:(bit_size(Mod))/big>> = Mod,
    <<Exponent:(bit_size(Exp))/big>> = Exp,
    #'RSAPublicKey'{modulus = Modulus, publicExponent = Exponent};
keyvalue_to_pubkey(#keyvalue_ec{curve = CurveURI, pubkey = PointB64}) ->
    CurveOID = case CurveURI of
        <<"urn:oid:", OidString/binary>> ->
            list_to_tuple([binary_to_integer(X) || X <-
                binary:split(OidString, <<".">>, [global])]);
        _ ->
            error({unsupported_ec_curve, CurveURI})
    end,
    CurveName = case CurveOID of
        ?'secp256r1' -> secp256r1;
        ?'secp384r1' -> secp384r1;
        ?'secp521r1' -> secp521r1;
        _ -> CurveOID
    end,
    Point = base64:decode(PointB64),
    {#'ECPoint'{point = Point}, {namedCurve, CurveName}}.

-spec pubkey_to_keyvalue(pubkey()) -> keyvalue().
pubkey_to_keyvalue(#'RSAPublicKey'{modulus = Modulus,
                                   publicExponent = Exponent}) ->
    Mod = binary:encode_unsigned(Modulus),
    Exp = binary:encode_unsigned(Exponent),
    #keyvalue_rsa{modulus = base64:encode(Mod),
                  exponent = base64:encode(Exp)};
pubkey_to_keyvalue({#'ECPoint'{point = Point}, {namedCurve, CurveName}}) ->
    CurveOID = case CurveName of
        prime256v1 -> ?'secp256r1';
        secp256r1 -> ?'secp256r1';
        secp384r1 -> ?'secp384r1';
        secp521r1 -> ?'secp521r1';
        _ when is_tuple(CurveName) -> CurveName
    end,
    OIDString = iolist_to_binary(lists:join($.,
        [integer_to_binary(X) || X <- tuple_to_list(CurveOID)])),
    CurveURI = <<"urn:oid:", OIDString/binary>>,
    #keyvalue_ec{curve = CurveURI,
                 pubkey = base64:encode(Point)}.

-spec cert_to_pubkey(#'OTPCertificate'{}) -> pubkey().
cert_to_pubkey(#'OTPCertificate'{} = Cert) ->
    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{subjectPublicKeyInfo = SPKI}
        } = Cert,
    #'OTPSubjectPublicKeyInfo'{
        algorithm = #'PublicKeyAlgorithm'{
            algorithm = AlgoOID,
            parameters = Params},
        subjectPublicKey = PubKey} = SPKI,
    case AlgoOID of
        ?'rsaEncryption' ->
            PubKey;
        ?'id-ecPublicKey' ->
            {namedCurve, CurveOID} = Params,
            case CurveOID of
                A when is_atom(A) -> {PubKey, {namedCurve, CurveOID}};
                ?'secp256r1' -> {PubKey, {namedCurve, secp256r1}};
                ?'secp384r1' -> {PubKey, {namedCurve, secp384r1}};
                ?'secp521r1' -> {PubKey, {namedCurve, secp521r1}};
                _ -> {PubKey, {namedCurve, CurveOID}}
            end
    end.

-spec key_type(pubkey()) -> xmlrat_dsig_signer:pubkey_algo().
key_type(#'RSAPublicKey'{}) -> rsa;
key_type({#'ECPoint'{}, {namedCurve, _}}) -> ecdsa;
key_type({I, #'Dss-Parms'{}}) when is_integer(I) -> dsa;
key_type(B) when is_binary(B) -> hmac.

-spec get_validated_pubkey(verify_options(), xmlrat_dsig_signer:algo(),
    #keyinfo{}) -> {ok, pubkey()} | {error, term()}.
get_validated_pubkey(Opts, SigAlgo = {KeyType, _}, KeyInfo) ->
    VerMod = maps:get(verifier, Opts, xmlrat_dsig_verifier_stdlib),
    VerOpts = maps:get(verifier_options, Opts, #{}),
    case KeyInfo of
        #keyinfo{name = undefined, certs = undefined, key = undefined} ->
            {error, insufficient_key_info};
        #keyinfo{name = N, certs = undefined, key = undefined} when is_binary(N) ->
            case VerMod:retrieve_key(VerOpts, #{name => N}, SigAlgo) of
                {ok, PubKey} ->
                    case key_type(PubKey) of
                        KeyType ->
                            R = VerMod:validate_key(VerOpts, PubKey, #{},
                                                    SigAlgo),
                            case R of
                                ok -> {ok, PubKey};
                                E = {error, _} -> E
                            end;
                        _ ->
                            {error, key_type_mismatch}
                    end;
                E = {error, _} -> E
            end;
        #keyinfo{certs = [CertB64 | _]} ->
            CertBin = base64:decode(CertB64),
            Cert = #'OTPCertificate'{} =
                public_key:pkix_decode_cert(CertBin, otp),
            PubKey = cert_to_pubkey(Cert),
            case key_type(PubKey) of
                KeyType ->
                    case VerMod:validate_cert(VerOpts, Cert, SigAlgo) of
                        ok -> {ok, PubKey};
                        E = {error, _} -> E
                    end;
                _ ->
                    {error, key_type_mismatch}
            end;
        #keyinfo{name = N, key = KeyValue} ->
            Details = case N of
                undefined -> #{};
                _ -> #{name => N}
            end,
            PubKey = keyvalue_to_pubkey(KeyValue),
            case key_type(PubKey) of
                KeyType ->
                    case VerMod:validate_key(VerOpts, PubKey, Details, SigAlgo) of
                        ok -> {ok, PubKey};
                        E = {error, _} -> E
                    end;
                _ ->
                    {error, key_type_mismatch}
            end
    end.

-spec algo_from_uri(uri()) -> xmlrat_dsig_signer:algo().
algo_from_uri(?dsig_RSAwithSHA1) -> {rsa, sha};
algo_from_uri(?dsig_RSAwithSHA256) -> {rsa, sha256};
algo_from_uri(?dsig_RSAwithSHA384) -> {rsa, sha384};
algo_from_uri(?dsig_RSAwithSHA512) -> {rsa, sha512};
algo_from_uri(?dsig_DSAwithSHA1) -> {dsa, sha};
algo_from_uri(?dsig_DSAwithSHA256) -> {dsa, sha256};
algo_from_uri(?dsig_ECDSAwithSHA1) -> {ecdsa, sha1};
algo_from_uri(?dsig_ECDSAwithSHA256) -> {ecdsa, sha256};
algo_from_uri(?dsig_ECDSAwithSHA384) -> {ecdsa, sha384};
algo_from_uri(?dsig_ECDSAwithSHA512) -> {ecdsa, sha512};
algo_from_uri(?dsig_HMAC_SHA1) -> {hmac, sha};
algo_from_uri(?dsig_HMAC_SHA256) -> {hmac, sha256};
algo_from_uri(?dsig_HMAC_SHA384) -> {hmac, sha384};
algo_from_uri(?dsig_HMAC_SHA512) -> {hmac, sha512};
algo_from_uri(URI) -> error({unsupported_algo, URI}).

-spec uri_from_algo(xmlrat_dsig_signer:algo()) -> uri().
uri_from_algo({rsa, sha}) -> ?dsig_RSAwithSHA1;
uri_from_algo({rsa, sha256}) -> ?dsig_RSAwithSHA256;
uri_from_algo({rsa, sha384}) -> ?dsig_RSAwithSHA384;
uri_from_algo({rsa, sha512}) -> ?dsig_RSAwithSHA512;
uri_from_algo({dsa, sha}) -> ?dsig_DSAwithSHA1;
uri_from_algo({dsa, sha256}) -> ?dsig_DSAwithSHA256;
uri_from_algo({ecdsa, sha1}) -> ?dsig_ECDSAwithSHA1;
uri_from_algo({ecdsa, sha256}) -> ?dsig_ECDSAwithSHA256;
uri_from_algo({ecdsa, sha384}) -> ?dsig_ECDSAwithSHA384;
uri_from_algo({ecdsa, sha512}) -> ?dsig_ECDSAwithSHA512;
uri_from_algo({hmac, sha}) -> ?dsig_HMAC_SHA1;
uri_from_algo({hmac, sha256}) -> ?dsig_HMAC_SHA256;
uri_from_algo({hmac, sha384}) -> ?dsig_HMAC_SHA384;
uri_from_algo({hmac, sha512}) -> ?dsig_HMAC_SHA512;
uri_from_algo(Algo) -> error({unsupported_algo, Algo}).

-spec hash_algo_from_uri(uri()) -> xmlrat_dsig_signer:hash_algo().
hash_algo_from_uri(?dsig_SHA1) -> sha;
hash_algo_from_uri(?dsig_SHA256) -> sha256;
hash_algo_from_uri(?dsig_SHA384) -> sha384;
hash_algo_from_uri(?dsig_SHA512) -> sha512;
hash_algo_from_uri(URI) -> error({unsupported_hash_algo, URI}).

-spec uri_from_hash_algo(xmlrat_dsig_signer:hash_algo()) -> uri().
uri_from_hash_algo(sha) -> ?dsig_SHA1;
uri_from_hash_algo(sha256) -> ?dsig_SHA256;
uri_from_hash_algo(sha384) -> ?dsig_SHA384;
uri_from_hash_algo(sha512) -> ?dsig_SHA512;
uri_from_hash_algo(Algo) -> error({unsupported_hash_algo, Algo}).

%% Performs a comparison between two binaries by computing their SHA512
%% hashes and checking equality between those. This avoids revealing anything
%% about matching bits/bytes between the raw binaries in the timing of the
%% comparison.
-spec hash_compare(binary(), binary()) -> boolean().
hash_compare(A, B) ->
    DigestA = crypto:hash(sha512, A),
    DigestB = crypto:hash(sha512, B),
    (DigestA =:= DigestB).

-type id() :: binary().
-type sign_options() :: #{
    signer_options => map(),
    signer => module(),
    detached => boolean(),
    signed_elements => [id()],
    hash_preferences => [xmlrat_dsig_signer:hash_algo()]
    }.

-define(sign_defaults, #{
    hash_preferences => [sha512, sha384, sha256, sha],
    signer => xmlrat_dsig_signer_stdlib,
    signer_options => #{},
    detached => false
    }).

%% @doc Signs an XML document.
%%
%% Returns either the complete enveloped document with signature (if
%% <code>detached</code> is <code>false</code>, the default); or just the
%% detached signature document.
-spec sign(xmlrat:document(), sign_options()) ->
    {ok, xmlrat:document()} | {error, term()}.
sign(Doc, Opts0) ->
    Opts1 = maps:merge(?sign_defaults, Opts0),
    #{signer := SignerMod, signer_options := SignerOpts,
      hash_preferences := HashPrefs} = Opts1,
    % First, calculate our references.
    RefURIs = case Opts1 of
        #{signed_elements := IDs} ->
            [<<"#",ID/binary>> || ID <- IDs];
        _ ->
            [<<>>]
    end,
    Refs = generate_references(Doc, RefURIs, Opts1),
    case SignerMod:algorithms(SignerOpts) of
        {ok, KeyAlgos} ->
            case select_algo(HashPrefs, KeyAlgos) of
                {ok, Algo} ->
                    SignedInfo = #signedinfo{c14n_meth = ?dsig_XML_c14n_exc,
                                             sig_meth = uri_from_algo(Algo),
                                             refs = Refs},
                    SIDoc = encode_siginfo(SignedInfo),
                    CanonSI = xmlrat_c14n:string(SIDoc),
                    case SignerMod:sign(SignerOpts, CanonSI, Algo) of
                        {ok, Signature} ->
                            {ok, KeyDetailsMap} = SignerMod:key_details(
                                SignerOpts),
                            KeyInfo = generate_keyinfo(KeyDetailsMap, Opts1),
                            Sig = #signature{
                                info = SignedInfo,
                                sig = base64:encode(Signature),
                                key = KeyInfo
                            },
                            SigDoc = encode_sig(Sig),
                            #{detached := Detached} = Opts1,
                            case Detached of
                                true ->
                                    {ok, SigDoc};
                                false ->
                                    EnvDoc = lists:map(fun
                                        (E = #xml_element{content = C0}) ->
                                            C1 = C0 ++ SigDoc,
                                            E#xml_element{content = C1};
                                        (Other) ->
                                            Other
                                    end, Doc),
                                    {ok, EnvDoc}
                            end;
                        E = {error, _} ->
                            E
                    end;
                E = {error, _} ->
                    E
            end;
        E = {error, _} ->
            E
    end.

generate_keyinfo(Details, _Opts) ->
    KI0 = #keyinfo{},
    KI1 = case Details of
        #{name := Name} when is_binary(Name) ->
            KI0#keyinfo{name = Name};
        _ ->
            KI0
    end,
    KI2 = case Details of
        #{certificate := #'OTPCertificate'{} = Cert} ->
            Der = public_key:pkix_encode('Certificate', Cert, otp),
            KI1#keyinfo{certs = [base64:encode(Der)]};
        #{certificate := #'Certificate'{} = Cert} ->
            Der = public_key:pkix_encode('Certificate', Cert, plain),
            KI1#keyinfo{certs = [base64:encode(Der)]};
        _ ->
            KI1
    end,
    _KI3 = case Details of
        #{public_key := PubKey} ->
            KI2#keyinfo{key = pubkey_to_keyvalue(PubKey)};
        _ ->
            KI2
    end.

select_algo([], KeyAlgos) ->
    {error, {no_key_algo_matched_hash_prefs, KeyAlgos}};
select_algo([Hash | Rest], KeyAlgos) ->
    case first_algo_with_hash(Hash, KeyAlgos) of
        none -> select_algo(Rest, KeyAlgos);
        Alg -> {ok, Alg}
    end.

first_algo_with_hash(_Hash, []) -> none;
first_algo_with_hash(Hash, [A = {_, AHash} | _]) when (Hash =:= AHash) ->
    A;
first_algo_with_hash(Hash, [_ | Rest]) ->
    first_algo_with_hash(Hash, Rest).

-spec generate_references(xmlrat:document(), [uri() | undefined], sign_options()) ->
    [#reference{}].
generate_references(_Doc, [], _Opts) -> [];
generate_references(Doc, [URI | Rest], Opts) ->
    #{detached := Detached} = Opts,
    [RootElem] = [X || X = #xml_element{} <- Doc],
    {DigestDoc, Enveloped} = case URI of
        undefined ->
            {Doc, not Detached};
        <<>> ->
            {Doc, not Detached};
        <<"#", ID/binary>> ->
            SubDoc = match_id(Doc, #{<<"id">> => ID}),
            % If an ID ref specifies the root element (which will end up as an
            % ancestor of the Signature element if not detached), then we may
            % need the enveloped transform. For a random element within it (a
            % sibling of the Signature element or lower) we don't need it.
            case SubDoc of
                [RootElem] -> {SubDoc, not Detached};
                _ -> {SubDoc, false}
            end
        % TODO: support other forms of the URI? there are other ways to specify
        %       an ID?
    end,
    CanonMsg = xmlrat_c14n:string(DigestDoc),
    XForms =
        case Enveloped of
            true -> [#transform{algo = ?dsig_enveloped}];
            false -> []
        end ++
        [#transform{algo = ?dsig_XML_c14n_exc}],
    #{hash_preferences := [DigestAlgo | _]} = Opts,
    DigestMethURI = uri_from_hash_algo(DigestAlgo),
    Digest = crypto:hash(DigestAlgo, CanonMsg),
    DigestB64 = base64:encode(Digest),
    [#reference{uri = URI,
                xforms = XForms,
                digest_meth = DigestMethURI,
                digest = DigestB64}
     | generate_references(Doc, Rest, Opts)].

-define(namespaces, #{
    <<"ds">> => ?NS_dsig,
    <<"ec">> => ?dsig_XML_c14n_exc
    }).

-xpath_record({decode_xform, transform, #{
    algo => "/ds:Transform/@Algorithm",
    force_ns => "/ds:Transform/ec:InclusiveNamespaces/@PrefixList"
    }, ?namespaces}).

-xml_record({encode_xform, transform,
    "<Transform Algorithm='&algo;'>"
        "<mxsl:if defined='force_ns'>"
            "<ec:InclusiveNamespaces "
                "xmlns:ec='http://www.w3.org/2001/10/xml-exc-c14n#' "
                "PrefixList='&force_ns;'/>"
        "</mxsl:if>"
    "</Transform>", ?namespaces}).

-xpath_record({decode_ref, reference, #{
    uri => "/ds:Reference/@URI",
    xforms => "/ds:Reference/ds:Transforms/ds:Transform",
    digest_meth => "/ds:Reference/ds:DigestMethod/@Algorithm",
    digest => "/ds:Reference/ds:DigestValue"
    }, ?namespaces}).

-xml_record({encode_ref, reference,
    "<Reference xmlns='http://www.w3.org/2000/09/xmldsig#' URI='&uri;'>"
        "<Transforms>"
            "&xforms;"
        "</Transforms>"
        "<DigestMethod Algorithm='&digest_meth;'/>"
        "<DigestValue>&digest;</DigestValue>"
    "</Reference>", ?namespaces}).

-xpath_record({decode_keyvalue_rsa, keyvalue_rsa, #{
    modulus => "/ds:RSAKeyValue/ds:Modulus",
    exponent => "/ds:RSAKeyValue/ds:Exponent"
    }, ?namespaces}).
-xml_record({encode_keyvalue_rsa, keyvalue_rsa,
    "<RSAKeyValue xmlns='http://www.w3.org/2000/09/xmldsig#'>"
        "<Modulus>&modulus;</Modulus>"
        "<Exponent>&exponent;</Exponent>"
    "</RSAKeyValue>", ?namespaces}).


-xpath_record({decode_keyvalue_ec, keyvalue_ec, #{
    curve => "/ds:ECKeyValue/ds:NamedCurve/@URI",
    pubkey => "/ds:ECKeyValue/ds:PublicKey"
    }, ?namespaces}).
-xml_record({encode_keyvalue_ec, keyvalue_ec,
    "<ECKeyValue xmlns='http://www.w3.org/2000/09/xmldsig#'>"
        "<NamedCurve URI='&curve;'/>"
        "<PublicKey>&pubkey;</PublicKey>"
    "</ECKeyValue>", ?namespaces}).

-xpath_record({decode_keyinfo, keyinfo, #{
    name => "/ds:KeyInfo/ds:KeyName",
    certs => "/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
    key => "/ds:KeyInfo/ds:KeyValue/ds:*"
    }, ?namespaces}).

-xml_record({encode_keyinfo, keyinfo,
    "<KeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#'>"
        "<mxsl:if defined='name'>"
            "<KeyName>&name;</KeyName>"
        "</mxsl:if>"
        "<mxsl:for-each field='certs' as='cert'>"
            "<X509Data>"
                "<X509Certificate>"
                    "<mxsl:value-of field='cert'/>"
                "</X509Certificate>"
            "</X509Data>"
        "</mxsl:for-each>"
        "<mxsl:if defined='key'>"
            "<KeyValue>"
                "<mxsl:value-of field='key'/>"
            "</KeyValue>"
        "</mxsl:if>"
    "</KeyInfo>", ?namespaces}).

-xpath_record({decode_siginfo, signedinfo, #{
    c14n_meth => "/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm",
    sig_meth => "/ds:SignedInfo/ds:SignatureMethod/@Algorithm",
    refs => "/ds:SignedInfo/ds:Reference"
    }, ?namespaces}).
-xml_record({encode_siginfo, signedinfo,
    "<SignedInfo xmlns='http://www.w3.org/2000/09/xmldsig#'>"
        "<CanonicalizationMethod Algorithm='&c14n_meth;'/>"
        "<SignatureMethod Algorithm='&sig_meth;'/>"
        "&refs;"
    "</SignedInfo>"}).

-xpath_record({decode_sig, signature, #{
    id => "/ds:Signature/@ds:Id",
    info => "/ds:Signature/ds:SignedInfo",
    sig => "/ds:Signature/ds:SignatureValue",
    key => "/ds:Signature/ds:KeyInfo"
    }, ?namespaces}).

-xml_record({encode_sig, signature,
    "<Signature "
               "xmlns='http://www.w3.org/2000/09/xmldsig#' "
               "xmlns:ds='http://www.w3.org/2000/09/xmldsig#' "
               "Id='&id;'>"
        "&info;"
        "<SignatureValue>&sig;</SignatureValue>"
        "&key;"
    "</Signature>"}).

-xpath({extract_sig, "/*/ds:Signature", ?namespaces}).
-xpath({extract_siginfo, "/ds:Signature/ds:SignedInfo", ?namespaces}).
-xpath({strip_sig_kids, "/*/*[not(self::ds:Signature)]", ?namespaces}).

strip_sig(Doc) ->
    NewRootKids = strip_sig_kids(Doc),
    lists:map(fun
        (Root = #xml_element{content = _}) ->
            Root#xml_element{content = NewRootKids};
        (Other) ->
            Other
    end, Doc).



-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

verify_valid_sha1_key_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<Envelope xmlns=\"http://example.org/envelope\">\n"
        "  <Body>\n"
        "    Olá mundo\n"
        "  </Body>\n"
        "  <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"
        "    <SignedInfo>\n"
        "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />\n"
        "      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" />\n"
        "      <Reference URI=\"\">\n"
        "        <Transforms>\n"
        "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />\n"
        "        </Transforms>\n"
        "        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" />\n"
        "        <DigestValue>UWuYTYug10J1k5hKfonxthgrAR8=</DigestValue>\n"
        "      </Reference>\n"
        "    </SignedInfo>\n"
        "    <SignatureValue>\n"
        "      TSQUoVrQ0kg1eiltNwIhKPrIdsi1VhWjYNJlXvfQqW2EKk3X37X862SCfrz7v8IYJ7OorWwlFpGDStJDSR6saO\n"
        "      ScqSvmesCrGEEq+U6zegR9nH0lvcGZ8Rvc/y7U9kZrE4fHqEiLyfpmzJyPmWUT9Uta14nPJYsl3cmdThHB8Bs=\n"
        "    </SignatureValue>\n"
        "    <KeyInfo>\n"
        "      <KeyValue>\n"
        "         <RSAKeyValue>\n"
        "           <Modulus>\n"
        "             4IlzOY3Y9fXoh3Y5f06wBbtTg94Pt6vcfcd1KQ0FLm0S36aGJtTSb6pYKfyX7PqCUQ8wgL6xUJ5GRPEsu9gyz8\n"
        "             ZobwfZsGCsvu40CWoT9fcFBZPfXro1Vtlh/xl/yYHm+Gzqh0Bw76xtLHSfLfpVOrmZdwKmSFKMTvNXOFd0V18=\n"
        "           </Modulus>\n"
        "           <Exponent>AQAB</Exponent>\n"
        "         </RSAKeyValue>\n"
        "      </KeyValue>\n"
        "    </KeyInfo>\n"
        "  </Signature>\n"
        "</Envelope>\n"/utf8>>),
    ?assertMatch({ok, _}, verify(Doc, #{
        verifier_options => #{
            danger_trust_any_key => true
            }
        })).

verify_valid_sha256_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<Envelope xmlns=\"http://example.org/envelope\">\n"
        "  <Body>\n"
        "    Olá mundo\n"
        "  </Body>\n"
        "  <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"
        "    <SignedInfo>\n"
        "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />\n"
        "      <SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" />\n"
        "      <Reference URI=\"\">\n"
        "        <Transforms>\n"
        "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />\n"
        "        </Transforms>\n"
        "        <DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" />\n"
        "        <DigestValue>XmEzFTF6w33nhHfeQqIZKwITz3H2mbBvShxWn+ML/7s=</DigestValue>\n"
        "      </Reference>\n"
        "    </SignedInfo>\n"
        "    <SignatureValue>C/NE8YqqNcySFxRazwbxZSUsoAoeqgbEDiVn+yg1zZY1Evb7VMV1MdoDJM39f7L26e9H//br6sjHZn7s+LGCJp9F2ZmCgiJxSOxqy2yCt6perxoKF3MDQmDRnMtglKeWNSBfYZRWEcA64PMMHz5WS5DCIVTcgU7lFzgMpUfYLOs=</SignatureValue>\n"
        "    <KeyInfo>\n"
        "      <KeyValue><RSAKeyValue><Modulus>4IlzOY3Y9fXoh3Y5f06wBbtTg94Pt6vcfcd1KQ0FLm0S36aGJtTSb6pYKfyX7PqCUQ8wgL6xUJ5GRPEsu9gyz8ZobwfZsGCsvu40CWoT9fcFBZPfXro1Vtlh/xl/yYHm+Gzqh0Bw76xtLHSfLfpVOrmZdwKmSFKMTvNXOFd0V18=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue>\n"
        "    </KeyInfo>\n"
        "  </Signature>\n"
        "</Envelope>\n"/utf8>>),
    ?assertMatch({ok, _}, verify(Doc, #{
        verifier_options => #{
            danger_trust_any_key => true
            }
        })).

verify_valid_sha256_ssh_fp_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<Envelope xmlns=\"http://example.org/envelope\">\n"
        "  <Body>\n"
        "    Olá mundo\n"
        "  </Body>\n"
        "  <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"
        "    <SignedInfo>\n"
        "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />\n"
        "      <SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" />\n"
        "      <Reference URI=\"\">\n"
        "        <Transforms>\n"
        "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />\n"
        "        </Transforms>\n"
        "        <DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" />\n"
        "        <DigestValue>XmEzFTF6w33nhHfeQqIZKwITz3H2mbBvShxWn+ML/7s=</DigestValue>\n"
        "      </Reference>\n"
        "    </SignedInfo>\n"
        "    <SignatureValue>C/NE8YqqNcySFxRazwbxZSUsoAoeqgbEDiVn+yg1zZY1Evb7VMV1MdoDJM39f7L26e9H//br6sjHZn7s+LGCJp9F2ZmCgiJxSOxqy2yCt6perxoKF3MDQmDRnMtglKeWNSBfYZRWEcA64PMMHz5WS5DCIVTcgU7lFzgMpUfYLOs=</SignatureValue>\n"
        "    <KeyInfo>\n"
        "      <KeyValue><RSAKeyValue><Modulus>4IlzOY3Y9fXoh3Y5f06wBbtTg94Pt6vcfcd1KQ0FLm0S36aGJtTSb6pYKfyX7PqCUQ8wgL6xUJ5GRPEsu9gyz8ZobwfZsGCsvu40CWoT9fcFBZPfXro1Vtlh/xl/yYHm+Gzqh0Bw76xtLHSfLfpVOrmZdwKmSFKMTvNXOFd0V18=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue>\n"
        "    </KeyInfo>\n"
        "  </Signature>\n"
        "</Envelope>\n"/utf8>>),
    ?assertMatch({ok, _}, verify(Doc, #{
        verifier_options => #{
            fingerprints => [
                {ssh, sha256, base64:decode(<<"bRnkjhD610D4zSpRu/jV3Wfi4tYZ0r2eO82GbDBwW5Y=">>)}]
            }
        })).


verify_valid_sha256_spki_fp_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<Envelope xmlns=\"http://example.org/envelope\">\n"
        "  <Body>\n"
        "    Olá mundo\n"
        "  </Body>\n"
        "  <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"
        "    <SignedInfo>\n"
        "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />\n"
        "      <SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" />\n"
        "      <Reference URI=\"\">\n"
        "        <Transforms>\n"
        "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />\n"
        "        </Transforms>\n"
        "        <DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" />\n"
        "        <DigestValue>XmEzFTF6w33nhHfeQqIZKwITz3H2mbBvShxWn+ML/7s=</DigestValue>\n"
        "      </Reference>\n"
        "    </SignedInfo>\n"
        "    <SignatureValue>C/NE8YqqNcySFxRazwbxZSUsoAoeqgbEDiVn+yg1zZY1Evb7VMV1MdoDJM39f7L26e9H//br6sjHZn7s+LGCJp9F2ZmCgiJxSOxqy2yCt6perxoKF3MDQmDRnMtglKeWNSBfYZRWEcA64PMMHz5WS5DCIVTcgU7lFzgMpUfYLOs=</SignatureValue>\n"
        "    <KeyInfo>\n"
        "      <KeyValue><RSAKeyValue><Modulus>4IlzOY3Y9fXoh3Y5f06wBbtTg94Pt6vcfcd1KQ0FLm0S36aGJtTSb6pYKfyX7PqCUQ8wgL6xUJ5GRPEsu9gyz8ZobwfZsGCsvu40CWoT9fcFBZPfXro1Vtlh/xl/yYHm+Gzqh0Bw76xtLHSfLfpVOrmZdwKmSFKMTvNXOFd0V18=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue>\n"
        "    </KeyInfo>\n"
        "  </Signature>\n"
        "</Envelope>\n"/utf8>>),
    ?assertMatch({ok, _}, verify(Doc, #{
        verifier_options => #{
            fingerprints => [
                {spki, sha256, binary:decode_hex(<<"1cfc3d1a7b49c9ebd22cd091ec060397b53a489845ed5bdb976ee638b50ca1b3">>)}]
            }
        })).

verify_valid_sha1_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\"?>"
        "<x:foo ID=\"9616e6c0-f525-11b7-afb7-5cf9dd711ed3\" "
               "xmlns:x=\"urn:foo:x:\">"
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                "<ds:SignedInfo>"
                    "<ds:CanonicalizationMethod "
                        "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                    "<ds:SignatureMethod "
                        "Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>"
                    "<ds:Reference URI=\"#9616e6c0-f525-11b7-afb7-5cf9dd711ed3\">"
                        "<ds:Transforms>"
                            "<ds:Transform "
                                "Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
                            "<ds:Transform "
                                "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                        "</ds:Transforms>"
                        "<ds:DigestMethod "
                            "Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
                        "<ds:DigestValue>xPVYXCs5uMMmIbfTiTZ5R5DVhTU=</ds:DigestValue>"
                    "</ds:Reference>"
                "</ds:SignedInfo>"
                "<ds:SignatureValue>rYk+WAghakHfR9VtpLz3AkMD1xLD1wISfNgch9+i+PC72RqhmfeMCZMkBaw0EO+CTKEoFBQIQaJYlEj8rIG+XN+8HyBV75BrMKZs1rdN+459Rpn2FOOJuHVb2jLDPecC9Ok/DGaNu6lol60hG9di66EZkL8ErQCuCeZqiw9tiXMUPQyVa2GxqT2UeXvJ5YtkNMDweUc3HhEnTG3ovYt1vOZt679w4N0HAwUa9rk40Z12fOTx77BbMICZ9Q4N2m3UbaFU24YHYpHR+WUTiwzXcmdkrHiE5IF37h7rTKAEixD2bTojaefmrobAz0+mBhCqBPcbfNLhLrpT43xhMenjpA==</ds:SignatureValue>"
                "<ds:KeyInfo>"
                    "<ds:X509Data>"
                        "<ds:X509Certificate>MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ</ds:X509Certificate>"
                    "</ds:X509Data>"
                "</ds:KeyInfo>"
            "</ds:Signature>"
            "<x:name>blah</x:name>"
        "</x:foo>">>),
    ?assertMatch({ok, _}, verify(Doc, #{
        verifier_options => #{
            danger_trust_any_cert => true
            }
        })).

verify_valid_sha1_spki_fp_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\"?>"
        "<x:foo ID=\"9616e6c0-f525-11b7-afb7-5cf9dd711ed3\" "
               "xmlns:x=\"urn:foo:x:\">"
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                "<ds:SignedInfo>"
                    "<ds:CanonicalizationMethod "
                        "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                    "<ds:SignatureMethod "
                        "Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>"
                    "<ds:Reference URI=\"#9616e6c0-f525-11b7-afb7-5cf9dd711ed3\">"
                        "<ds:Transforms>"
                            "<ds:Transform "
                                "Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
                            "<ds:Transform "
                                "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                        "</ds:Transforms>"
                        "<ds:DigestMethod "
                            "Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
                        "<ds:DigestValue>xPVYXCs5uMMmIbfTiTZ5R5DVhTU=</ds:DigestValue>"
                    "</ds:Reference>"
                "</ds:SignedInfo>"
                "<ds:SignatureValue>rYk+WAghakHfR9VtpLz3AkMD1xLD1wISfNgch9+i+PC72RqhmfeMCZMkBaw0EO+CTKEoFBQIQaJYlEj8rIG+XN+8HyBV75BrMKZs1rdN+459Rpn2FOOJuHVb2jLDPecC9Ok/DGaNu6lol60hG9di66EZkL8ErQCuCeZqiw9tiXMUPQyVa2GxqT2UeXvJ5YtkNMDweUc3HhEnTG3ovYt1vOZt679w4N0HAwUa9rk40Z12fOTx77BbMICZ9Q4N2m3UbaFU24YHYpHR+WUTiwzXcmdkrHiE5IF37h7rTKAEixD2bTojaefmrobAz0+mBhCqBPcbfNLhLrpT43xhMenjpA==</ds:SignatureValue>"
                "<ds:KeyInfo>"
                    "<ds:X509Data>"
                        "<ds:X509Certificate>MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ</ds:X509Certificate>"
                    "</ds:X509Data>"
                "</ds:KeyInfo>"
            "</ds:Signature>"
            "<x:name>blah</x:name>"
        "</x:foo>">>),
    ?assertMatch({ok, _}, verify(Doc, #{
        verifier_options => #{
            fingerprints => [{spki, sha512, base64:decode(<<"zl1Hj2NNr68sGkFHsTPNCPc/P6afxuvZl7NXqECqwLrXgzX7fDuvUhVCLqtzq4NQ3w95QdARO+wwKDOywleWiQ==">>)}]
            }
        })).

verify_valid_sha1_x509_fp_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\"?>"
        "<x:foo ID=\"9616e6c0-f525-11b7-afb7-5cf9dd711ed3\" "
               "xmlns:x=\"urn:foo:x:\">"
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                "<ds:SignedInfo>"
                    "<ds:CanonicalizationMethod "
                        "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                    "<ds:SignatureMethod "
                        "Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>"
                    "<ds:Reference URI=\"#9616e6c0-f525-11b7-afb7-5cf9dd711ed3\">"
                        "<ds:Transforms>"
                            "<ds:Transform "
                                "Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
                            "<ds:Transform "
                                "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                        "</ds:Transforms>"
                        "<ds:DigestMethod "
                            "Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
                        "<ds:DigestValue>xPVYXCs5uMMmIbfTiTZ5R5DVhTU=</ds:DigestValue>"
                    "</ds:Reference>"
                "</ds:SignedInfo>"
                "<ds:SignatureValue>rYk+WAghakHfR9VtpLz3AkMD1xLD1wISfNgch9+i+PC72RqhmfeMCZMkBaw0EO+CTKEoFBQIQaJYlEj8rIG+XN+8HyBV75BrMKZs1rdN+459Rpn2FOOJuHVb2jLDPecC9Ok/DGaNu6lol60hG9di66EZkL8ErQCuCeZqiw9tiXMUPQyVa2GxqT2UeXvJ5YtkNMDweUc3HhEnTG3ovYt1vOZt679w4N0HAwUa9rk40Z12fOTx77BbMICZ9Q4N2m3UbaFU24YHYpHR+WUTiwzXcmdkrHiE5IF37h7rTKAEixD2bTojaefmrobAz0+mBhCqBPcbfNLhLrpT43xhMenjpA==</ds:SignatureValue>"
                "<ds:KeyInfo>"
                    "<ds:X509Data>"
                        "<ds:X509Certificate>MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ</ds:X509Certificate>"
                    "</ds:X509Data>"
                "</ds:KeyInfo>"
            "</ds:Signature>"
            "<x:name>blah</x:name>"
        "</x:foo>">>),
    ?assertMatch({ok, _}, verify(Doc, #{
        verifier_options => #{
            fingerprints => [{x509, sha, base64:decode(<<"xlYKtnfxFAPGWCMqkUz7cTQV9pw=">>)}]
            }
        })).

verify_valid_sha1_x509_ca_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\"?>"
        "<x:foo ID=\"9616e6c0-f525-11b7-afb7-5cf9dd711ed3\" "
               "xmlns:x=\"urn:foo:x:\">"
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                "<ds:SignedInfo>"
                    "<ds:CanonicalizationMethod "
                        "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                    "<ds:SignatureMethod "
                        "Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>"
                    "<ds:Reference URI=\"#9616e6c0-f525-11b7-afb7-5cf9dd711ed3\">"
                        "<ds:Transforms>"
                            "<ds:Transform "
                                "Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
                            "<ds:Transform "
                                "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                        "</ds:Transforms>"
                        "<ds:DigestMethod "
                            "Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
                        "<ds:DigestValue>xPVYXCs5uMMmIbfTiTZ5R5DVhTU=</ds:DigestValue>"
                    "</ds:Reference>"
                "</ds:SignedInfo>"
                "<ds:SignatureValue>rYk+WAghakHfR9VtpLz3AkMD1xLD1wISfNgch9+i+PC72RqhmfeMCZMkBaw0EO+CTKEoFBQIQaJYlEj8rIG+XN+8HyBV75BrMKZs1rdN+459Rpn2FOOJuHVb2jLDPecC9Ok/DGaNu6lol60hG9di66EZkL8ErQCuCeZqiw9tiXMUPQyVa2GxqT2UeXvJ5YtkNMDweUc3HhEnTG3ovYt1vOZt679w4N0HAwUa9rk40Z12fOTx77BbMICZ9Q4N2m3UbaFU24YHYpHR+WUTiwzXcmdkrHiE5IF37h7rTKAEixD2bTojaefmrobAz0+mBhCqBPcbfNLhLrpT43xhMenjpA==</ds:SignatureValue>"
                "<ds:KeyInfo>"
                    "<ds:X509Data>"
                        "<ds:X509Certificate>MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ</ds:X509Certificate>"
                    "</ds:X509Data>"
                "</ds:KeyInfo>"
            "</ds:Signature>"
            "<x:name>blah</x:name>"
        "</x:foo>">>),
    Der = base64:decode(<<"MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ">>),
    Cert = public_key:pkix_decode_cert(Der, otp),
    ?assertMatch({ok, _}, verify(Doc, #{
        verifier_options => #{
            ca_certs => [Cert],
            ignore_expired_certs => true
            }
        })).

verify_valid_sha1_no_fp_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\"?>"
        "<x:foo ID=\"9616e6c0-f525-11b7-afb7-5cf9dd711ed3\" "
               "xmlns:x=\"urn:foo:x:\">"
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                "<ds:SignedInfo>"
                    "<ds:CanonicalizationMethod "
                        "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                    "<ds:SignatureMethod "
                        "Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>"
                    "<ds:Reference URI=\"#9616e6c0-f525-11b7-afb7-5cf9dd711ed3\">"
                        "<ds:Transforms>"
                            "<ds:Transform "
                                "Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
                            "<ds:Transform "
                                "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                        "</ds:Transforms>"
                        "<ds:DigestMethod "
                            "Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
                        "<ds:DigestValue>xPVYXCs5uMMmIbfTiTZ5R5DVhTU=</ds:DigestValue>"
                    "</ds:Reference>"
                "</ds:SignedInfo>"
                "<ds:SignatureValue>rYk+WAghakHfR9VtpLz3AkMD1xLD1wISfNgch9+i+PC72RqhmfeMCZMkBaw0EO+CTKEoFBQIQaJYlEj8rIG+XN+8HyBV75BrMKZs1rdN+459Rpn2FOOJuHVb2jLDPecC9Ok/DGaNu6lol60hG9di66EZkL8ErQCuCeZqiw9tiXMUPQyVa2GxqT2UeXvJ5YtkNMDweUc3HhEnTG3ovYt1vOZt679w4N0HAwUa9rk40Z12fOTx77BbMICZ9Q4N2m3UbaFU24YHYpHR+WUTiwzXcmdkrHiE5IF37h7rTKAEixD2bTojaefmrobAz0+mBhCqBPcbfNLhLrpT43xhMenjpA==</ds:SignatureValue>"
                "<ds:KeyInfo>"
                    "<ds:X509Data>"
                        "<ds:X509Certificate>MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ</ds:X509Certificate>"
                    "</ds:X509Data>"
                "</ds:KeyInfo>"
            "</ds:Signature>"
            "<x:name>blah</x:name>"
        "</x:foo>">>),
    ?assertMatch({error, _}, verify(Doc, #{
        verifier_options => #{
            fingerprints => [{spki, sha256, <<>>}]
            }
        })).

parse_key_rsa_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<KeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#'>\n"
        "<KeyValue><RSAKeyValue>\n"
        "<Modulus>\n"
        "4IlzOY3Y9fXoh3Y5f06wBbtTg94Pt6vcfcd1KQ0FLm0S36aGJtTSb6pYKfyX7PqCUQ8wgL6xUJ5GRPEsu9gyz8\n"
        "ZobwfZsGCsvu40CWoT9fcFBZPfXro1Vtlh/xl/yYHm+Gzqh0Bw76xtLHSfLfpVOrmZdwKmSFKMTvNXOFd0V18=\n"
        "</Modulus>\n"
        "<Exponent>AQAB</Exponent>\n"
        "</RSAKeyValue></KeyValue>\n"
        "</KeyInfo>\n">>),
    R = parse_key(Doc),
    ?assertMatch({ok, _}, R),
    {ok, KD} = R,
    ?assertMatch(#{public_key := #'RSAPublicKey'{}}, KD).

parse_key_ec_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<KeyInfo xmlns='http://www.w3.org/2000/09/xmldsig#'>\n"
        "<KeyName>some key</KeyName>\n"
        "<KeyValue><ECKeyValue>\n"
        "<PublicKey>\n"
        "j5sLNXdJgD7ye531XlyUb2exL8I=\n"
        "</PublicKey>\n"
        "<NamedCurve URI='urn:oid:1.2.840.10045.3.1.7' />\n"
        "</ECKeyValue></KeyValue>\n"
        "</KeyInfo>\n">>),
    R = parse_key(Doc),
    ?assertMatch({ok, _}, R),
    {ok, KD} = R,
    ?assertMatch(#{name := <<"some key">>,
                   public_key := {#'ECPoint'{}, {namedCurve, secp256r1}}}, KD).

parse_key_cert_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>"
            "<ds:X509Data>"
                "<ds:X509Certificate>MIIDfTCCAmWgAwIBAgIJANCSQXrTqpDjMA0GCSqGSIb3DQEBBQUAMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApRdWVlbnNsYW5kMREwDwYDVQQHDAhCcmlzYmFuZTEMMAoGA1UECgwDRm9vMRAwDgYDVQQDDAdzYW1saWRwMB4XDTEzMDQyOTA2MTAyOVoXDTIzMDQyOTA2MTAyOVowVTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClF1ZWVuc2xhbmQxETAPBgNVBAcMCEJyaXNiYW5lMQwwCgYDVQQKDANGb28xEDAOBgNVBAMMB3NhbWxpZHAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFhBuEO3fX+FlyT2YYzozxmXNXEmQjksigJSKD4hvsgsyGyl1iLkqNT6IbkuMXoyJG6vXufMNVLoktcLBd6eu6LQwwRjSU62AVCWZhIJP8U6lHqVsxiP90h7/b1zM7Hm9uM9RHtG+nKB7W0xNRihG8BUQOocSaLIMZZXqDPW1h/UvUqmpEzCtT0kJyXX0UAmDHzTYWHt8dqOYdcO2RAlJX0UKnwG1bHjTAfw01lJeOZiF66kH777nStYSElrHXr0NmCO/2gt6ouEnnUqJWDWRzaLbzhMLmGj83lmPgwZCBbIbnbQWLYPQ438EWfEYELq9nSQrgfUmmDPb4rtsQOXqZAgMBAAGjUDBOMB0GA1UdDgQWBBT64y2JSqY96YTYv1QbFyCPp3To/zAfBgNVHSMEGDAWgBT64y2JSqY96YTYv1QbFyCPp3To/zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAecr+C4w3LYAU4pCbLAW2BbFWGZRqBAr6ZKZKQrrqSMUJUiRDoKc5FYJrkjl/sGHAe3b5vBrU3lb/hpSiKXVf4/zBP7uqAF75B6LwnMwYpPcXlnRyPngQcdTL5EyQT5vwqv+H3zB64TblMYbsvqm6+1ippRNq4IXQX+3NGTEkhh0xgH+e3wE8BjjiygDu0MqopaIVPemMVQIm3HI+4jmf60bz8GLD1J4dj5CvyW1jQCXu2K2fcS1xJS0FLrxh/QxR0+3prGkYiZeOWE/dHlTTvQLB+NftyamUthVxMFe8dvXMTix/egox+ps2NuO2XTkDaeeRFjUhPhS8SvZO9l0lZ</ds:X509Certificate>"
            "</ds:X509Data>"
        "</ds:KeyInfo>">>),
    R = parse_key(Doc),
    ?assertMatch({ok, _}, R),
    {ok, KD} = R,
    ?assertMatch(#{public_key := #'RSAPublicKey'{},
                   certificate := #'OTPCertificate'{}}, KD),
    {ok, Doc2} = generate_key(KD),
    ?assertMatch({ok, KD}, parse_key(Doc2)).

verify_valid_complicated_test() ->
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
        "<SignedInfo>\n"
        "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />\n"
        "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" />\n"
        "<Reference URI=\"\">\n"
        "<Transforms>\n"
        "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />\n"
        "<Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />\n"
        "</Transforms>\n"
        "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" />\n"
        "<DigestValue>d6Pzi4DPNG6uc9KqTxdnm1zdLSA=</DigestValue>\n"
        "</Reference>\n"
        "<Reference URI=\"#foo\">\n"
        "<Transforms>\n"
        "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />\n"
        "<Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />\n"
        "</Transforms>\n"
        "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" />\n"
        "<DigestValue>j5sLNXdJgD7ye531XlyUb2exL8I=</DigestValue>\n"
        "</Reference>\n"
        "<Reference URI=\"#bar\">\n"
        "<Transforms>\n"
        "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />\n"
        "<Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />\n"
        "</Transforms>\n"
        "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" />\n"
        "<DigestValue>yn5TDgwmUdYwr7PtVYsz2XuwUww=</DigestValue>\n"
        "</Reference>\n"
        "</SignedInfo>\n"
        "<SignatureValue>ErZz53i1O2IjsFg2RJKugaEYkwv8jAcjyu484bViJczBchVCwsKGCGQ830YCkHxDIGIWWcaiMYGUFmkndy9iTRUi4csn3TIpQTzQd/3tIUWQ8xiZRytriL5cMLWtjnhFRp7tuB28/h6DkjWKm5c0m7mlBhDOZVEk6Wu5PjhwD8E=</SignatureValue>\n"
        "<KeyInfo>\n"
        "<KeyValue><RSAKeyValue>\n"
        "<Modulus>\n"
        "4IlzOY3Y9fXoh3Y5f06wBbtTg94Pt6vcfcd1KQ0FLm0S36aGJtTSb6pYKfyX7PqCUQ8wgL6xUJ5GRPEsu9gyz8\n"
        "ZobwfZsGCsvu40CWoT9fcFBZPfXro1Vtlh/xl/yYHm+Gzqh0Bw76xtLHSfLfpVOrmZdwKmSFKMTvNXOFd0V18=\n"
        "</Modulus>\n"
        "<Exponent>AQAB</Exponent>\n"
        "</RSAKeyValue></KeyValue>\n"
        "</KeyInfo>\n"
        "</Signature>\n"
        "</doc>\n">>),
    ?assertMatch({ok, _}, verify(Doc, #{
        verifier_options => #{
            danger_trust_any_key => true
            }
        })).

verify_invalid_sha256_test() ->
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<Envelope xmlns=\"http://example.org/envelope\">\n"
        "  <Body>\n"
        "    Ola mundo\n"
        "  </Body>\n"
        "  <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"
        "    <SignedInfo>\n"
        "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" />\n"
        "      <SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" />\n"
        "      <Reference URI=\"\">\n"
        "        <Transforms>\n"
        "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />\n"
        "        </Transforms>\n"
        "        <DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" />\n"
        "        <DigestValue>XmEzFTF6w33nhHfeQqIZKwITz3H2mbBvShxWn+ML/7s=</DigestValue>\n"
        "      </Reference>\n"
        "    </SignedInfo>\n"
        "    <SignatureValue>C/NE8YqqNcySFxRazwbxZSUsoAoeqgbEDiVn+yg1zZY1Evb7VMV1MdoDJM39f7L26e9H//br6sjHZn7s+LGCJp9F2ZmCgiJxSOxqy2yCt6perxoKF3MDQmDRnMtglKeWNSBfYZRWEcA64PMMHz5WS5DCIVTcgU7lFzgMpUfYLOs=</SignatureValue>\n"
        "    <KeyInfo>\n"
        "      <KeyValue><RSAKeyValue><Modulus>4IlzOY3Y9fXoh3Y5f06wBbtTg94Pt6vcfcd1KQ0FLm0S36aGJtTSb6pYKfyX7PqCUQ8wgL6xUJ5GRPEsu9gyz8ZobwfZsGCsvu40CWoT9fcFBZPfXro1Vtlh/xl/yYHm+Gzqh0Bw76xtLHSfLfpVOrmZdwKmSFKMTvNXOFd0V18=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue>\n"
        "    </KeyInfo>\n"
        "  </Signature>\n"
        "</Envelope>\n"/utf8>>),
    ?assertMatch({error, invalid_digest}, verify(Doc, #{
        verifier_options => #{
            danger_trust_any_key => true
            }
        })).

end_to_end_test() ->
    Key = public_key:generate_key({rsa, 2048, 16#10001}),
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version='1.0'?>\n"
        "<doc xmlns='urn:doc:' xmlns:foo='urn:foo:'>\n"
        "  <foo>123</foo>\n",
        "  <bar id='bar'>\n\n"
        "    <foo:baz>abc123</foo:baz>\n"
        "  </bar>\n"
        "</doc>">>),
    [Root] = [E || E = #xml_element{} <- Doc],
    Res = xmlrat_dsig:sign(Doc, #{
        signer_options => #{private_key => Key}}),
    ?assertMatch({ok, _}, Res),
    {ok, SigDoc} = Res,
    ?assertMatch([#xml_element{tag = {_, <<"Signature">>, _}}],
        extract_sig(SigDoc)),
    VRes = verify(SigDoc, #{
        verifier_options => #{danger_trust_any_key => true}}),
    ?assertMatch({ok, [Root]}, VRes),
    SigDoc2 = lists:map(fun
        (E = #xml_element{attributes = A0}) ->
            A1 = A0 ++ [#xml_attribute{name = <<"test">>,
                                       value = <<"aaaa">>}],
            E#xml_element{attributes = A1};
        (Other) -> Other
    end, SigDoc),
    VRes2 = verify(SigDoc2, #{
        verifier_options => #{danger_trust_any_key => true}}),
    ?assertMatch({error, invalid_digest}, VRes2).

partial_end_to_end_test() ->
    Key = public_key:generate_key({rsa, 2048, 16#10001}),
    {ok, Doc} = xmlrat_parse:string(<<
        "<?xml version='1.0'?>\n"
        "<doc xmlns='urn:doc:' xmlns:foo='urn:foo:'>\n"
        "  <foo>123</foo>\n",
        "  <bar id='bar'>\n\n"
        "    <foo:baz>abc123</foo:baz>\n"
        "  </bar>\n"
        "</doc>">>),
    {ok, [Bar]} = xmlrat_xpath:run("/doc/bar", Doc),
    Res = xmlrat_dsig:sign(Doc, #{
        signer_options => #{private_key => Key},
        signed_elements => [<<"bar">>]
        }),
    ?assertMatch({ok, _}, Res),
    {ok, SigDoc} = Res,
    ?assertMatch([#xml_element{tag = {_, <<"Signature">>, _}}],
        extract_sig(SigDoc)),
    VRes = verify(SigDoc, #{
        verifier_options => #{danger_trust_any_key => true}}),
    Root = #xml_element{tag = {default, <<"doc">>, <<"urn:doc:doc">>},
                        content = [Bar]},
    ?assertMatch({ok, [Root]}, VRes),
    SigDoc2 = lists:map(fun
        (E = #xml_element{attributes = A0}) ->
            A1 = A0 ++ [#xml_attribute{name = <<"test">>,
                                       value = <<"aaaa">>}],
            E#xml_element{attributes = A1};
        (Other) -> Other
    end, SigDoc),
    VRes2 = verify(SigDoc2, #{
        verifier_options => #{danger_trust_any_key => true}}),
    ?assertMatch({ok, [Root]}, VRes2).

saml_test() ->
    {ok, Doc} = xmlrat_parse:string(base64:decode(<<"PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIERlc3RpbmF0aW9uPSJodHRwczovL3hsZXgtcmF0c2FtbC51cWNsb3VkLm5ldC9zYW1sL2NvbnN1bWUiIElEPSJJRF8wNTdmNTIyMS0wZGU5LTQ0NjUtODdjZS01YjZiYWNlMjYxMTAiIEluUmVzcG9uc2VUbz0icmF0c2FtbC0zRkIzMTBBQUQxNzAxQzQxNDZBODg1NjlDQ0UyQzVEMSIgSXNzdWVJbnN0YW50PSIyMDI1LTA0LTE3VDAzOjQzOjQ0LjA2MFoiIFZlcnNpb249IjIuMCI+PHNhbWw6SXNzdWVyPmh0dHBzOi8veGxleC1rZXljbG9hay51cWNsb3VkLm5ldC9yZWFsbXMvbWFzdGVyPC9zYW1sOklzc3Vlcj48ZHNpZzpTaWduYXR1cmUgeG1sbnM6ZHNpZz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzaWc6U2lnbmVkSW5mbz48ZHNpZzpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzaWc6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxkc2lnOlJlZmVyZW5jZSBVUkk9IiNJRF8wNTdmNTIyMS0wZGU5LTQ0NjUtODdjZS01YjZiYWNlMjYxMTAiPjxkc2lnOlRyYW5zZm9ybXM+PGRzaWc6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHNpZzpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzaWc6VHJhbnNmb3Jtcz48ZHNpZzpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48ZHNpZzpEaWdlc3RWYWx1ZT5YZVZ1c0w4Z0lSenlneGZrVTkzMy9rdXVpNXhna0JxZWVqS0lRNXFKVzRNPTwvZHNpZzpEaWdlc3RWYWx1ZT48L2RzaWc6UmVmZXJlbmNlPjwvZHNpZzpTaWduZWRJbmZvPjxkc2lnOlNpZ25hdHVyZVZhbHVlPktPaWVCSU5Teko2L0tUOGtybnU2SGttWGtaR3pFditWTHQvOGgrNDV6bStaVGQ4MnVWWjJlZjI0MnFvdE9pYnNvYmJzQlJCVkNWQWRZVVJBaFZQMm9LOE1MQXNkREs3M01MaHE0bnEwVnBHYy9EeFdJdUR6QXY1SjYyVWY2Q0tTSGhiZTlaTkp4K1NGbUU5M0tzTloyMkw5QXBxRTNuRUVvdWg3YStIZVU4RDVDNEE3RzZTbnBGM0pPdkU4dXpyVzZCd05JZWhuMURKT3pUNVhabVA1TXRSVVJKbzhVUTdMRHZWM1QrOXAwSDhFRmdnSWpzcFpxQ1Y1aVJLdnlLRVBDZlU5NXFEVVd4NG1aWVN6MFlWSTZnQzBBanR3b1ViNDlKMnZuZTNLWkhDeXRZR0lZeTNGT2d5cG12SDVvTFpxVkF3SDQ3Y0IyTzAvVmpHNVRmT0VCdz09PC9kc2lnOlNpZ25hdHVyZVZhbHVlPjxkc2lnOktleUluZm8+PGRzaWc6S2V5TmFtZT5DTj1tYXN0ZXI8L2RzaWc6S2V5TmFtZT48ZHNpZzpYNTA5RGF0YT48ZHNpZzpYNTA5Q2VydGlmaWNhdGU+TUlJQ216Q0NBWU1DQmdHVnAxSkVCakFOQmdrcWhraUc5dzBCQVFzRkFEQVJNUTh3RFFZRFZRUUREQVp0WVhOMFpYSXdIaGNOTWpVd016RTRNRE16TkRBeFdoY05NelV3TXpFNE1ETXpOVFF4V2pBUk1ROHdEUVlEVlFRRERBWnRZWE4wWlhJd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUM3Q21uM1dtUGZaNGRobUJwQXhoZVhuV3l6eTBFNE44LzUyakRUU0cvOGRUVERGcHIxLzJnQU14MnpXM2ExdHpjUWlXcHlwVk1tQkxvYWFIRUNoUnRYL2ZuUmtnSThWdlZwUzdBZFBtL2IzaE5MeHpkTnZ1Vis3cGttVDZQcXBvWWw4bktjYk5nSk1GSzlRK3NGSHQ1L3VlMEZ1djZLNnovcGUrWVV5LzF2VzdtQW9WREdOR0o1aWRhZGs5bGJzU081am5iNEFqcVhsMmRWem16TTVqZzgydjRCeXloclZrby83K1ZzdGhZK1RqejVFS3FWOHlLN1IxK2h5YlQxTGdZR3JEWVZvZ1BjekdPd3dZN3ZDd1MxK3V2aTRsYk5zUCtXQmFaV200UVhHbXBLcm41cXNHQURxUktrZEo2UlRXRUo3QzhrT2VWWHdBVnJoMFBCMTZsOUFnTUJBQUV3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUl5VE9WV0NRUm9EWEJYeHVma2lnYitXNnl4K2FUcEFMcEZmMkh0Qmhod01rK0dZOUNIdlo2ZGVGUUJ0ekN0ZjJ3OTNuRjV0OFQxR1d3bG5FUE9DS2ZWUEdqK2FWM1hnWlNKQlRQdXNlQ1d5NDF4ZXVpVTl2ZFdnLzVwRCtiVkpFYmNScmV1TCt4ekJUTUlPanNEUVRucHhYOTdZMWc2b21maUVkandFYldZWUdVaysvQ3dPaWRCM1QrWVRQV0VVazdSYXlMUi9aM1MxV3JwK1IxZUt5eElJZS9LNklDbk81MUoyMEZWWUNyRko3Ym9HMmFmVEpjRUpSbFA3UUQ5ZXhzOVloWXJ0N2pmMjdzQ3NwY2NqbllRN2pWQ2pGcDdoNTlsaHAwM1FwYk4zU0F3VytDMEhPR0JWVVp3VnlqUk4zaC9JVzYyQUxJOVU3UWZIWWVYNlUyND08L2RzaWc6WDUwOUNlcnRpZmljYXRlPjwvZHNpZzpYNTA5RGF0YT48L2RzaWc6S2V5SW5mbz48L2RzaWc6U2lnbmF0dXJlPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxzYW1sOkFzc2VydGlvbiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9IklEX2FhZGVlZWM5LWZlZWItNDE3ZS1hYTAwLTliODlhODcwZmVhNiIgSXNzdWVJbnN0YW50PSIyMDI1LTA0LTE3VDAzOjQzOjQ0LjA2MFoiIFZlcnNpb249IjIuMCI+PHNhbWw6SXNzdWVyPmh0dHBzOi8veGxleC1rZXljbG9hay51cWNsb3VkLm5ldC9yZWFsbXMvbWFzdGVyPC9zYW1sOklzc3Vlcj48c2FtbDpTdWJqZWN0PjxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OnVuc3BlY2lmaWVkIj5hZG1pbjwvc2FtbDpOYW1lSUQ+PHNhbWw6U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0icmF0c2FtbC0zRkIzMTBBQUQxNzAxQzQxNDZBODg1NjlDQ0UyQzVEMSIgTm90T25PckFmdGVyPSIyMDI1LTA0LTE3VDAzOjQ0OjQyLjA2MFoiIFJlY2lwaWVudD0iaHR0cHM6Ly94bGV4LXJhdHNhbWwudXFjbG91ZC5uZXQvc2FtbC9jb25zdW1lIi8+PC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sOlN1YmplY3Q+PHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMjUtMDQtMTdUMDM6NDM6NDIuMDYwWiIgTm90T25PckFmdGVyPSIyMDI1LTA0LTE3VDAzOjQ0OjQyLjA2MFoiPjxzYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+PHNhbWw6QXVkaWVuY2U+aHR0cHM6Ly94bGV4LXJhdHNhbWwudXFjbG91ZC5uZXQvc2FtbC9tZXRhZGF0YTwvc2FtbDpBdWRpZW5jZT48L3NhbWw6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWw6Q29uZGl0aW9ucz48c2FtbDpBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMjUtMDQtMTdUMDM6NDM6NDQuMDYwWiIgU2Vzc2lvbkluZGV4PSIyNmVhNzAzYS1jMjQ5LTQ4ODItODE5ZS1mZDQ4NjE2MDdmMzg6OmU0YTI5ZmRmLWM0OTQtNDJhZi1hZDI3LWJmZTc4NTk1ZmU2NCIgU2Vzc2lvbk5vdE9uT3JBZnRlcj0iMjAyNS0wNC0xN1QxMzo0Mzo0NC4wNjBaIj48c2FtbDpBdXRobkNvbnRleHQ+PHNhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6dW5zcGVjaWZpZWQ8L3NhbWw6QXV0aG5Db250ZXh0Q2xhc3NSZWY+PC9zYW1sOkF1dGhuQ29udGV4dD48L3NhbWw6QXV0aG5TdGF0ZW1lbnQ+PHNhbWw6QXR0cmlidXRlU3RhdGVtZW50PjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPnF1ZXJ5LXJlYWxtczwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPnVtYV9hdXRob3JpemF0aW9uPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlJvbGUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+bWFuYWdlLWV2ZW50czwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPm1hbmFnZS11c2Vyczwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPm1hbmFnZS1hY2NvdW50PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlJvbGUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+Y3JlYXRlLXJlYWxtPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlJvbGUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+ZGVmYXVsdC1yb2xlcy1tYXN0ZXI8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iUm9sZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj52aWV3LWF1dGhvcml6YXRpb248L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iUm9sZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj52aWV3LWlkZW50aXR5LXByb3ZpZGVyczwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnM8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iUm9sZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj52aWV3LWV2ZW50czwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPnF1ZXJ5LXVzZXJzPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlJvbGUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+dmlldy1jbGllbnRzPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlJvbGUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+YWRtaW48L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iUm9sZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj52aWV3LXJlYWxtPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlJvbGUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+dmlldy11c2Vyczwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPm1hbmFnZS1yZWFsbTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPnF1ZXJ5LWdyb3Vwczwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPmltcGVyc29uYXRpb248L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iUm9sZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5vZmZsaW5lX2FjY2Vzczwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPnF1ZXJ5LWNsaWVudHM8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iUm9sZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5tYW5hZ2UtYXV0aG9yaXphdGlvbjwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJSb2xlIiBOYW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPm1hbmFnZS1hY2NvdW50LWxpbmtzPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlJvbGUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+dmlldy1wcm9maWxlPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlJvbGUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI+bWFuYWdlLWNsaWVudHM8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48c2FtbDpBdHRyaWJ1dGUgTmFtZT0iUm9sZSIgTmFtZUZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5jcmVhdGUtY2xpZW50PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9zYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6UmVzcG9uc2U+">>)),
    ?assertMatch({ok, _Subset}, verify(Doc, #{
        verifier_options => #{
            danger_trust_any_cert => true
            }
        })).

-endif.
