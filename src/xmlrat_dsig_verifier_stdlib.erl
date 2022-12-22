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
%% Supports:
%%
%% <ul>
%%   <li>
%%     Validating certificates or keys based on their fingerprints:
%%     <ul>
%%       <li>SPKI fingerprint</li>
%%       <li>SSH key fingerprint</li>
%%       <li>X.509 certificate fingerprint</li>
%%     </ul>
%%  </li>
%%  <li>
%%    Validation of CA-signed certificates, but:
%%    <ul>
%%      <li>No chain/intermediate support (end certificate must be signed
%%          directly by CA)</li>
%%      <li>No OCSP support (but does support CRLs retrieved via HTTP)</li>
%%    </ul>
%%  </li>
%% </ul>
%%
%% See {@link options()} for the format of the `verifier_options' map. If no
%% options are given, this module will deny all keys and certificates.
%%
-module(xmlrat_dsig_verifier_stdlib).

-include_lib("public_key/include/public_key.hrl").

-behaviour(xmlrat_dsig_verifier).

-export([retrieve_key/3, validate_key/4, validate_cert/3]).

-export_type([fingerprint/0, options/0]).

-type fingerprint() ::
    {spki | ssh | x509, crypto:hash_algorithm(), binary()}.
-type path() :: string().

-type options() :: #{
    fingerprints => [fingerprint()],
    ca_certs => [#'OTPCertificate'{}],
    ca_cert_file => path(),
    danger_trust_any_key => boolean(),
    danger_trust_any_cert => boolean(),
    danger_ignore_crl_fetch_errors => boolean()
    }.

-spec retrieve_key(options(),
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
-spec validate_key(options(), xmlrat_dsig_verifier:pubkey(),
    xmlrat_dsig_verifier:key_details(), xmlrat_dsig_verifier:algo())
        -> ok | {error, term()}.
validate_key(#{fingerprints := []}, PubKey, _Details, _Algo) ->
    {error, {no_matching_fingerprint, PubKey}};
validate_key(#{fingerprints := [Fp | Rest]}, PubKey, Details, Algo) ->
    case match_fp(Fp, PubKey) of
        true -> ok;
        false -> validate_key(#{fingerprints => Rest}, PubKey, Details, Algo)
    end;
validate_key(#{danger_trust_any_key := true}, _PubKey, _Details, _Algo) ->
    ok.

curve_to_oid(T) when is_tuple(T) and is_integer(element(1,T)) -> T;
curve_to_oid(secp256r1) -> ?'secp256r1';
curve_to_oid(secp384r1) -> ?'secp384r1';
curve_to_oid(secp521r1) -> ?'secp521r1'.

-type pubkey() :: xmlrat_dsig_verifier:pubkey().
-type cert() :: xmlrat_dsig_verifier:cert().
-type pubkey_or_cert() :: pubkey() | cert().

-spec match_fp(fingerprint(), pubkey_or_cert()) -> boolean().
match_fp({spki, HashFunc, Fp}, PubKey = #'RSAPublicKey'{}) ->
    PubKeyDer = public_key:pkix_encode('RSAPublicKey', PubKey, otp),
    SPKI = #'OTPSubjectPublicKeyInfo'{
        algorithm = #'PublicKeyAlgorithm'{
            algorithm = ?'rsaEncryption',
            parameters = <<5,0>>},
        subjectPublicKey = PubKeyDer},
    Der = public_key:pkix_encode('OTPSubjectPublicKeyInfo', SPKI, otp),
    Hash = crypto:hash(HashFunc, Der),
    case Hash of
        Fp -> true;
        _ -> false
    end;
match_fp({spki, HashFunc, Fp}, {#'ECPoint'{point = Pt}, {namedCurve, Curve}}) ->
    CurveOid = curve_to_oid(Curve),
    SPKI = #'OTPSubjectPublicKeyInfo'{
        algorithm = #'PublicKeyAlgorithm'{
            algorithm = ?'id-ecPublicKey',
            parameters = {namedCurve, CurveOid}
        },
        subjectPublicKey = Pt},
    Der = public_key:pkix_encode('OTPSubjectPublicKeyInfo', SPKI, otp),
    Hash = crypto:hash(HashFunc, Der),
    case Hash of
        Fp -> true;
        _ -> false
    end;
match_fp({spki, HashFunc, Fp}, Cert = #'OTPCertificate'{}) ->
    #'OTPCertificate'{tbsCertificate = TBS} = Cert,
    #'OTPTBSCertificate'{subjectPublicKeyInfo = SPKI0} = TBS,
    SPKI1 = make_spki_encodable(SPKI0),
    Der = public_key:pkix_encode('OTPSubjectPublicKeyInfo', SPKI1, otp),
    Hash = crypto:hash(HashFunc, Der),
    case Hash of
        Fp -> true;
        _ -> false
    end;
match_fp({ssh, HashFunc, Fp}, Cert = #'OTPCertificate'{}) ->
    #'OTPCertificate'{tbsCertificate = TBS} = Cert,
    #'OTPTBSCertificate'{subjectPublicKeyInfo = SPKI} = TBS,
    #'OTPSubjectPublicKeyInfo'{algorithm = Alg, subjectPublicKey = SPK} = SPKI,
    PubKey = case Alg of
        #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey',
                              parameters = {namedCurve, Oid}} ->
            {SPK, {namedCurve, Oid}};
        _ ->
            SPK
    end,
    Data = ssh_file:encode(PubKey, ssh2_pubkey),
    Hash = crypto:hash(HashFunc, Data),
    case Hash of
        Fp -> true;
        _ -> false
    end;
match_fp({ssh, HashFunc, Fp}, PubKey0) ->
    PubKey1 = case PubKey0 of
        {P = #'ECPoint'{}, {namedCurve, N}} ->
            {P, {namedCurve, curve_to_oid(N)}};
        _ -> PubKey0
    end,
    Data = ssh_file:encode(PubKey1, ssh2_pubkey),
    Hash = crypto:hash(HashFunc, Data),
    case Hash of
        Fp -> true;
        _ -> false
    end;
match_fp({x509, HashFunc, Fp}, Cert = #'OTPCertificate'{}) ->
    Der = public_key:pkix_encode('OTPCertificate', Cert, otp),
    Hash = crypto:hash(HashFunc, Der),
    case Hash of
        Fp -> true;
        _ -> io:format("~p vs ~p\n", [Hash, Fp]), false
    end;
match_fp(_, _) -> false.

make_spki_encodable(SPKI0) ->
    #'OTPSubjectPublicKeyInfo'{algorithm = Alg0,
                               subjectPublicKey = SPK0} = SPKI0,
    Alg1 = case Alg0 of
        #'PublicKeyAlgorithm'{parameters = 'NULL'} ->
            Alg0#'PublicKeyAlgorithm'{parameters = <<5,0>>};
        _ -> Alg0
    end,
    SPK1 = case Alg0 of
        #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey'} ->
            #'ECPoint'{point = Pt} = SPK0,
            Pt;
        _ ->
            public_key:pkix_encode(element(1, SPK0), SPK0, otp)
    end,
    SPKI1 = SPKI0#'OTPSubjectPublicKeyInfo'{algorithm = Alg1,
                                            subjectPublicKey = SPK1},
    SPKI1.

%% @doc Validate an X.509 certificate included in the XML DSIG payload.
-spec validate_cert(options(), xmlrat_dsig_verifier:cert(),
    xmlrat_dsig_verifier:algo()) -> ok | {error, term()}.
validate_cert(#{fingerprints := [Fp | Rest]}, Cert, Algo) ->
    case match_fp(Fp, Cert) of
        true -> ok;
        false -> validate_cert(#{fingerprints => Rest}, Cert, Algo)
    end;
validate_cert(M0 = #{ca_cert_file := Path}, Cert, Algo) ->
    {ok, CAData} = file:read_file(Path),
    Entries0 = public_key:pem_decode(CAData),
    Entries1 = lists:foldl(fun
        ({'Certificate',E,_}, Acc) ->
            case (catch public_key:pkix_decode_cert(E, otp)) of
                {'EXIT', _} -> Acc;
                C = #'OTPCertificate'{} -> [C | Acc]
            end;
        (_, Acc) -> Acc
    end, [], Entries0),
    M1 = maps:remove(ca_cert_file, M0),
    validate_cert(M1#{ca_certs => Entries1}, Cert, Algo);
validate_cert(M = #{ca_certs := CAs}, Cert, _Algo) ->
    IgnoreCRL = maps:get(danger_ignore_crl_fetch_errors, M, false),
    case find_ca(CAs, Cert) of
        {ok, CA} ->
            case public_key:pkix_path_validation(CA, [Cert], []) of
                {ok, _} ->
                    case (catch fetch_dp_and_crls(Cert)) of
                        {'EXIT', _Reason} when IgnoreCRL ->
                            ok;
                        {'EXIT', Reason} ->
                            {error, {crl_fetch_failure, Reason}};
                        [] ->
                            ok;
                        DPsAndCRLs ->
                            CRLOpts = [
                                {issuer_fun, {fun (_DP, CL, _Name, none) ->
                                    {ok, CrlCA} = find_ca(CAs, CL),
                                    {ok, CrlCA, []}
                                end, none}}
                            ],
                            R = public_key:pkix_crls_validate(Cert,
                                DPsAndCRLs, CRLOpts),
                            case R of
                                valid -> ok;
                                _ -> {error, crl_failure}
                            end
                    end;
                Err ->
                    Err
            end;
        Err ->
            Err
    end;
validate_cert(#{fingerprints := []}, Cert, _Algo) ->
    {error, {no_matching_fingerprint, Cert}};
validate_cert(#{danger_trust_any_cert := true}, _Cert, _Algo) ->
    ok.

fetch_dp_and_crls(Cert) ->
    DPs = public_key:pkix_dist_points(Cert),
    fetch_dps(DPs).

fetch_dps([DP = #'DistributionPoint'{distributionPoint = {fullName, Names}} | Rest]) ->
    fetch_dp_names(DP, Names) ++ fetch_dps(Rest);
fetch_dps([_ | Rest]) ->
    fetch_dps(Rest);
fetch_dps([]) -> [].

fetch_dp_names(DP, [{uniformResourceIdentifier, "http"++_ = URL} | Rest]) ->
    case httpc:request(get, {URL, [{"connection", "close"}]},
                       [{timeout, 1000}], [{body_format, binary}]) of
        {ok, {_Status, _Headers, Body}} ->
            case (catch public_key:der_decode('CertificateList', Body)) of
                {'EXIT', _} ->
                    case (catch public_key:pem_decode(Body)) of
                        {'EXIT', _} -> fetch_dp_names(DP, Rest);
                        [] -> fetch_dp_names(DP, Rest);
                        CLs ->
                            [{DP, {D, public_key:der_decode('CertificateList', D)},
                                  {D, public_key:der_decode('CertificateList', D)}}
                             || {'CertificateList', D, not_encrypted} <- CLs]
                            ++ fetch_dp_names(DP, Rest)
                    end;
                CL = #'CertificateList'{} ->
                    [{DP, {Body, CL}, {Body, CL}} | fetch_dp_names(DP, Rest)]
            end;
        _ ->
            fetch_dp_names(DP, Rest)
    end;
fetch_dp_names(DP, [_ | Rest]) ->
    fetch_dp_names(DP, Rest);
fetch_dp_names(_DP, []) -> [].

-spec find_ca([#'OTPCertificate'{}], #'OTPCertificate'{} | #'CertificateList'{})
    -> {ok, #'OTPCertificate'{}} | {error, term()}.

find_ca([], #'OTPCertificate'{tbsCertificate = TBS}) ->
    #'OTPTBSCertificate'{issuer = {rdnSequence, Issuer}} = TBS,
    {error, {unknown_ca, Issuer}};
find_ca([], _Cert) ->
    {error, unknown_ca};
find_ca([CA | Rest], Cert) ->
    case public_key:pkix_is_issuer(Cert, CA) of
        true -> {ok, CA};
        false -> find_ca(Rest, Cert)
    end.
