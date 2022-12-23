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

-define(dsig_SHA1, <<"http://www.w3.org/2000/09/xmldsig#sha1">>).
-define(dsig_SHA256, <<"http://www.w3.org/2001/04/xmlenc#sha256">>).
-define(dsig_SHA224, <<"http://www.w3.org/2001/04/xmldsig-more#sha224">>).
-define(dsig_SHA384, <<"http://www.w3.org/2001/04/xmldsig-more#sha384">>).
-define(dsig_SHA512, <<"http://www.w3.org/2001/04/xmlenc#sha512">>).

-define(dsig_base64, <<"http://www.w3.org/2000/09/xmldsig#base64">>).

-define(dsig_RSAwithSHA1, <<"http://www.w3.org/2000/09/xmldsig#rsa-sha1">>).
-define(dsig_RSAwithSHA256, <<"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256">>).
-define(dsig_RSAwithSHA384, <<"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384">>).
-define(dsig_RSAwithSHA512, <<"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512">>).

-define(dsig_ECDSAwithSHA1, <<"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1">>).
-define(dsig_ECDSAwithSHA256, <<"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256">>).
-define(dsig_ECDSAwithSHA384, <<"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384">>).
-define(dsig_ECDSAwithSHA512, <<"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512">>).

-define(dsig_DSAwithSHA1, <<"http://www.w3.org/2000/09/xmldsig#dsa-sha1">>).
-define(dsig_DSAwithSHA256, <<"http://www.w3.org/2009/xmldsig11#dsa-sha256">>).

-define(dsig_HMAC_SHA1, <<"http://www.w3.org/2000/09/xmldsig#hmac-sha1">>).
-define(dsig_HMAC_SHA256, <<"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256">>).
-define(dsig_HMAC_SHA384, <<"http://www.w3.org/2001/04/xmldsig-more#hmac-sha384">>).
-define(dsig_HMAC_SHA512, <<"http://www.w3.org/2001/04/xmldsig-more#hmac-sha512">>).

-define(dsig_XML_c14n_exc, <<"http://www.w3.org/2001/10/xml-exc-c14n#">>).
-define(dsig_XML_c14n_10, <<"http://www.w3.org/TR/2001/REC-xml-c14n-20010315">>).
-define(dsig_XML_c14n_11, <<"http://www.w3.org/2006/12/xml-c14n11">>).

-define(dsig_enveloped, <<"http://www.w3.org/2000/09/xmldsig#enveloped-signature">>).
-define(dsig_xpath, <<"http://www.w3.org/TR/1999/REC-xpath-19991116">>).

-define(NS_dsig, <<"http://www.w3.org/2000/09/xmldsig#">>).
