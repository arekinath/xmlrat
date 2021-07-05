# xmlrat

xmlrat is an Erlang library for parsing and manipulating XML documents.
It's particularly designed for use in parsing untrusted inputs in a server
context (e.g. the original use-case is accepting and processing SAML
assertions).

The name xmlrat comes from it using a Packrat parser.

It provides:

 * An XML 1.0 DOM parser
 * A compiler for a subset of XPath 1.0
 * An Erlang `parse_transform` allowing compiling XPath expressions and
   XSLT-style templates to pure Erlang code
 * An implementation of Exclusive Canonical XML
 * An implementation of XML Digital Signature 1.0

Being a fully compliant XML library with a complete implementation of all
specs is a non-goal: features which are inherently dangerous in the context
of parsing untrusted input from the Internet are generally not included.

The library is written in pure Erlang and is designed to deal primarily with
binaries for all data.

## Examples

Parsing an XML document:

```erlang
> xmlrat_parse:string(<<"<?xml version='1.0'?><doc attr='foo'>hi</doc>").
{ok,[#xml{version = <<"1.0">>},
     #xml_element{tag = <<"doc">>,
                  attributes = [#xml_attribute{name = <<"attr">>,value = <<"foo">>}],
                  content = [<<"hi">>]}]}
```

Running XPath:

```erlang
> xmlrat_xpath:run("/doc/@attr", Doc).
{ok,[#xml_attribute{name = <<"attr">>,value = <<"foo">>}]}

> xmlrat_xpath:run("/doc[@attr = 'foo']/text()", Doc).
{ok,<<"hi">>}
```

Canonical XML and XML Digital Signature:

```erlang
> xmlrat_c14n:string(Doc).
<<"<doc attr=\"foo\">hi</doc>">>

> Key = public_key:generate_key({rsa, 2048, 16#10001}).
> Opts = #{signer_options => #{private_key => Key}}.
> {ok, SignedDoc} = xmlrat_dsig:sign(Doc, Opts).
> io:format("~s\n", [
	xmlrat_generate:string(SignedDoc, #{indent => true})
	]).
<?xml version="1.0"?>
<doc attr="foo">
  hi
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      ...
    </SignedInfo>
    <SignatureValue>
      ...
    </SignatureValue>
    <KeyInfo>
      <KeyValue>
        <RSAKeyValue>
          ...
        </RSAKeyValue>
      </KeyValue>
    </KeyInfo>
  </Signature>
</doc>
```

Using the `parse_transform` attributes:

```erlang
-compile({parse_transform, xmlrat_parse_transform}).
-include_lib("xmlrat/include/records.hrl").

-xpath({match_foobar, "/foo/bar[@id = '1']/text()"}).
% now use match_foobar(document()) -> <<"text">>

-xpath({match_foobar2, "/foo/bar/[@id = $id]/text()"}).
% now use match_foobar2(document(), #{<<"id">> => Value}) -> <<"text">>

-record(bar, {
	id :: integer(),
	value :: binary()
	}).
-xpath_record({decode_foobar, bar, #{
	id => "/foo/bar/@id",
	value => "/foo/bar/text()"
	}}).
% now use decode_foobar(document()) -> #bar{}

-xml_record({encode_foobar, bar,
	"<bar id='&id;'><mxsl:value-of field='value'/></bar>"}).
% now use encode_foobar(#bar{}) -> document().
```

## Installing

Available on [hex.pm](https://hex.pm/packages/xmlrat)

## API docs

Edoc available on the [hexdocs](https://hexdocs.pm/xmlrat)
