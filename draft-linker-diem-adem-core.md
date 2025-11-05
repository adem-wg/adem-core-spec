---
title: "ADEM Core Specification"
category: info

docname: draft-linker-diem-adem-core-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "Digital Emblems"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "Digital Emblems"
  type: "Working Group"
  mail: "diem@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/diem"
  github: "adem-wg/adem-core-spec"
  latest: "https://adem-wg.github.io/adem-core-spec/draft-linker-diem-adem-core.html"

author:
 -
    fullname: "Felix Linker"
    email: "linkerfelix@gmail.com"

normative:

informative:

...

--- abstract

In times of armed conflict, the protective emblems of the red cross, red crescent, and red crystal are used to mark physical assets.
This enables military units to identify assets as respected and protected under international humanitarian law.
This draft specifies the format and trust architecture of a protective, digital emblem to network-connected infrastructure.
Such emblems mark bearers as protected under IHL analogously to the physical emblems.

--- middle

# Introduction

International Humanitarian Law (IHL) mandates that military units must not attack medical facilities, such as hospitals.
The emblems of the red cross, red crescent, and red crystal are used to mark physical infrastructure (e.g., by a red cross painted on a hospital's rooftop), thereby enabling military units to identify those bearers as protected under IHL.
This document specifies the structure and trust model of digital emblems for IHL that can be used to mark digital infrastructure as protected under IHL analogously to the physical emblems.
We call this system *ADEM*, which stands for an Authentic Digital EMblem.

In ADEM, emblems are signed statements that mark a *bearer* as proteced under IHL.
Emblems are issued by *emblem issuers*.
Emblem issuer can be authorized by *authorities*.
Authorities do so by signing *endorsements* for emblem issuers.
We call both emblems and endorsements *tokens*.
Emblems are consumed and validated by *validators*.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

**Token** A token is either an emblem or an endorsement and encoded as a JWS.

**Emblem** An emblem is a sign of protection under IHL.

**Endorsement** An endorsement associates a public key with an identity, and hence, resembles the idea of a certificate.
When signed by an authority, it attests that the authorized issuer can generally issue claims of protection.

**Root Key** Organizations control root keys, which identify them cryptographically.
Any key of an organization that is endorsed by other parties is a root key.

**Bearer** A bearer is a network-connected asset that enjoys the specific protections under IHL.
Bearers must be unambiguously identifiable and unambiguously protected, for example, if they are identified by a domain name that domain name must not be used for services that do not enjoy specific protections under IHL.

**Emblem issuer** An emblem issuer is an organization entitled to issue claims of protection for their digital infrastructure.

**Authority** An authority is an organization that is trusted by some to attest a party's status as protected.
This trust may stem from law.
For example, nation states or NGOs can take the role of authorities.

**Organization** An emblem issuer or autority.

**Validator** A validator is an agent interested in observing and verifying digital emblems.

Beyond these terms, we use the terms "claim" and "header parameter" as references to the JWT specification {{!RFC7519}}.

# Tokens

## Identifiers and their Semantics

Emblems are issued for bearers by emblem issuers, which in turn are authorized by authorities.
Both emblem issuers and authorities are *organizations*.
This section specifies how bearers and organizations are identified.

### Bearer Identifiers

Bearers are identified by *bearer identifiers* (BIs).
Bearer identifiers closely resemble Uniform Resource Identifiers (URIs) as specified in {{!RFC3986}}.
However, to limit their scope, we do not follow the specification of URIs and instead define our own syntax.

#### Syntax

Bearer identifiers follow the syntax (`domain-name`, `IPv6` defined below):

~~~~
bearer-identifier = domain-name | "[" IPv6 "]"
~~~~

Domain names (`domain-name`) MUST be formatted as usual and specified in {{!RFC1035}} with the exception that the leftmost label MAY be the single-character wildcard `"*"`.
In particular, `"*"` itself is a valid domain name in context of this specification.

IPv6 addresses (`IPv6`) MUST be formatted following {{!RFC4291}}.
IPv6 addresses MUST be global unicast or link-local unicast addresses.
Note that the syntax of IPv6 addresses also support IPv4 addresses through "IPv4-Mapped IPv6 Addresses" (cf. {{!RFC4291}}, [Section 2.5.5.2](https://www.rfc-editor.org/rfc/rfc4291.html#section-2.5.5.2)).

These are examples of BIs:

* `*.example.com`
* `[2606:2800:220:1:248:1893:25c8:1946]`
* `[::FFFF:93.184.216.34]`

#### Semantics

Several kinds of bearers can be identified by bearer identifiers:

* Network facing processes, e.g., web servers
* Computational devices both in the virtual sense, e.g., a virtual machine, and in the physical sense, e.g., a laptop
* Networks

A BI identifies a set of IPv4 or IPv6 addresses:

- If the BI is an IPv6 address, it identifies this address only.
- If the BI an IPv6 address prefix, it identifies all IPv6 addresses matching that prefix.
- If the BI is a domain name, it identifies any address for which there is an `A` or `AAAA` record for that domain name.
- If the BI is a domain name starting with the wildcard `"*"`, it identifies any address for which there is an `A` or `AAAA` record for that domain name or any of its subdomains.

Any process reachable under any of the addresses pointed towards by `address` and on the port specified (or any port, if unspecified) is pointed by the respective BI.

#### Order

BIs may not only be used for identification but also for constraint purposes.
For example, an endorsement may constrain emblems to only signal protection for a specific IP address range.
In this section, we define an order on BIs so that one can verify if an identifying BI complies with a constraining BI.

We define an BI A to be *more general* than an BI B, if all of the following conditions apply:

* If A encodes a domain name and does not contain the wildcard `"*"`, B encodes a domain name, too, and A is equal to B.
* If A encodes a domain name and contains the wildcard `"*"`, B encodes a domain name, too, and B is a subdomain of A excluding the wildcard `"*"`.
In this regard, any domain is considered a subdomain of itself.
* If A encodes an IP address, B encodes an IP address, too, and A is a prefix of B.

Note that BIs encoding a domain name are incomparable to BIs encoding IP addresses, i.e., neither can be more general than the other.

### Organization Identifiers

Emblems can be associated to an organization.
Organizations are identified by URIs, bearing the scheme `"https"` and a domain name.
We call URIs identifying organizations *organization identifiers* (OIs).

More precisely, an OI has the syntax:

~~~~
organization-identifier = "https://" domain-name
~~~~

Domain names must be formatted as usual, specified in {{!RFC1035}}, but always represented in all lower-case.
For example, `https://example.com` is a valid OI, but `https://EXAMPLE.COM` is not.

## Token Encoding

Tokens MUST be encoded as a JWS {{!RFC7515}} or as an unsecured JWT as defined in {{!RFC7519}}, [Section 6](https://datatracker.ietf.org/doc/html/rfc7519#section-6) in compact serialization.
Tokens encoded as JWS MUST only use JWS protected headers and MUST include the `jwk` or the `kid` header parameter.
Any token MUST include the `cty` (content type) header parameter.

### Emblems {#emblems}

An emblem is encoded either as JWS or as an unsecured JWT which signals protection of bearers.
It is distinguished by the `cty` header parameter value which MUST be `"adem-emb"`.
Its payload includes the JWT claims defined in the table below, following {{!RFC7519}}, [Section 4.1](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1).
All other registered JWT claims MUST NOT be included.

| Claim | Status | Semantics | Encoding |
| ----- | ------ | --------- | -------- |
| `ver` | REQUIRED | Version string | `"v1"` |
| `iat` | REQUIRED | As per {{!RFC7519}} | |
| `nbf` | REQUIRED | As per {{!RFC7519}} | |
| `exp` | REQUIRED | As per {{!RFC7519}} | |
| `iss` | RECOMMENDED | Organization signaling protection | OI |
| `bearers` | REQUIRED | BIs marked a protected | Array of BIs |
| `emb` | REQUIRED | Emblem details | JSON object (as follows) |

Multiple BIs within `bearers` may be desirable, e.g., to include both a bearer's IPv4 and IPv6 address.
The claim value of `emb` MUST be a JSON {{!RFC7159}} object with the following key-value mappings.

| Claim | Status | Semantics | Encoding |
| ----- | ------ | --------- | -------- |
| `prp` | OPTIONAL | Emblem purposes | Array of `purpose` (as follows) |
| `dst` | OPTIONAL | Permitted distribution channels | Array of `distribution-method` (as follows) |

      purpose = "protective" | "indicative"

      distribution-method = "dns" | "tls" | "udp"

The distribution channels defined above correspond to the distribution methods as specified in {{ADEM-DNS}}, {{ADEM-TLS}}, and {{ADEM-UDP}} respectively.


#### Example

For example, an emblem might comprise the following header and payload.

Header:

~~~~json
{
  "alg": "ES512",
  "kid": "4WICC9pZ5zh6m3sfNYwwLilHzNazbFoJU6Qe5ds_8pY",
  "cty": "adem-emb"
}
~~~~

Payload:

~~~~json
{
  "emb": {
    "dst": ["icmp"],
    "prp": ["protective"]
  },
  "iat": 1672916137,
  "nbf": 1672916137,
  "exp": 1675590932,
  "iss": "https://example.com",
  "bearers": ["[2001:0db8:582:ae33::29]"]
}
~~~~

### Endorsements

Endorsements are encoded as JWSs.
Endorsements attest two statements: that a public key is affiliated with an organization, pointed to by OIs, and that this organization is eligible to issue emblems for their bearers.
They are distinguished by the `cty` header parameter value which MUST be `"adem-end"`.
An endorsement's payload includes the JWT claims defined in the table below.
All otger registered JWT claims MUST NOT be included.

| Claim | Status | Semantics | Encoding |
| ----- | ------ | --------- | -------- |
| `ver` | REQUIRED | Version string | `"v1"` |
| `iat` | REQUIRED | As per {{!RFC7519}} | |
| `nbf` | REQUIRED | As per {{!RFC7519}} | |
| `exp` | REQUIRED | As per {{!RFC7519}} | |
| `iss` | RECOMMENDED | Endorsing organization | OI |
| `sub` | RECOMMENDED | Endorsed organization | OI |
| `key` | REQUIRED | Endorsed organization's key | JWK as per {{!RFC7517}} (must include `alg`) |
| `log` | OPTIONAL | Root key CT logs | Array (as follows) |
| `end` | REQUIRED | Endorsed key can endorse further | Boolean |
| `emb` | REQUIRED | Emblem constraints | JSON object (as follows) |

If an endorsement was signed by a root key, it MUST include `log`.
`log` maps to an array of JSON objects with the following claims.
The semantics of these fields are defined in {{!RFC6962}} for `v1` and {{!RFC9162}} for `v2`.

| Claim | Status | Semantics | Encoding |
| ----- | ------ | --------- | -------- |
| `ver` | REQUIRED | CT log version | `"v1"` or `"v2"` |
| `id`  | REQUIRED | The CT log's ID | Base64-encoded string |
| `hash` | REQUIRED | The binding certificate's leaf hash in the log | Base64-encoded string |

`emb` resembles the emblem's `emb` claim and includes the following claims.

| Claim | Status | Semantics | Encoding |
| ----- | ------ | --------- | -------- |
| `prp` | OPTIONAL | Purpose constraint | Array of `purpose` |
| `dst` | OPTIONAL | Distribution method constraint | Array of `distribution-method` |
| `bearers` | OPTIONAL | Bearer constraint | Array of BIs |
| `wnd` | OPTIONAL | Maximum emblem lifetime | Integer |

We say that an endorsement *endorses* a token if its `key` claim equals the token's verification key, and its `sub` claim equals the token's `iss` claim.
We note that the latter includes the possibility of both `sub` and `iss` being undefined.

We say that an emblem is *valid* with respect to an endorsement if all the following conditions apply:

* The endorsement's `emb.prp` claim is undefined or a superset of the emblem's `emb.prp` claim.
* The endorsement's `emb.dst` claim is undefined or a superset of the emblem's `emb.dst` claim.
* The endorsement's `emb.bearers` claim is undefined or for each BI within the emblem's `emb.bearers` claim, there exists an BI within the endorsement's `emb.bearers` claim which is more general than the emblem's `emb.bearers` claim.
* The endorsement's `emb.wnd` claim is undefined or the sum of emblem's `nbf` and the endorsement's `emb.wnd` claims is greater than or equal to the emblem's `exp` claim.

# Public Key Commitment {#pk-distribution}

Parties must undeniably link their root public keys to their OI.
In this section, we specify the configuration of a emblem issuer's OI.
Root public keys are all public keys which are only endorsed by third parties and never endorsed by the organization itself.
A party MAY have multiple root public keys.

Any root public key MUST be encoded as JWK as per {{!RFC7517}} and {{!RFC7518}}.
Root public keys MUST include the `alg` and `kid` parameters, and the `kid` parameter MUST be the key's JWK Thumbprint as per {{!RFC7638}}, encoded in Base 32 as per {{!RFC4648}}.

For a root public key to be configured correctly, there MUST be an X.509 certificate that:

* MUST NOT be revoked
* MUST be logged in the Certificate Transparency logs {{!RFC6962}}, {{!RFC9162}}
  * Note that log inclusion requires a valid certificate chain that leads to
  one of the logs accepted root certificates. Clients are RECOMMENDED to verify
  that this chain is valid and that none of the certificates along it have been
  revoked.
* MUST be valid for at least all the following domains (`<OI>` is understood to be a placeholder for the party's OI):
  * `adem-configuration.<OI>`
  * For root public key's kid `<KID>` (to be understood as a placeholder): `<KID>.adem-configuration.<OI>`

We intentionally do not specify how clients should check a certificate's revocation status.
It is RECOMMENDED that clients use offline revocation checks that are provided by major browser vendors, for example, [OneCRL or CRLite by Mozilla](https://wiki.mozilla.org/CA/Revocation_Checking_in_Firefox), or [CRLSet by Chrome](https://chromium.googlesource.com/playground/chromium-org-site/+/refs/heads/main/Home/chromium-security/crlsets.md).

# Signs of Protection

A sign of protection is an emblem, accompanied by one or more endorsements.
Whenever a token includes OIs (in `iss` or `sub` claims), these OIs must be configured accordingly.
An OI serves to identify an emblem issuer or authority in the real world.
Hence, parties MUST configure the website hosted under their OI to provide sufficient identifying information.

## Verification

Whenever a validator receives an emblem, they MAY check if it is valid.
The validity of an emblem is defined with respect to a public key.
A validity checking algorithm MUST returns the following values.
The order of these values encodes the *strength* of the verification result.

1. `UNSIGNED`
2. `INVALID`
3. `SIGNED-UNTRUSTED`
4. `SIGNED-TRUSTED`
5. `ORGANIZATIONAL-UNTRUSTED`
6. `ORGANIZATIONAL-TRUSTED`
7. `ENDORSED-UNTRUSTED`
8. `ENDORSED-TRUSTED`

Given an input public key and an emblem with a set of endorsements, a verification algorithm takes the following steps:

1. If the emblem does not bear a signature, return `UNSIGNED`.
2. Run the *signed emblem verification procedure* ({{signed-emblems}}; results in one of `SIGNED-TRUSTED`, `SIGNED-UNTRUSTED`, or `INVALID`).
3. If previous procedure resulted in `INVALID` or the emblem does not include the `iss` claim, return the last verification procedure's result and the emtpy set of OIs.
4. Run the *organizational emblem verification procedure* ({{org-emblems}}; results in one of `ORGANIZATIONAL-TRUSTED`, `ORGANIZATIONAL-UNTRUSTED`, `INVALID`).
5. If the previous procedure resulted in `INVALID` return `INVALID` and the empty set of OIs.
6. If all tokens include the same `iss` claim, return the strongest return value matching `*-TRUSTED`, the strongest return value matching `*-UNTRUSTED` provided that it is strictly stronger than the strongest return value matching `*-TRUSTED`, and the empty set of OIs.
7. Run the *endorsed emblem verification procedure* ({{endorsed-emblems}}; results in a set of OIs and one of `ENDORSED-TRUSTED`, `ENDORSED-UNTRUSTED`, `INVALID`).
8. If the previous procedure resulted in `INVALID` return `INVALID` and the empty set of OIs.
9. Return the strongest return value matching `*-TRUSTED`, the strongest return value matching `*-UNTRUSTED` provided that it is strictly stronger than the strongest return value matching `*-TRUSTED`, and the set of OIs returned by the endorsed emblem verification procedure.

Note that the endorsed emblem verification procedure resulting in `INVALID` is handled implicitly in step 8.
As the procedure did not terminate in step 5, organizational verification must have been successful.
Hence, `INVALID` cannot be the strongest return value, and an emblem not being accompanied by valid endorsements are downgraded to organizational emblems.

The set of OIs returned by the verification procedure encodes the OIs of endorsing parties where verification passed.

### Comments on Trust Policies

We strongly RECOMMEND against accepting emblems resulting in `SIGNED-UNTRUSTED`.
In such cases, validators should aim to authenticate the respective public keys via other, out-of-band methods.
This effectively lifts the result to `SIGNED-TRUSTED`.
Signed emblems are supported for cases of emergency where an emblem issuer is able to communicate one or more public key, but might not be able to set up a signing infrastructure linking their bearers to a root key.

There is no definite guideline on how to choose which keys to trust, i.e., which keys to pass as trusted public key to the verification procedure.
Some validators may have pre-existing trust relationships with some authorities, e.g., military units of a nation state could use the public keys of their nation state or allies.
Other validators might be fine with fetching public keys authenticated only by the web PKI.

## Protection

An emblem for which the verification procedure produces a result other than `INVALID` marks any asset whose address is identified by at least one of the emblem's BIs.
Such an emblem signals that the respective asset is enjoys the specific protections of IHL.

# Algorithms

## Signed Emblem Verification Procedure {#signed-emblems}

Context:

* Input: An emblem, a set of endorsements, and a trusted public key.
* Output: `SIGNED-TRUSTED`, `SIGNED-UNTRUSTED`, or `INVALID`.

Algorithm:

1. Ignore all endorsements including an `iss` claim different to the emblem's `iss` claim.
A defined `iss` claim is understood to be different to an undefined `iss` claim.
2. Verify every signature.
3. Verify that all endorsements form a consecutive chain where there is a unique root endorsement and the public key which verifies the emblem is transitively endorsed by that root endorsement.
4. Verify that no endorsement expired.
5. Verify that all endorsements bear the claim `end=true` except for the emblem signing key's endorsement.
6. Verify that the emblem is valid with regard to every endorsement.
7. If any of the aforementioned verification steps fail, return `INVALID`.
If there is a token signed by the trusted input public key, return `SIGNED-TRUSTED`.
Otherwise, return `SIGNED-UNTRUSTED`.

Distribution methods MAY indicate an order of tokens to guide clients assembling the chain of endorsements in step 3.
Whenever such an order is specified, clients MAY immediately reject a set of tokens as invalid if the indicated order does not yield a valid chain of endorsements.

## Organizational Emblem Verification Procedure {#org-emblems}

Context:

* Assumptions: Signed emblem verification has been performed and did not return `INVALID`.
Every token as part of the input includes the `iss` claim.
* Input: An emblem, a set of endorsements, and a trusted public key.
* Output: `ORGANIZATIONAL-TRUSTED`, `ORGANIZATIONAL-UNTRUSTED`, or `INVALID`.

Algorithm:

1. Ignore all endorsements including an `iss` claim different to the emblem's `iss` claim.
2. Verify that the top-most endorsement's `iss` claim value (its OI) is configured correctly as specified in {{pk-distribution}}.
3. If the aforementioned verification step fails, return `INVALID`.
If the top-most endorsing key is equal to the trusted input public key, return `ORGANIZATIONAL-TRUSTED`. Otherwise, return `ORGANIZATIONAL-UNTRUSTED`.

## Endorsed Emblem Verification Procedure {#endorsed-emblems}

Context:

* Assumptions: Organizational emblem verification has been performed and did not return `INVALID`.
There are emblems as part of the input including an `iss` claim different to the emblem's `iss` claim.
* Input: An emblem, a set of endorsements, and a trusted public key.
* Output: `ENDORSED-TRUSTED`, `ENDORSED-UNTRUSTED`, or `INVALID`, and a set of OIs.

Algorithm:

1. Ignore all endorsements including an `iss` claim equal to the emblem's `iss` claim.
2. For every endorsement:
   1. Verify its signature.
   2. Verify that it endorses the top-most endorsing key with the same `iss` claim as the emblem.
   3. Verify that it did not expire.
   4. Verify that it bears the claim `end=true`.
   5. Verify that the emblem is valid with regard to this endorsement.
   6. Implementations SHOULD verify that the endorsement's `iss` claim value (its OI) is configured correctly as specified in {{pk-distribution}}.
   7. Should any of the aforementioned verification steps fail, ignore this endorsement.
3. If there are no endorsements remaining after the last step, return `INVALID` and the empty set of OIs.
If in the set of remaining endorsements, there is an endorsement with a verification key equal to the trusted input public key, return `ENDORSED-TRUSTED`.
Otherwise, return `ENDORSED-UNTRUSTED`.
In both the latter cases, also return the set of all `iss` claims of the remaining endorsements.

# Security Considerations

## No Endorsements without `iss`

The procedures to verify organizational or endorsed emblems as specified in {{org-emblems}} and {{endorsed-emblems}} assume that the emblem's `iss` claim is defined.
Practically speaking, this implies that parties can only go beyond pure public key authentication (where public keys need to be authenticated out-of-band) by stating an OI.

The constraints on well-configured OIs offers two beneficial security properties:

* Parties cannot equivocate their keys, i.e., they need to commit to a consistent set of keys.
* Parties cannot deny having used certain root public keys.

These properties stem from parties needing to include a hash of their key in a TLS certificate, and consequently, in certificate transparency logs.

## Token Order

As specified in {{signed-emblems}}, clients MAY reject sets of tokens as invalid if the order of tokens as indicated by the sending client does not yield a valid chain of endorsements.
This allows an adversary to force rejection of a set of tokens by altering, e.g., sequence numbers on non-integrity protected channels such as UDP.

However, this does not constitute a new attack.
Such adversaries could flip a bit in the emblem's signature, rendering the set of tokens invalid, too.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
