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
  STATIC-CT:
    target: https://github.com/C2SP/C2SP/blob/0f3fddde7d1d8bd55e42723572c4c144457c50d0/static-ct-api.md
    title: The Static Certificate Transparency API
    date: 2026-03-20

informative:

...

--- abstract

In times of armed conflict, the protective emblems of the red cross, red crescent, and red crystal are used to mark physical assets.
This enables military units to identify assets as respected and protected under international humanitarian law.
This draft specifies the format and trust architecture of a protective, digital emblem for network-connected infrastructure.
Such emblems mark assets as protected under IHL analogously to the physical emblems.

--- middle

# Introduction

International Humanitarian Law (IHL) mandates that military units must not attack medical facilities, such as hospitals.
The emblems of the red cross, red crescent, and red crystal are used to mark physical infrastructure (e.g., by a red cross painted on a hospital's rooftop), thereby enabling military units to identify those assets as protected under IHL.
This document specifies the structure and trust model of digital emblems for IHL that can be used to mark digital infrastructure as protected under IHL analogously to the physical emblems.
We call this system *ADEM*, which stands for an Authentic Digital EMblem.

In ADEM, emblems are signed statements that mark *assets* as protected under IHL.
Emblems are issued by *emblem issuers*.
Emblem issuers can be authorized by *authorities*.
Authorities do so by signing *endorsements* for emblem issuers.
We call both emblems and endorsements *tokens*.
Emblems are consumed and validated by *validators*.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

**Token** A token is either an emblem or an endorsement and is encoded as a signed CBOR Web Token (CWT).

**Emblem** An emblem is a sign of protection under IHL.

**Endorsement** An endorsement associates a public key with an identity, and hence, resembles the idea of a certificate.
When signed by an authority, it attests that the authorized issuer can generally issue claims of protection.

**Root Key** Organizations control root keys, which identify them cryptographically.
Any key of an organization that is endorsed by other parties is a root key.

**Asset** An asset is a network-connected service that enjoys the specific protections under IHL.
Assets must be unambiguously identifiable and unambiguously protected, for example, if they are identified by a domain name that domain name must not be used for services that do not enjoy specific protections under IHL.

**Emblem issuer** An emblem issuer is an organization entitled to issue claims of protection for their digital infrastructure.

**Authority** An authority is an organization that is trusted by some to attest a party's status as protected.
This trust may stem from law.
For example, nation states or NGOs can take the role of authorities.

**Organization** An emblem issuer or authority.

**Validator** A validator is an agent interested in observing and verifying digital emblems.

Beyond these terms, we use the terms "claim", "claim key", "claim value", and "CWT Claims Set" as defined in {{!RFC8392}}, and "header parameter" as defined in {{!RFC9052}}.

# Tokens

## Identifiers and their Semantics

Emblems are issued for assets by emblem issuers, which in turn are authorized by authorities.
Both emblem issuers and authorities are *organizations*.
This section specifies how assets and organizations are identified.

### Asset Identifiers

Assets are identified by *asset identifiers* (AIs).
Asset identifiers closely resemble Uniform Resource Identifiers (URIs) as specified in {{!RFC3986}}.
However, to limit their scope, we do not follow the specification of URIs and instead define our own syntax.

#### Syntax

Asset identifiers follow the syntax (`domain-name`, `IPv6` defined below):

~~~~
asset-identifier = domain-name | "[" IPv6 "]"
~~~~

Domain names (`domain-name`) MUST be formatted as usual and specified in {{!RFC1035}} with the exception that the leftmost label MAY be the single-character wildcard `"*"`.
In particular, `"*"` itself is a valid domain name in context of this specification.

IPv6 addresses (`IPv6`) MUST be formatted following {{!RFC4291}}.
IPv6 addresses MUST be global unicast or link-local unicast addresses.
Note that the syntax of IPv6 addresses also supports IPv4 addresses through "IPv4-Mapped IPv6 Addresses" (cf. {{!RFC4291}}, [Section 2.5.5.2](https://www.rfc-editor.org/rfc/rfc4291.html#section-2.5.5.2)).

These are examples of AIs:

* `*.example.com`
* `[2001:0db8::248:1893:25c8:1946]`
* `[::FFFF:93.184.216.34]`

#### Semantics

Several kinds of assets can be identified by asset identifiers:

* Network facing processes, e.g., web servers
* Computational devices both in the virtual sense, e.g., a virtual machine, and in the physical sense, e.g., a laptop
* Networks

An AI identifies a set of IPv4 or IPv6 addresses:

- If the AI is an IPv6 address, it identifies this address only.
- If the AI is an IPv6 address prefix, it identifies all IPv6 addresses matching that prefix.
- If the AI is a domain name, it identifies any address for which there is an `A` or `AAAA` record for that domain name.
- If the AI is a domain name starting with the wildcard `"*"`, it identifies any address for which there is an `A` or `AAAA` record for that domain name or any of its subdomains.

Any process reachable under any of the addresses pointed towards by `address` and on the port specified (or any port, if unspecified) is pointed by the respective AI.

#### Order

AIs may not only be used for identification but also for constraint purposes.
For example, an endorsement may constrain emblems to only signal protection for a specific IP address range.
In this section, we define an order on AIs so that one can verify if an identifying AI complies with a constraining AI.

We define an AI A to be *more general* than an AI B, if all of the following conditions apply:

* If A encodes a domain name and does not contain the wildcard `"*"`, B encodes a domain name, too, and A is equal to B.
* If A encodes a domain name and contains the wildcard `"*"`, B encodes a domain name, too, and B is a subdomain of A excluding the wildcard `"*"`.
In this regard, any domain is considered a subdomain of itself.
* If A encodes an IP address, B encodes an IP address, too, and A is a prefix of B.

Note that AIs encoding a domain name are incomparable to AIs encoding IP addresses, i.e., neither can be more general than the other.

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

Tokens MUST be encoded as CWTs {{!RFC8392}} secured by a COSE_Sign1 structure {{!RFC9052}}, and tokens MUST include the CWT CBOR tag 61 and the COSE_Sign1 CBOR tag 18.
The COSE payload MUST be present and MUST contain the CBOR-encoded CWT Claims Set.
External additional authenticated data MUST be the zero-length byte string.

The CWT Claims Set MUST be a CBOR map.
Registered CWT claims use their integer claim keys from {{!RFC8392}}; claims defined by this document use the text-string claim keys shown below.
Unless this document states otherwise, the terms and processing rules of {{!RFC8392}} apply.

### Key Identifiers and Key Formats {#key-formats}

Keys are encoded as COSE_Key structures {{!RFC9052}} and MUST include the `alg` parameter (label 3).
The key's `alg` value MUST equal the `alg` value in the protected header of each token signed with that key.

We identify keys using key identifiers, which are 32-byte SHA-256 COSE Key Thumbprints, computed as specified in {{!RFC9679}}.
To force computation and thus verification of key identifiers, COSE_Key structures in the context of ADEM SHOULD NOT contain the `kid` parameter (label 2).
Implementations that encode key material MUST NOT include the `kid` parameter, but implementations consuming key material SHOULD accept and ignore the `kid` parameter and MUST verify the `kid` parameter by recomputing it.

Key identifiers are encoded as a CBOR byte string when used as the COSE `kid` header parameter or as a CWT claim value.
When a textual representation is required, key identifiers are encoded using base32 as specified in {{!RFC4648}}, in lowercase and without trailing `=` characters.

### Common Token Fields {#common-token-fields}

Both emblems and endorsements use the following protected header parameters and CWT claims.
Implementations generating tokens MUST NOT include header parameters or CWT claims beyond those referenced in this document.

The COSE protected header MUST include the `alg` (label 1) and `kid` (label 4) header parameters.
The `alg` value identifies the signature algorithm.
The `kid` value MUST equal the key identifier of the verification key as specified in {{key-formats}}.

The protected header MAY include the `typ` (label 16, see {{!RFC9596}}) header parameter with the value `"application/adem"`.
The `typ` parameter identifies tokens as emblems.
Where clear from context, the `typ` parameter MAY be omitted.

The COSE unprotected header MUST be empty.

| Claim | Claim key | Status | Semantics | CBOR type |
| ----- | --------- | ------ | --------- | --------- |
| `ver` | `"ver"` | REQUIRED | Version counter | uint, value 1 |
| `iat` | 6 | OPTIONAL | Issued-at time, as per {{!RFC8392}} | NumericDate |
| `nbf` | 5 | REQUIRED | Not-before time, as per {{!RFC8392}} | NumericDate |
| `exp` | 4 | REQUIRED | Expiration time, as per {{!RFC8392}} | NumericDate |
| `iss` | 1 | RECOMMENDED | Organization issuing the token | tstr containing an OI |
| `emb` | `"emb"` | REQUIRED | Emblem details or constraints, depending on the token type | map |

The token version counter `ver` MUST be an unsigned integer in the range 0 to 255, encoded as a CBOR unsigned integer.
This document specifies version 1.

For an emblem, `iss` identifies the organization signaling protection; for an endorsement, it identifies the endorsing organization.
The `emb` claim MUST be a CBOR {{!RFC8949}} map.
Its entries and their requirements depend on the token type and are defined in {{emblems}} and {{endorsements}}.

### Emblems {#emblems}

An emblem is encoded as a signed CWT and signals the protection of assets.
Its CWT Claims Set includes the common claims defined in {{common-token-fields}} and the additional claim defined in the table below.

| Claim | Claim key | Status | Semantics | CBOR type |
| ----- | --------- | ------ | --------- | --------- |
| `assets` | `"assets"` | REQUIRED | AIs marked as protected | array of tstr AIs |

Multiple AIs within `assets` may be desirable, e.g., to include both an asset's IPv4 and IPv6 address.
For an emblem, the `emb` claim contains the following entries.

| Entry | Map key | Status | Semantics | CBOR type |
| ----- | ------- | ------ | --------- | --------- |
| `prp` | `"prp"` | REQUIRED | Emblem purposes | array of tstr `purpose` values (as follows) |
| `dst` | `"dst"` | OPTIONAL | Permitted distribution channels | array of tstr `distribution-method` values (as follows) |

The `purpose` values identify the purpose signaled by the emblem.

| Value | Explanation |
| ----- | ----------- |
| `"redcr-protective"` | Protective use of the red cross, red crescent, or red crystal emblem to signal protection under IHL. |
| `"redcr-indicative"` | Indicative use of the red cross, red crescent, or red crystal emblem to signal an affiliation with the International Red Cross and Red Crescent Movement. |
| `"dangerous-forces"` | Identification of works and installations containing dangerous forces, such as dams, dykes, and nuclear electrical generating stations. |
| `"civil-defense"` | Identification of civil defence organizations and their protected personnel and assets. |
| `"blue-shield"` | Identification of cultural property protected under IHL. |

The `distribution-method` values identify the permitted methods for distributing the emblem.

| Value | Explanation |
| ----- | ----------- |
| `"dns"` | Distribution through the Domain Name System (DNS), as specified in other documents. |

Other distribution methods are planned for the future.

#### Example

For example, an emblem might comprise the following protected header and CWT Claims Set, shown in CBOR diagnostic notation.

Protected header:

~~~~cbor-diag
{
  / alg / 1: -36, / ES512 /
  / kid / 4: h'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  / typ / 16: "application/adem"
}
~~~~

Claims Set:

~~~~cbor-diag
{
  "ver": 1,
  "emb": {
    "dst": ["dns"],
    "prp": ["redcr-protective"]
  },
  / nbf / 5: 1672916137,
  / exp / 4: 1675590932,
  / iss / 1: "https://example.com",
  "assets": ["[2001:0db8:582:ae33::29]"]
}
~~~~

### Endorsements {#endorsements}

Endorsements are encoded as signed CWTs.
Endorsements attest two statements: that a public key is affiliated with an organization, identified by an OI, and that this organization is authorized to issue emblems for their assets.
An endorsement's CWT Claims Set includes the common claims defined in {{common-token-fields}} and the additional claims defined in the table below.

| Claim | Claim key | Status | Semantics | CBOR type |
| ----- | --------- | ------ | --------- | --------- |
| `sub` | 2 | RECOMMENDED | Endorsed organization | tstr containing an OI |
| `key` | `"key"` | REQUIRED | Endorsed organization's public key | bstr containing the endorsed key's `kid` |
| `end` | `"end"` | REQUIRED | Endorsed key can endorse further | bool |

The protected header parameter `log` uses the text-string label `"log"` and identifies the CT logs that contain a binding certificate for the endorsement's verification key.
If an endorsement was signed by a root key, its protected header MUST include `log`.
The `log` value is an array of CBOR maps, each of which identifies a CT log entry that commits to the organization's root signing key (see {{pk-distribution}}).
This standard supports log entries of both standard CT logs as specified in {{!RFC6962}} and tiled CT logs as specified in {{STATIC-CT}}.

| Entry | Map key | Status | Semantics | CBOR type |
| ----- | ------- | ------ | --------- | --------- |
| `id`  | `"id"` | REQUIRED | The CT log's ID | bstr |
| `hash` | `"hash"` | see below | The binding certificate's leaf hash in the log | bstr |
| `index` | `"index"` | see below | The binding certificate's log entry index in the log | uint |

For logs following {{!RFC6962}}, a map in `log` MUST include the `hash` entry and MUST NOT include the `index` entry.
The contrary is the case for logs following {{STATIC-CT}}.
For those logs, a map in `log` MUST include the `index` entry and MUST NOT include the `hash` entry.

For an endorsement, the `emb` claim contains the following constraint entries.

| Entry | Map key | Status | Semantics | CBOR type |
| ----- | ------- | ------ | --------- | --------- |
| `prp` | `"prp"` | OPTIONAL | Purpose constraint | array of tstr `purpose` values |
| `dst` | `"dst"` | OPTIONAL | Distribution method constraint | array of tstr `distribution-method` values |
| `assets` | `"assets"` | OPTIONAL | Asset constraint | array of tstr AIs |
| `wnd` | `"wnd"` | OPTIONAL | Maximum emblem lifetime in seconds | int |

We say that an endorsement *endorses* a token if its `key` claim equals the key identifier of the token's verification key, and its `sub` claim equals the token's `iss` claim.
We note that the latter includes the possibility of both `sub` and `iss` being undefined.

We say that an emblem is *valid* with respect to an endorsement if all the following conditions apply:

* The endorsement's `emb.prp` claim is undefined or a superset of the emblem's `emb.prp` claim.
* The endorsement's `emb.dst` claim is undefined or a superset of the emblem's `emb.dst` claim.
* The endorsement's `emb.assets` claim is undefined or for each AI within the emblem's `emb.assets` claim, there exists an AI within the endorsement's `emb.assets` claim which is more general than the emblem's `emb.assets` claim.
* The endorsement's `emb.wnd` claim is undefined or the sum of emblem's `nbf` and the endorsement's `emb.wnd` claims is greater than or equal to the emblem's `exp` claim.

# Public Key Commitment {#pk-distribution}

Parties must undeniably link their root public keys to their OI.
In this section, we specify the configuration of an emblem issuer's OI.
Root public keys are all public keys which are only endorsed by third parties and never endorsed by the organization itself.
A party MAY have multiple root public keys.
For a root public key to be configured correctly, there MUST be an X.509 certificate that:

* MUST NOT be revoked
* MUST be logged in the Certificate Transparency logs {{!RFC6962}}, {{!RFC9162}}
  * Note that log inclusion requires a valid certificate chain that leads to
  one of the log's accepted root certificates. Clients are RECOMMENDED to verify
  that this chain is valid and that none of the certificates along it have been
  revoked.
* MUST be valid for at least all the following domains (`<OI>` is understood to be a placeholder for the domain name in the party's OI):
  * `adem-configuration.<OI>`
  * For the textual representation `<KID>` of the root public key's key identifier, as specified in {{key-formats}}: `<KID>.adem-configuration.<OI>`

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
A validity checking algorithm MUST return the following values.
The order of these values encodes the *strength* of the verification result.

1. `INVALID`
2. `SIGNED-UNTRUSTED`
3. `SIGNED-TRUSTED`
4. `ORGANIZATIONAL-UNTRUSTED`
5. `ORGANIZATIONAL-TRUSTED`
6. `ENDORSED-UNTRUSTED`
7. `ENDORSED-TRUSTED`

Given an input public key and an emblem with a set of endorsements, a verification algorithm takes the following steps:

1. Run the *signed emblem verification procedure* ({{signed-emblems}}; results in one of `SIGNED-TRUSTED`, `SIGNED-UNTRUSTED`, or `INVALID`).
2. If previous procedure resulted in `INVALID` or the emblem does not include the `iss` claim, return the last verification procedure's result and the empty set of OIs.
3. Run the *organizational emblem verification procedure* ({{org-emblems}}; results in one of `ORGANIZATIONAL-TRUSTED`, `ORGANIZATIONAL-UNTRUSTED`, `INVALID`).
4. If the previous procedure resulted in `INVALID` return `INVALID` and the empty set of OIs.
5. If all tokens include the same `iss` claim, return the strongest return value matching `*-TRUSTED`, the strongest return value matching `*-UNTRUSTED` provided that it is strictly stronger than the strongest return value matching `*-TRUSTED`, and the empty set of OIs.
6. Run the *endorsed emblem verification procedure* ({{endorsed-emblems}}; results in a set of OIs and one of `ENDORSED-TRUSTED`, `ENDORSED-UNTRUSTED`, `INVALID`).
7. If the previous procedure resulted in `INVALID` return `INVALID` and the empty set of OIs.
8. Return the strongest return value matching `*-TRUSTED`, the strongest return value matching `*-UNTRUSTED` provided that it is strictly stronger than the strongest return value matching `*-TRUSTED`, and the set of OIs returned by the endorsed emblem verification procedure.

Note that the endorsed emblem verification procedure resulting in `INVALID` is handled implicitly in step 8.
As the procedure did not terminate in step 5, organizational verification must have been successful.
Hence, `INVALID` cannot be the strongest return value, and an emblem not being accompanied by valid endorsements is downgraded to organizational emblems.

The set of OIs returned by the verification procedure encodes the OIs of endorsing parties where verification passed.

### Comments on Trust Policies

We strongly RECOMMEND against accepting emblems resulting in `SIGNED-UNTRUSTED`.
In such cases, validators should aim to authenticate the respective public keys via other, out-of-band methods.
This effectively lifts the result to `SIGNED-TRUSTED`.
Signed emblems are supported for cases of emergency where an emblem issuer is able to communicate one or more public keys, but might not be able to set up a signing infrastructure linking their assets to a root key.

There is no definite guideline on how to choose which keys to trust, i.e., which keys to pass as trusted public key to the verification procedure.
Some validators may have pre-existing trust relationships with some authorities, e.g., military units of a nation state could use the public keys of their nation state or allies.
Other validators might be fine with fetching public keys authenticated only by the web PKI.

## Protection

An emblem for which the verification procedure produces a result other than `INVALID` marks any asset whose address is identified by at least one of the emblem's AIs.
Such an emblem signals that the respective asset enjoys the specific protections of IHL.

Emblem issuers MUST only issue emblems for assets that are used only for protected purposes.

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
There are endorsements as part of the input including an `iss` claim different to the emblem's `iss` claim.
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

The constraints on well-configured OIs offer two beneficial security properties:

* Parties cannot equivocate their keys, i.e., they need to commit to a consistent set of keys.
* Parties cannot deny having used certain root public keys.

These properties stem from parties needing to include a hash of their key in a TLS certificate, and consequently, in certificate transparency logs.

## Token Order

As specified in {{signed-emblems}}, clients MAY reject sets of tokens as invalid if the order of tokens as indicated by the sending client does not yield a valid chain of endorsements.
This allows an adversary to force rejection of a set of tokens by altering, e.g., sequence numbers on non-integrity protected channels.

However, this does not constitute a new attack.
Such adversaries could flip a bit in the emblem's signature, rendering the set of tokens invalid, too.

## Key Identifiers

Key identifiers were designed such that they commit to the identified key, i.e., key identifiers must provide strong collision-resistance.
This is ensured by computing it using SHA-256.

# IANA Considerations

TODO

--- back
