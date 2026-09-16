---
title: "An Authentic Digital, Distinctive EMblem (ADEM) - Message Format and Authorization Model"
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

In times of armed conflict, the emblems recognized under International Humanitarian Law (IHL), such as the red cross, red crescent, and red crystal, are used to mark physical assets.
This enables, e.g., the military to identify assets that enjoy the specific protections under IHL during their operations.
This draft specifies the message format and authorization model for a digital emblem, which signals that network-connected services enjoy specific protections under IHL.

--- middle

# Introduction

International Humanitarian Law (IHL) awards specific protections to certain assets, in particular, medical facilities.
These protections require that assets must be respected and protected, and in particular that assets must not be disrupted.
The distinctive emblems recognized under IHL, for example, the Red Cross, can signal an assets status under IHL.
But naturally, these emblems are visual and are thus limited to assets with which one interacts primarily physically, e.g., buildings.
There is currently no way to signal over the network layer that a network-connected asset enjoys specific protections under IHL, which can be a channel of disruption, however.

This draft addresses the above problem and specifies a message format and authorization model for the distinctive emblems recognized under IHL so that they can be conveyed on the network layer.
Other drafts will specify how these messages will be conveyed over the network and which assets will be identified as enjoying specific protections under IHL.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

**Asset**
: An asset is a network-connected service that enjoys the specific protections under IHL.

**Emblem**
: An emblem is a message which signals that an asset enjoys specific protections under IHL.

**Emblem issuer**
: An emblem issuer is an organization that issues emblems.

**Authority**
: An authority is an organization that authorizes other organizations as being eligible to issue emblems.

**Endorsement**
: An endorsement associates a public key with an identity, and hence, resembles the idea of a certificate.
When signed by an authority, it attests that the authorized issuer can generally issue claims of protection.

**Token**
: An emblem or an endorsement.

**Organization**
: An emblem issuer or authority.

**Root Key**
: Organizations control root keys, which identify them cryptographically.
Any key that an organization commits to as described in {{pk-distribution}} is a root key.

**Validator**
: A validator is someone who discovers and validates digital emblems.

Beyond these terms, we use the terms "claim", "claim key", "claim value", and "CWT Claims Set" as defined in {{!RFC8392}}, and "header parameter" as defined in {{!RFC9052}}.

# Overview

This document specifies the digital message format and authorization model for an authentic digital, distinctive emblem recognized under IHL.
Emblems signal that one or more asset enjoys specific protections under IHL, and endorsements encode that one organization authorizes another to issue emblems.
Both emblems and endorsements are called *tokens* and encoded as signed CBOR Web Tokens (CWTs) {{!RFC8392}}.
Emblems are signed by emblem issuers and endorsements are signed by emblem issuers and authorities.

Endorsements also allow for authenticating public key material for verifying token signatures.
Any organization, emblem issuer or authority, is identified by a domain name and one or more root public keys, which they can use to sign endorsements.
Organizations must bind this root public key to the domain name identifying as specified in {{pk-distribution}}.

In the following, we describe (i) how to encode public key material for the use in ADEM as COSE_Keys ({{key-formats}}), (ii) the format of tokens ({{tokens}}), (iii) how organizations must bind their root public keys to the domain name identifying them ({{pk-distribution}}), and (iv) how emblems and associated endorsements are validated ({{validation}}).

This draft does not specify how tokens are presented, and how they identify which asset enjoys specific protections under IHL.
Different types of assets, e.g., a patient database and a network-connected medical device, use different network channels and digital emblems should be both conveyed over the respective channels and use identifiers for the marked assets that match these channels.

## Requirements

ADEM was designed to provide the following requirements.
We highlight three requirements in particular that informed the writing of this draft.

1. Digital emblems should usable for a wide range of network-connected services.
We thus encode emblems in binary, as CWTs. so that they can - in principle - be integrated into many existing, different protocols.
2. The use of the distinctive emblems requires authorization by a competent authority; typically a state.
States are the ultimate authority under IHL and must be able to operate independently of one another.
Authorities thus require no further authentication, integration into root trust stores, or anything similar.
Instead, we require that authorities commit to their public key material so that they can be held accountable when issuing fraudulent endorsements (see {{pk-distribution}} and {{accountability}}).
3. As explained in {{!I-D.ietf-diem-requirements-03}}, the validation of digital, distinctive emblems should be undetectable.
While this draft alone cannot provide undetectable validation, we ensure that undetectable validation is not precluded.
In particular, we designed the emblem message format and authorization so that an emblem and associated endorsements can be validated mostly without follow-up queries (see also {{undet-validation}}).

# Public Key Material {#key-formats}

Public keys are encoded as COSE_Key structures {{!RFC9052}}.
We identify keys using key identifiers, which are 32-byte SHA-256 COSE Key Thumbprints, computed as specified in {{!RFC9679}}.
To force computation and thus verification of key identifiers, COSE_Key structures SHOULD NOT contain the `kid` parameter (label 2).
Implementations that encode key material MUST NOT include the `kid` parameter, but implementations consuming key material SHOULD accept and ignore the `kid` parameter.

Key identifiers are encoded as a CBOR byte string when used as the COSE `kid` header parameter or as a CWT claim value.
When a textual representation is required, key identifiers are encoded using base32 as specified in {{!RFC4648}}, in lowercase and without trailing `=` characters.

# Tokens {#tokens}

## Organization Identifiers

Emblems are issued for assets by emblem issuers, which in turn are authorized by authorities.
Emblem issuers and authorities are identified by Uniform Resource Identifiers (URIs) {{!RFC3986}} of the following form, which we call *organization identifiers* (OIs).
The scheme MUST be `https`.
The authority component MUST contain a fully qualified domain name (FQDN), which MUST be represented in all lower-case.
The path, query, and fragment components MUST be empty, and the URI MUST NOT end with a trailing slash.
Concretely, an OI has the syntax:

~~~~
organization-identifier = "https://" FQDN
~~~~

## Token Encoding

Tokens MUST be encoded as CWTs {{!RFC8392}} secured by a COSE_Sign1 structure {{!RFC9052}}, and tokens MUST include the CWT CBOR tag 61 and the COSE_Sign1 CBOR tag 18.
The COSE payload MUST be present and MUST contain the CBOR-encoded CWT Claims Set.
External additional authenticated data MUST be the zero-length byte string.

The CWT Claims Set MUST be a CBOR map.
Registered CWT claims use their integer claim keys from {{!RFC8392}}; claims defined by this document use the text-string claim keys shown below.

### Common Token Fields {#common-token-fields}

Both emblems and endorsements use the following protected header parameters and CWT claims.
Implementations generating tokens MUST NOT include header parameters or CWT claims beyond those referenced in this document.

The COSE protected header MUST include the `alg` (label 1) and `kid` (label 4) header parameters.
The `alg` value identifies the signature algorithm.
The `kid` value MUST equal the key identifier of the verification key as specified in {{key-formats}}.

The protected header MAY include the `typ` (label 16, see {{!RFC9596}}) header parameter with the value `"application/adem"`.
Where clear from context, the `typ` parameter MAY be omitted.

The COSE unprotected header MUST be empty.

| Claim | Claim key | Status | Semantics | CBOR type |
| ----- | --------- | ------ | --------- | --------- |
| `ver` | `"ver"` | REQUIRED | Version counter | uint, value 1 |
| `iat` | 6 | OPTIONAL | Issued-at time, as per {{!RFC8392}} | NumericDate |
| `nbf` | 5 | REQUIRED | Not-before time, as per {{!RFC8392}} | NumericDate |
| `exp` | 4 | REQUIRED | Expiration time, as per {{!RFC8392}} | NumericDate |
| `iss` | 1 | RECOMMENDED | Organization issuing the token | tstr containing an OI |
| `prp` | `"prp"` | REQUIRED | Emblem purposes | uint |

The token version counter `ver` MUST be an unsigned integer in the range 0 to 255, encoded as a CBOR unsigned integer.
This document specifies version 1.

For an emblem, `iss` identifies the organization signaling protection; for an endorsement, it identifies the endorsing organization.

The `prp` claim identifies the kind of emblem recognized under IHL as a bitmap and MUST be non-zero.
Each bit, as indicated below, corresponds to a particular use of emblems recognized under IHL.
Values MAY be combined, using bit-wise OR, to indicate the use of multiple emblems at the same time.
Consequently, the value of the `prp` field MUST be between 1 and 31.
The semantics of the `prp` claim differ between emblems and endorsements and will be specified later.

| Value | Explanation |
| ----- | ----------- |
| `0b_0000_0001` | Protective use of the red cross, red crescent, or red crystal emblem to signal protection under IHL. |
| `0b_0000_0010` | Indicative use of the red cross, red crescent, or red crystal emblem to signal an affiliation with the International Red Cross and Red Crescent Movement. |
| `0b_0000_0100` | Identification of works and installations containing dangerous forces, such as dams, dykes, and nuclear electrical generating stations. |
| `0b_0000_1000` | Identification of civil defence organizations and their protected personnel and assets. |
| `0b_0001_0000` | Identification of cultural property protected under IHL. |

### Emblems {#emblems}

An emblem's CWT Claims Set includes the common claims defined in {{common-token-fields}} and the additional claim defined in the table below.

| Claim | Claim key | Status | Semantics | CBOR type |
| ----- | --------- | ------ | --------- | --------- |
| `assets` | `"assets"` | REQUIRED | Assets marked as protected | array |

The `assets` claim contains asset identifiers.
Their syntax, encoding, and matching semantics will be defined in separate drafts that specify discovery and distribution of tokens.
The asset identifier in the example below is illustrative.

An emblem's `prp` claim specifies how the asset is marked.
For example, when the claim has value 1, it indicates that the asset is marked with the digital equivalent to the emblems of the Red Cross, Red Crescent, and Red Crystal.

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
  / nbf / 5: 1672916137,
  / exp / 4: 1675590932,
  / iss / 1: "https://example.com",
  "assets": ["example.com"],
  "prp": 1
}
~~~~

### Endorsements {#endorsements}

Endorsements are encoded as signed CWTs.
Endorsements attest two statements: that a public key is affiliated with an organization, identified by an OI, and that this organization is authorized to issue emblems for their assets.
An endorsement's CWT Claims Set includes the common claims defined in {{common-token-fields}} and the additional claims defined in the table below.

| Claim | Claim key | Status | Semantics | CBOR type |
| ----- | --------- | ------ | --------- | --------- |
| `sub` | 2 | RECOMMENDED | Endorsed organization, identified by their OI | tstr |
| `key` | `"key"` | REQUIRED | Endorsed organization's public key thumbprint | bstr |
| `end` | `"end"` | REQUIRED | Endorsed key can endorse further | bool |
| `log` | `"log"` | see below | Root key commitment | array of maps as below |

An endorsement's `prp` claim constrains what kind of emblems the endorsed organization may issue.
Each bit set in the `prp` claim gives the endorsed organization permission to issue the respective emblem.
An emblem is thus *valid* with respect to an endorsement if the bit-wise AND of the endorsement's `prp` claim and the emblem's `prp` claim is equal to the emblem's `prp` claim.

We say that an endorsement *endorses* a token if its `key` claim equals the key identifier of the token's verification key, and its `sub` claim equals the token's `iss` claim.
Note that the latter includes the possibility of both `sub` and `iss` being undefined.

Endorsements MAY contain the `log` claim.
If an endorsement was signed by a root key, it MUST include the `log` claim.
The `log` claim identifies the CT logs that contain a binding certificate for the endorsement's verification key.
The value of `log` is an array of CBOR maps, each of which identifies a CT log entry that commits to the organization's root signing key (see {{pk-distribution}}).
This standard supports log entries of both standard CT logs as specified in {{!RFC6962}} and tiled CT logs as specified in {{STATIC-CT}}.

| Entry | Map key | Status | Semantics | CBOR type |
| ----- | ------- | ------ | --------- | --------- |
| `id`  | `"id"` | REQUIRED | The CT log's ID | bstr |
| `hash` | `"hash"` | see below | The binding certificate's leaf hash in the log | bstr |
| `index` | `"index"` | see below | The binding certificate's log entry index in the log | uint |

For logs implementing {{!RFC6962}}, a map in `log` MUST include the `hash` entry and MUST NOT include the `index` entry.
For logs implementing {{STATIC-CT}}, a map in `log` MUST include the `index` entry and MUST NOT include the `hash` entry.

# Public Key Commitment {#pk-distribution}

Organizations must undeniably link some of their public keys to their OI, and we specify a public key commitment mechanism in this section to achieve that.
Every public key an organization commits to in this way is a root public key.
An organization MAY have multiple root public keys.
For a root public key to be configured correctly, there MUST be an X.509 certificate that:

* MUST NOT be revoked
* MUST be logged in the Certificate Transparency logs {{!RFC6962}} {{STATIC-CT}}
  * Note that log inclusion requires a valid certificate chain that leads to
  one of the log's accepted root certificates. Clients are RECOMMENDED to verify
  that this chain is valid and that none of the certificates along it have been
  revoked.
* MUST be valid for at least all the following domains while not considering wildcards in the certificate subject (`<OI>` is understood to be a placeholder for the domain name in the organization's OI):
  * `adem-configuration.<OI>`
  * For the textual representation `<KID>` of the root public key's key identifier, as specified in {{key-formats}}: `<KID>.adem-configuration.<OI>`

<!-- TODO: Transform into informative references -->
We intentionally do not specify how clients should check a certificate's revocation status.
It is RECOMMENDED that clients use offline revocation checks that are provided by major browser vendors, for example, [OneCRL or CRLite by Mozilla](https://wiki.mozilla.org/CA/Revocation_Checking_in_Firefox), or [CRLSet by Chrome](https://chromium.googlesource.com/playground/chromium-org-site/+/refs/heads/main/Home/chromium-security/crlsets.md).


# Validation {#validation}

Whenever a validator receives a set of tokens, they SHOULD validate it.
Validation returns one or more of the following values and a set of OIs.
The set of OIs returned by the validation procedure encodes the OIs of endorsing organizations for which validation passed.

1. `INVALID`
2. `SIGNED`
3. `ORGANIZATIONAL`
4. `ENDORSED`

Given a set of tokens and a set of public keys, validation takes the following steps.

1. For every public key, compute its key identifier as described in {{key-formats}}.
2. For every token, perform the following steps:
    1. Verify the token's signature using the public key whose key identifier computed in the previous step matches the `kid` header parameter.
    2. Verify the token's `nbf` and `exp` claims.
    3. Should either of the aforementioned validation steps fail, discard this token.
3. Identify the emblem among the remaining tokens.
The emblem is the token containing an `assets` claim, and it MUST be uniquely defined.
If there is not exactly one token containing an `assets` claim, return `INVALID`.
All other tokens are endorsements.
4. Run the *signed emblem validation procedure* ({{signed-emblems}}; results in one of `SIGNED` or `INVALID`).
5. If the previous procedure resulted in `INVALID` or the emblem does not include the `iss` claim, return the last validation procedure's result and the empty set of OIs.
6. Run the *organizational emblem validation procedure* ({{org-emblems}}; results in one of `ORGANIZATIONAL`, `INVALID`).
7. If the previous procedure resulted in `INVALID`, return `INVALID` and the empty set of OIs.
8. Run the *endorsed emblem validation procedure* ({{endorsed-emblems}}; results in a set of OIs and one of `ENDORSED`, `INVALID`).
9. If the endorsed emblem validation procedure resulted in `INVALID`, return `SIGNED`, `ORGANIZATIONAL` and the empty set of OIs.
Otherwise, return `SIGNED`, `ORGANIZATIONAL`, `ENDORSED`, and the OIs returned by the endorsed emblem validation procedure.

# Algorithms

Each procedure operates on its own copy of the validated token set.
Discarding endorsements within a procedure does not remove them from the inputs to subsequent procedures.

## Signed Emblem Validation Procedure {#signed-emblems}

Context:

* Assumptions: All input tokens' signatures, and `nbf` and `exp` claims were validated.
* Input: An emblem and a set of endorsements.
* Output: `SIGNED` or `INVALID`.

Algorithm:

1. Discard all endorsements including an `iss` claim different to the emblem's `iss` claim.
An omitted `iss` claim is different to an included `iss` claim and equal to an omitted `iss` claim.
2. If no endorsements remain, return `SIGNED`.
Otherwise, verify that all endorsements form a consecutive chain where there is a unique root endorsement and the public key which was used to verify the emblem's signature is transitively endorsed by that root endorsement.
3. Verify that all endorsements bear the claim `end=true` except for the endorsement endorsing the emblem's verification key, the `end` claim of which MAY be `false`.
4. Verify that the emblem is valid with regard to every endorsement.
5. If any of the aforementioned validation steps fail, return `INVALID`.
Otherwise, return `SIGNED`.

## Organizational Emblem Validation Procedure {#org-emblems}

Context:

* Assumptions: All input tokens' signatures, and `nbf` and `exp` claims were validated.
Signed emblem validation has been performed and did not return `INVALID`.
The emblem includes the `iss` claim.
* Input: An emblem and a set of endorsements.
* Output: `ORGANIZATIONAL` or `INVALID`.

Algorithm:

1. Discard all endorsements including an `iss` claim different to the emblem's `iss` claim.
2. If either (a) no endorsements remain, or (b) the remaining endorsements do not form a linear chain, or (c) the top-most endorsement of that chain has no `log` protected header parameter, return `INVALID`.
3. Verify the top-most endorsement's verification public key by using its `iss` claim and `log` header parameter as specified in {{pk-distribution}}.
If verification fails, return `INVALID`.
Otherwise, return `ORGANIZATIONAL`.

## Endorsed Emblem Validation Procedure {#endorsed-emblems}

Context:

* Assumptions: All input tokens' signatures, and `nbf` and `exp` claims were validated.
Organizational emblem validation has been performed and did not return `INVALID`.
* Input: An emblem and a set of endorsements.
* Output: `ENDORSED` or `INVALID`, and a set of OIs.

Algorithm:

1. Discard all endorsements with an `iss` claim equal to the emblem's `iss` claim or with an undefined `iss` claim.
2. For every endorsement:
    1. Verify that it endorses the top-most endorsement with the same `iss` claim as the emblem.
    2. Verify that it bears the claim `end=true`.
    3. Verify that the emblem is valid with regard to this endorsement.
    4. Verify the endorsement's verification public key by using its `iss` claim and `log` header parameter as specified in {{pk-distribution}}.
    5. Should any of the aforementioned validation steps fail, discard this endorsement.
3. If there are no endorsements remaining, return `INVALID` and the empty set of OIs.
Otherwise, return `ENDORSED` and the set of all `iss` claims of the remaining endorsements.

# Security Considerations

## Interpreting Validation Results

Validators SHOULD NOT accept emblems resulting only in `SIGNED` without authenticating their verification keys out of band.
In such cases, validators should aim to authenticate the respective public keys via other, out-of-band methods.
Signed emblems are supported for cases of emergency where an emblem issuer is able to communicate one or more public keys, but might not be able to set up a signing infrastructure linking their assets to a root key.

## Accountability {#accountability}

TODO

### No Endorsements without `iss`

The procedures to verify organizational or endorsed emblems as specified in {{org-emblems}} and {{endorsed-emblems}} assume that the emblem's `iss` claim is defined.
Practically speaking, this implies that one can only go beyond pure public key authentication (where public keys need to be authenticated out-of-band) by stating an OI.

The constraints on well-configured OIs offer two beneficial security properties:

* Organizations cannot equivocate their keys, i.e., they need to commit to a consistent set of keys.
* Organizations cannot deny having used certain root public keys.

These properties stem from organizations needing to include a hash of their key in a TLS certificate, and consequently, in certificate transparency logs.

## Undetectable Validation {#undet-validation}

TODO

# IANA Considerations

TODO

--- back
