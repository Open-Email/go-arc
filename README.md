# go-arc

ARC (Authenticated Received Chain, [RFC 8617](https://www.rfc-editor.org/rfc/rfc8617)) signing and verification for Go.

ARC preserves email authentication results across forwarding hops. Each intermediary adds one **ARC set** — `ARC-Authentication-Results` (what its receiving edge observed), `ARC-Message-Signature` (a DKIM-style signature over the message), and `ARC-Seal` (a signature over *every* ARC header of every instance so far, making the chain tamper-evident).

This library is the shared ARC engine of the OpenEmail platform: the signer runs in the forwarding path (`openemail-smtp-out`), the verifier at the receiving edge (`openemail-smtp-in`). Signer and verifier are two directions of the same computation, kept in one package so they cannot drift.

## Verify

```go
result, err := arc.Verify(rawMessage, &arc.VerifyOptions{
    LookupTXT: arc.DefaultLookupTXT, // inject a stub in tests
})
// result.Pass, result.Instance, result.FailureReasons
```

A message with no ARC headers passes once the verifier has scanned the complete header block. Exceeding the 10,000-field scan limit produces a failed result. A chain passes only if every instance 1..N is complete, every `cv=` is semantically valid (`none` at i=1, `pass` above, any `fail` is fatal), and every signature verifies.

`result.Instances` reports what each set in the chain *claims* — oldest first, and populated for failing chains too:

```go
for _, inst := range result.Instances {
    // inst.Instance, inst.Sealer (ARC-Seal d=), inst.Signer (AMS d=),
    // inst.ChainStatus (cv=), inst.AuthResults (the AAR, i= stripped)
}
oldest, ok := result.OldestAuthResults() // the i=1 AAR
```

`Pass` alone cannot support a trust decision, which is why this exists. RFC 8617 §5.2 verifies only the **newest** `ARC-Message-Signature`, so an attacker can take a genuinely sealed message, replace the body, append their own set with `cv=pass`, and the chain still validates. Anything acting on a chain's contents — an RFC 8617 §7.2.1 DMARC override, say — must check **every** `Sealer` against its own trust list, and must read the **oldest** AAR: only the i=1 hop received the message from its originator, so every later AAR describes a forwarder instead. `LatestARCAuthResults` is the signer's header and the wrong one for this.

## Sign

```go
authRes, ok := arc.CombinedAuthenticationResults(rawMessage, "mx.example.com")
if !ok {
    // No edge-stamped Authentication-Results — forward without sealing.
}
res, err := arc.Sign(rawMessage, &arc.SignConfig{
    Domain:      "example.com",  // d=: the forwarding platform's domain
    Selector:    "arc1",
    PrivateKey:  key,            // RSA; DKIM-style TXT record at arc1._domainkey.example.com
    AuthResults: authRes,        // REQUIRED: the ingress observations
})
// res.Message has the new ARC set prepended; res.Instance, res.CV
```

The signing domain and selector accept internationalized DNS labels such as `bücher.example`. The signer always writes them to `d=` and `s=` as A-labels, such as `xn--bcher-kva.example`: RFC 8616 §4 permits U-labels in an internationalized message, but a verifier that does not convert them would look the key up under a name that holds none. Verification converts U-labels to A-labels for the key lookup, and uses an ASCII name as written. [RFC 8616 §4](https://www.rfc-editor.org/rfc/rfc8616#section-4)

`CombinedAuthenticationResults` recognizes token and quoted forms of the configured service ID. It preserves spaces and tabs inside quoted results when collecting the fields for sealing. A fold inside a quoted service ID must decode identically at ingress and egress. For the OpenEmail ingress parser, a continuation starting with one space meets that requirement. [RFC 8601 §2.2](https://www.rfc-editor.org/rfc/rfc8601#section-2.2)

Design decisions, all load-bearing:

- **`AuthResults` is required.** Use `CombinedAuthenticationResults` to collect all version 1 assessments from the configured authentication service into one AAR, including when the service stamped separate fields for SPF and DKIM. The receiving edge must remove inbound fields claiming its own authserv-id before stamping its results. Fields from other services are excluded. `FindAuthenticationResults` remains available for callers that need only the topmost matching field. [RFC 8617 §4.1.1](https://www.rfc-editor.org/rfc/rfc8617#section-4.1.1)
- **`cv=` is computed, never assumed.** With prior sets present, the chain is validated (DNS required) and the seal declares the true result. On `fail`, the seal covers only the sealer's own set (§5.1.2).
- **The seal is hand-computed, not borrowed from a DKIM signer.** It covers all prior ARC sets plus the new AAR and AMS, relaxed-canonicalized in instance order, and carries exactly the tags §4.1.3 allows: `i, a, b, cv, d, s, t` — no `bh=`, no `h=`, no `c=`, no `v=`.
- **Everything signed is exactly what is emitted.** Headers are folded before hashing and the `b=` value is spliced into a frozen layout, so a verifier reconstructing the signed input gets identical bytes.
- **Refusals over guesses.** A chain at instance 50 (`ErrChainLimit`), ARC headers too damaged to number honestly (`ErrMalformedChain`), a header block that mail software reads in more than one way (`ErrMalformedMessage`) or results that cannot be folded under 998 bytes (`ErrLineTooLong`) mean: forward without sealing.
- **A header block must read the same everywhere.** Every line of it has to be a header field (a printable ASCII name directly followed by a colon) or the continuation of one, with no CR outside a line break. A line such as `Subject<FF>: x`, a line of CRs, a line with no colon or a name with a space before its colon is a Subject, a continuation or the end of the headers to one parser and not to another. `Sign` refuses such a message and `Verify` fails any chain on it. The body is not covered by this: relaxed body canonicalization lets white space at line ends change, and a bare LF is read as a line break.
- **Signed names are oversigned.** The AMS lists `From`, `Sender`, `To`, `Cc`, `Reply-To`, `Subject`, `Date`, `Message-ID`, `In-Reply-To`, `References`, `MIME-Version`, `Content-Type`, `Content-Transfer-Encoding` and `Content-Disposition` once per field present and once more (RFC 6376 §5.4, §8.15). A field of one of those names added after sealing, whether a second copy or one the message never had, breaks the signature. This protects seals made here; a chain sealed elsewhere is only as tight as its own `h=` list.

Use `arc.SignTransformed(original, outbound, cfg)` after modifying a message.
Set `cfg.AuthResults` from the original ingress observations. The function validates any
prior ARC chain against `original` and signs the final `outbound` bytes. It requires
the same ARC headers in the same order and returns an error if the prior chain
cannot validate. An incomplete scan of the original returns `ErrMalformedMessage`.

## Testing

```sh
go test ./...                    # offline: round-trips, tamper/strip negatives, tag shape
GOARC_LIVE_DNS=1 go test ./...   # + cryptographic verification of a real Gmail ARC chain
```

The suite pins the property naive implementations miss: **stripping a prior ARC set must break every later seal**. Cross-validation status: the verifier passes Google's real ARC chain (live DNS); chains produced by the signer are accepted by [dkimpy](https://launchpad.net/dkimpy)'s independent `arc_verify` (`cv=pass`, all signatures valid).
