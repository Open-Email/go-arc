# go-arc

ARC (Authenticated Received Chain, [RFC 8617](https://www.rfc-editor.org/rfc/rfc8617)) signing and verification for Go. Pure stdlib — no dependencies.

ARC preserves email authentication results across forwarding hops. Each intermediary adds one **ARC set** — `ARC-Authentication-Results` (what its receiving edge observed), `ARC-Message-Signature` (a DKIM-style signature over the message), and `ARC-Seal` (a signature over *every* ARC header of every instance so far, making the chain tamper-evident).

This library is the shared ARC engine of the OpenEmail platform: the signer runs in the forwarding path (`openemail-smtp-out`), the verifier at the receiving edge (`openemail-smtp-in`). Signer and verifier are two directions of the same computation, kept in one package so they cannot drift.

## Verify

```go
result, err := arc.Verify(rawMessage, &arc.VerifyOptions{
    LookupTXT: arc.DefaultLookupTXT, // inject a stub in tests
})
// result.Pass, result.Instance, result.FailureReasons
```

A message with no ARC headers passes (nothing to validate). A chain passes only if every instance 1..N is complete, every `cv=` is semantically valid (`none` at i=1, `pass` above, any `fail` is fatal), and every signature verifies.

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
authRes, ok := arc.FindAuthenticationResults(rawMessage, "mx.example.com")
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

Design decisions, all load-bearing:

- **`AuthResults` is required.** The AAR must carry what the ADMD's receiving edge actually observed (§5.1.1) — the edge stamps `Authentication-Results`, the message carries it to the egress, `FindAuthenticationResults` extracts it. A sealer with nothing to report must not seal; fabricated verdicts defeat the mechanism.
- **`cv=` is computed, never assumed.** With prior sets present, the chain is validated (DNS required) and the seal declares the true result. On `fail`, the seal covers only the sealer's own set (§5.1.2).
- **The seal is hand-computed, not borrowed from a DKIM signer.** It covers all prior ARC sets plus the new AAR and AMS, relaxed-canonicalized in instance order, and carries exactly the tags §4.1.3 allows: `i, a, b, cv, d, s, t` — no `bh=`, no `h=`, no `c=`, no `v=`.
- **Everything signed is exactly what is emitted.** Headers are folded before hashing and the `b=` value is spliced into a frozen layout, so a verifier reconstructing the signed input gets identical bytes.
- **Refusals over guesses.** A chain at instance 50 (`ErrChainLimit`) or ARC headers too damaged to number honestly (`ErrMalformedChain`) mean: forward without sealing.

## Testing

```sh
go test ./...                    # offline: round-trips, tamper/strip negatives, tag shape
GOARC_LIVE_DNS=1 go test ./...   # + cryptographic verification of a real Gmail ARC chain
```

The suite pins the property naive implementations miss: **stripping a prior ARC set must break every later seal**. Cross-validation status: the verifier passes Google's real ARC chain (live DNS); chains produced by the signer are accepted by [dkimpy](https://launchpad.net/dkimpy)'s independent `arc_verify` (`cv=pass`, all signatures valid).
