// Package arc implements ARC (Authenticated Received Chain, RFC 8617)
// signing and verification.
//
// ARC preserves email authentication results across forwarding
// intermediaries (mailing lists, forwarders). Each intermediary that
// handles a message adds one "ARC set" — three headers sharing an
// instance number (i=N):
//
//   - ARC-Authentication-Results (AAR): the authentication results
//     (SPF, DKIM, DMARC, prior ARC) observed when the message arrived
//   - ARC-Message-Signature (AMS): a DKIM-style signature over the
//     message as forwarded
//   - ARC-Seal (AS): a signature over ALL ARC header fields of every
//     instance so far, making the chain tamper-evident
//
// The signer and verifier in this package are two directions of the
// same computation and are tested against each other; the verifier is
// additionally exercised against real-world ARC chains.
//
// Signing requires the authentic ingress authentication results: the
// sealer's AAR must state what the receiving edge of the ADMD observed
// (RFC 8617 §5.1.1). Sign therefore refuses to operate without an
// AuthResults value — fabricating one would defeat the whole mechanism.
package arc

import (
	"context"
	"errors"
	"net"
	"time"
)

// MaxChainLength is the largest ARC instance number this package will
// extend or accept. RFC 8617 §4.2.1 sets 50 as the upper bound.
const MaxChainLength = 50

// ErrChainLimit is returned by Sign when the message already carries an
// ARC chain at the maximum instance. The caller should forward the
// message without adding an ARC set.
var ErrChainLimit = errors.New("arc: chain already at maximum instance, refusing to extend")

// ErrMalformedChain is returned by Sign when ARC headers are present
// but so damaged that no instance number can be assigned honestly (for
// example, every i= tag is missing or unparseable). The caller should
// forward the message without adding an ARC set.
var ErrMalformedChain = errors.New("arc: existing ARC headers are unusable, refusing to extend")

// ChainStatus is the cv= value of an ARC-Seal.
type ChainStatus string

const (
	ChainNone ChainStatus = "none" // first hop: no prior chain existed
	ChainPass ChainStatus = "pass" // prior chain validated
	ChainFail ChainStatus = "fail" // prior chain present but invalid
)

// LookupTXT resolves a DNS name to its TXT records. Verification and
// chain-aware signing need it to fetch public keys; tests inject a stub.
type LookupTXT func(name string) ([]string, error)

// DefaultLookupTXT resolves TXT records with a 10-second timeout using
// the system resolver.
func DefaultLookupTXT(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupTXT(ctx, name)
}
