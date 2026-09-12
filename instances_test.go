package arc

import (
	"strings"
	"testing"
)

// TestInstancesReportEverySealer pins the property a DMARC override depends
// on: a two-hop chain reports BOTH sealers, oldest first. A caller that saw
// only the newest one would be trusting a set an attacker can always append.
func TestInstancesReportEverySealer(t *testing.T) {
	msg, lookup := testChain(t, 2)
	res := mustVerify(t, msg, lookup)
	if !res.Pass {
		t.Fatalf("expected the chain to pass, got %+v", res)
	}
	if len(res.Instances) != 2 {
		t.Fatalf("Instances = %d entries, want 2: %+v", len(res.Instances), res.Instances)
	}

	want := []struct {
		instance int
		sealer   string
		cv       ChainStatus
		authRes  string
	}{
		{1, "forward-a.example", ChainNone, authResultsA},
		{2, "forward-b.example", ChainPass, authResultsB},
	}
	for i, w := range want {
		got := res.Instances[i]
		if got.Instance != w.instance {
			t.Errorf("Instances[%d].Instance = %d, want %d", i, got.Instance, w.instance)
		}
		if got.Sealer != w.sealer {
			t.Errorf("Instances[%d].Sealer = %q, want %q", i, got.Sealer, w.sealer)
		}
		if got.Signer != w.sealer {
			t.Errorf("Instances[%d].Signer = %q, want %q", i, got.Signer, w.sealer)
		}
		if got.ChainStatus != w.cv {
			t.Errorf("Instances[%d].ChainStatus = %q, want %q", i, got.ChainStatus, w.cv)
		}
		if got.AuthResults != w.authRes {
			t.Errorf("Instances[%d].AuthResults = %q, want %q", i, got.AuthResults, w.authRes)
		}
	}
}

// TestOldestInstanceIsNotTheLatest is the whole point of the accessor: on a
// multi-hop chain the oldest AAR describes the ORIGINAL sender and the newest
// describes the previous forwarder. Reading the wrong one answers a different
// question, so the two helpers must visibly disagree.
func TestOldestInstanceIsNotTheLatest(t *testing.T) {
	msg, lookup := testChain(t, 2)
	res := mustVerify(t, msg, lookup)

	oldest, ok := res.OldestInstance()
	if !ok {
		t.Fatal("OldestInstance() found no i=1 set")
	}
	if oldest.Instance != 1 || oldest.Sealer != "forward-a.example" {
		t.Errorf("OldestInstance() = %+v, want i=1 sealed by forward-a.example", oldest)
	}

	oldestAAR, ok := res.OldestAuthResults()
	if !ok {
		t.Fatal("OldestAuthResults() returned nothing")
	}
	if oldestAAR != authResultsA {
		t.Errorf("OldestAuthResults() = %q, want %q", oldestAAR, authResultsA)
	}
	// The oldest AAR is the only one carrying the originator's DMARC result.
	if !strings.Contains(oldestAAR, "dmarc=pass header.from=origin.example") {
		t.Errorf("oldest AAR lost the originator's DMARC result: %q", oldestAAR)
	}

	latestInstance, latestAAR, ok := LatestARCAuthResults(msg)
	if !ok {
		t.Fatal("LatestARCAuthResults() returned nothing")
	}
	if latestInstance != 2 || latestAAR != authResultsB {
		t.Errorf("LatestARCAuthResults() = (%d, %q), want (2, %q)", latestInstance, latestAAR, authResultsB)
	}
	if latestAAR == oldestAAR {
		t.Error("oldest and newest AAR are identical; the fixture no longer exercises the distinction")
	}
}

// TestInstancesOnFirstHop covers the common single-hop chain: one entry,
// cv=none, and the oldest set is also the newest.
func TestInstancesOnFirstHop(t *testing.T) {
	msg, lookup := testChain(t, 1)
	res := mustVerify(t, msg, lookup)
	if len(res.Instances) != 1 {
		t.Fatalf("Instances = %+v, want exactly one entry", res.Instances)
	}
	inst := res.Instances[0]
	if inst.Instance != 1 || inst.Sealer != "forward-a.example" || inst.ChainStatus != ChainNone {
		t.Errorf("Instances[0] = %+v, want i=1 forward-a.example cv=none", inst)
	}
	if inst.AuthResults != authResultsA {
		t.Errorf("Instances[0].AuthResults = %q, want %q", inst.AuthResults, authResultsA)
	}
}

// TestNoARCHeadersReportsNoInstances keeps the "nothing to validate" pass
// honest: it passes with an empty report, not with a fabricated entry.
func TestNoARCHeadersReportsNoInstances(t *testing.T) {
	res, err := Verify([]byte(baseMessage), &VerifyOptions{LookupTXT: dnsStub(nil)})
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}
	if !res.Pass || res.Instance != 0 {
		t.Fatalf("expected a pass at instance 0, got %+v", res)
	}
	if len(res.Instances) != 0 {
		t.Errorf("Instances = %+v, want none", res.Instances)
	}
	if _, ok := res.OldestInstance(); ok {
		t.Error("OldestInstance() reported a set on a message with no ARC headers")
	}
	if _, ok := res.OldestAuthResults(); ok {
		t.Error("OldestAuthResults() reported a payload on a message with no ARC headers")
	}
}

// TestInstancesReportedOnAFailingChain is what makes the report usable for
// logging a refusal: a chain broken by a stripped set still names who sealed
// the sets that remain.
func TestInstancesReportedOnAFailingChain(t *testing.T) {
	msg, lookup := testChain(t, 2)
	// Drop instance 1 entirely — the classic downgrade attempt.
	headers, body := splitMessage(string(msg))
	var sb strings.Builder
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h.key), "arc-") && h.instance == 1 {
			continue
		}
		sb.WriteString(h.raw)
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)

	res := mustVerify(t, []byte(sb.String()), lookup)
	if res.Pass {
		t.Fatal("a chain missing instance 1 must not pass")
	}
	if len(res.Instances) != 1 || res.Instances[0].Instance != 2 {
		t.Fatalf("Instances = %+v, want the surviving i=2 set", res.Instances)
	}
	if res.Instances[0].Sealer != "forward-b.example" {
		t.Errorf("surviving sealer = %q, want forward-b.example", res.Instances[0].Sealer)
	}
	if _, ok := res.OldestInstance(); ok {
		t.Error("OldestInstance() invented an i=1 set that is not in the message")
	}
}

// TestInstancesReportAppendedSetSeparately is the attack RFC 8617 §5.2 leaves
// open: only the NEWEST ARC-Message-Signature is verified, so an attacker can
// append their own set to a genuinely sealed message and the chain still
// validates. The report must show their domain as a distinct sealer — that is
// the only signal a caller has to refuse the chain.
func TestInstancesReportAppendedSetSeparately(t *testing.T) {
	// A genuine first hop, then a second set from an unrelated domain.
	ka, _, kc := testKeys(t)
	lookup := dnsStub(map[string]string{
		"sel-a._domainkey.forward-a.example": txtFor(t, ka),
		"sel-x._domainkey.attacker.example":  txtFor(t, kc),
	})
	first, err := Sign([]byte(baseMessage), signConfig(ka, "forward-a.example", "sel-a", authResultsA, lookup))
	if err != nil {
		t.Fatalf("first hop: %v", err)
	}
	appended, err := Sign(first.Message, signConfig(kc, "attacker.example", "sel-x",
		"mx.attacker.example; dmarc=pass header.from=origin.example", lookup))
	if err != nil {
		t.Fatalf("appended hop: %v", err)
	}
	if appended.CV != ChainPass {
		t.Fatalf("appended set declared cv=%s, want pass (the attack depends on it)", appended.CV)
	}

	res := mustVerify(t, appended.Message, lookup)
	if !res.Pass {
		t.Fatalf("the appended chain must still VALIDATE — that is the hazard: %+v", res)
	}
	if len(res.Instances) != 2 {
		t.Fatalf("Instances = %+v, want two entries", res.Instances)
	}
	if res.Instances[1].Sealer != "attacker.example" {
		t.Errorf("Instances[1].Sealer = %q, want attacker.example", res.Instances[1].Sealer)
	}
	// And the oldest AAR is still the genuine one, so a caller checking only
	// the oldest set — without also checking every sealer — would be fooled.
	oldest, _ := res.OldestInstance()
	if oldest.Sealer != "forward-a.example" || oldest.AuthResults != authResultsA {
		t.Errorf("oldest set = %+v, want the genuine forward-a.example set", oldest)
	}
}
