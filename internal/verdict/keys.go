package verdict

import "github.com/A015cc/why-slow/internal/probe/latency"

// Observation keys read by the rules.
//
// The latency probe exports its keys, so those are referenced rather than
// copied. The path, nat and ipv6 probes declare theirs as literals at the
// emission site, so those names are mirrored here and pinned by
// TestPathProbeEmitsExpectedKeys, which drives the real path probe and asserts
// it still emits these exact strings.
//
// The failure being guarded against is a quiet one. A probe renames a key, the
// rule that reads it finds nothing, and the report simply stops mentioning that
// problem: nothing errors, nothing looks broken, and the tool gets worse without
// saying so.
const (
	keyConnect    = latency.KeyConnect
	keyAttempts   = latency.KeyAttempts
	keyTruncated  = latency.KeyTruncated
	keyRefused    = latency.KeyRefused
	keyDialErrors = latency.KeyDialErrors
	keyDNSLookup  = latency.KeyDNSLookup

	keyABPairs   = latency.KeyABPairs
	keyABSkipped = latency.KeyABSkipped
	keyABMedian  = latency.KeyABMedian
	keyABPValue  = latency.KeyABPValue
	keyABSummary = latency.KeyABSummary
	keyABLabelA  = latency.KeyABLabelA
	keyABLabelB  = latency.KeyABLabelB
)

// Probe names, as recorded in Observation.Probe.
const (
	probeLatency = "latency"
	probePath    = "path"
	probeNAT     = "nat"
	probeIPv6    = "ipv6"
)

const (
	keyEgressIface   = "egress.iface"
	keyEgressSrcIP   = "egress.src_ip"
	keyEgressVirtual = "egress.is_virtual"
	keyEgressKind    = "egress.kind"
	keyGateway       = "gateway"
	keyGatewayCGNAT  = "gateway.is_cgnat"
)

const (
	keyNatCGNAT    = "nat.cgnat"
	keyNatReason   = "nat.reason"
	keyPublicV4    = "public.ip.v4"
	keyPublicV6    = "public.ip.v6"
	keyPublicProv  = "public.provider"
	keyPublicAgree = "public.agreement"
	keyPublicError = "public.error"
	// keyPublicAnswers is how many IPv4 providers replied. Without it, an
	// unagreed result cannot be told apart from a genuine disagreement.
	keyPublicAnswers = "public.answers_n"
	keyStunMappedIP  = "stun.mapped_ip"
	keyStunMappedPt  = "stun.mapped_port"
)

const (
	keyV6AnyGlobal = "ipv6.any_global"
	keyV6Default   = "ipv6.default_route"
	keyV6Reachable = "ipv6.reachable"
	keyV6GlobalCnt = "v6.global_count"
	keyV6Classes   = "v6.classes"
	keyV6Error     = "ipv6.error"
)

// subjectDefault is the fixed subject the probes use for host-wide facts such as
// the default gateway. It is path's unexported subjectDefault, mirrored for the
// same reason as the keys above.
const subjectDefault = "default"

// The nat probe splits its observations across two subjects: host-wide NAT
// conclusions under "nat", and the public-address measurements under "public".
// Reading a public.* key under the "nat" subject silently matches nothing, which
// is how a rule goes quiet without anyone noticing.
const publicSubject = "public"
