package yara

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// tlv encodes one DER element.
func tlv(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	n := len(body)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, body...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, body...)
	case n < 0x10000:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, body...)
	}
	return append([]byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

func der(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func attr(oid asn1.ObjectIdentifier, value []byte) []byte {
	return tlv(0x30, der(oid), tlv(0x31, value))
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCert(t testing.TB, subject pkix.Name, parent *testCA, ca bool, eku ...x509.ExtKeyUsage) *testCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: subject, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: eku, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: ca,
	}
	if ca {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(raw)
	return &testCA{c, key}
}

var (
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	sha256Alg          = der(pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue})
)

// signerInfoDER signs content with the signer, with extra signed and
// unsigned attributes.
func signerInfoDER(t testing.TB, s *testCA, digestOfContent []byte, signed [][]byte, unsigned [][]byte) (info, signature []byte) {
	attrs := append([][]byte{attr(oidMessageDigest, der(digestOfContent))}, signed...)
	var body []byte
	for _, a := range attrs {
		body = append(body, a...)
	}
	h := sha256.Sum256(tlv(0x31, body))
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	ias := tlv(0x30, s.cert.RawIssuer, der(s.cert.SerialNumber))
	parts := [][]byte{der(1), ias, sha256Alg, tlv(0xA0, body), der(pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}), der(sig)}
	if len(unsigned) > 0 {
		var u []byte
		for _, a := range unsigned {
			u = append(u, a...)
		}
		parts = append(parts, tlv(0xA1, u))
	}
	return tlv(0x30, parts...), sig
}

// signFixture appends an Authenticode signature by signer (with a
// countersignature by tsa at signTime) to a PE file.
func signFixture(t testing.TB, file []byte, signer, tsa *testCA, extra []*x509.Certificate, signTime time.Time) []byte {
	for len(file)%8 != 0 {
		file = append(file, 0)
	}
	certOff := len(file)
	const o = 0x118
	checksumAt, dirAt := o+64, o+144
	h := sha256.New()
	h.Write(file[:checksumAt])
	h.Write(file[checksumAt+4 : dirAt])
	h.Write(file[dirAt+8 : certOff])
	digest := h.Sum(nil)
	spcData := tlv(0x30, der(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}), tlv(0x30))
	spc := tlv(0x30, spcData, tlv(0x30, sha256Alg, der(digest)))
	spcContents := spc[2:]
	if spc[1]&0x80 != 0 {
		spcContents = spc[2+int(spc[1]&0x7F):]
	}
	sum := sha256.Sum256(spcContents)
	opus := attr(oidSpcOpusInfo, tlv(0x30, tlv(0xA0, tlv(0x80, utf16BE("Fixture")))))
	// The countersignature signs the signature, which it is part of: sign
	// once to learn the signature, then again with the countersignature.
	_, firstSig := signerInfoDER(t, signer, sum[:], [][]byte{attr(oidContentType, der(oidSpcIndirectData)), opus}, nil)
	_ = firstSig
	info, sig := signerInfoDER(t, signer, sum[:], [][]byte{attr(oidContentType, der(oidSpcIndirectData)), opus}, nil)
	csSum := sha256.Sum256(sig)
	when, _ := asn1.MarshalWithParams(signTime.UTC(), "utc")
	cs, _ := signerInfoDER(t, tsa, csSum[:], [][]byte{attr(oidContentType, der(oidData)), attr(oidSigningTime, when)}, nil)
	// Rebuild the signer info with the countersignature as an unsigned
	// attribute (unsigned attributes do not change the signature).
	info = withUnsigned(info, attr(oidCounterSignature, cs))
	var certs []byte
	for _, c := range append([]*x509.Certificate{signer.cert, tsa.cert}, extra...) {
		certs = append(certs, c.Raw...)
	}
	sd := tlv(0x30, der(1), tlv(0x31, sha256Alg), tlv(0x30, der(oidSpcIndirectData), tlv(0xA0, spc)), tlv(0xA0, certs), tlv(0x31, info))
	ci := tlv(0x30, der(oidSignedData), tlv(0xA0, sd))
	entry := make([]byte, 8)
	binary.LittleEndian.PutUint32(entry, uint32(8+len(ci)))
	binary.LittleEndian.PutUint16(entry[4:], 0x0200)
	binary.LittleEndian.PutUint16(entry[6:], 2)
	entry = append(entry, ci...)
	for len(entry)%8 != 0 {
		entry = append(entry, 0)
	}
	binary.LittleEndian.PutUint32(file[dirAt:], uint32(certOff))
	binary.LittleEndian.PutUint32(file[dirAt+4:], uint32(len(entry)))
	return append(file, entry...)
}

// withUnsigned appends unsigned attributes to an encoded signer info.
func withUnsigned(info []byte, attrs ...[]byte) []byte {
	var raw asn1.RawValue
	asn1.Unmarshal(info, &raw)
	var u []byte
	for _, a := range attrs {
		u = append(u, a...)
	}
	return tlv(0x30, raw.Bytes, tlv(0xA1, u))
}

func utf16BE(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.BigEndian.AppendUint16(b, u)
	}
	return b
}

func TestAuthenticode(t *testing.T) {
	ca := newCert(t, pkix.Name{CommonName: "OpenRMM Test CA"}, nil, true)
	leaf := newCert(t, pkix.Name{Country: []string{"NL"}, Organization: []string{"OpenRMM Tests"}, CommonName: "OpenRMM Test Signer"}, ca, false, x509.ExtKeyUsageCodeSigning)
	tsa := newCert(t, pkix.Name{CommonName: "OpenRMM Test Timestamps"}, ca, false, x509.ExtKeyUsageTimeStamping)
	signTime := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	file := signFixture(t, buildFixture(), leaf, tsa, []*x509.Certificate{ca.cert}, signTime)
	thumb := sha1.Sum(leaf.cert.Raw)
	serial := fmt.Sprintf("%x", leaf.cert.SerialNumber.Bytes())
	var parts []string
	for i := 0; i < len(serial); i += 2 {
		parts = append(parts, serial[i:i+2])
	}
	rules := fmt.Sprintf(`import "pe" import "time"
rule signed { condition: pe.number_of_signatures == 1 and pe.is_signed and pe.signatures[0].verified
  and pe.signatures[0].subject == "/C=NL/O=OpenRMM Tests/CN=OpenRMM Test Signer" and pe.signatures[0].issuer == "/CN=OpenRMM Test CA"
  and pe.signatures[0].thumbprint == "%s" and pe.signatures[0].serial == "%s" and pe.signatures[0].algorithm == "ecdsa-with-SHA256"
  and pe.signatures[0].digest_alg == "sha256" and pe.signatures[0].digest == pe.signatures[0].file_digest
  and pe.signatures[0].number_of_certificates == 3 and pe.signatures[0].signer_info.program_name == "Fixture"
  and pe.signatures[0].signer_info.length == 2 and pe.signatures[0].signer_info.chain[1].subject == "/CN=OpenRMM Test CA"
  and pe.signatures[0].number_of_countersignatures == 1 and pe.signatures[0].countersignatures[0].verified
  and pe.signatures[0].countersignatures[0].sign_time == %d and pe.signatures[0].valid_on(time.now())
  and not pe.signatures[0].valid_on(0) and pe.signatures[0].version == 3 }`, hex.EncodeToString(thumb[:]), strings.Join(parts, ":"), signTime.Unix())

	trusted := x509.NewCertPool()
	trusted.AddCert(ca.cert)
	codeSigningRoots = trusted
	defer func() { codeSigningRoots = nil }()
	if got := scanText(t, rules, string(file)); len(got) != 1 {
		t.Fatal("a valid signature did not verify", got)
	}
	// In a memory scan, from the program's file.
	rs, _ := Compile(rules)
	img := mapImage(file)
	m, err := rs.ScanTarget(context.Background(), []Block{{Base: fxBase, Data: img}}, -1, Target{Image: &Block{Base: fxBase, Data: img}, ImageFile: file})
	if err != nil || len(m) != 1 {
		t.Fatal("memory scan with the program's file", m, err)
	}

	// An untrusted root: the signature is intact but not verified.
	codeSigningRoots = x509.NewCertPool()
	if got := scanText(t, `import "pe" rule r { condition: pe.number_of_signatures == 1 and not pe.is_signed and not pe.signatures[0].verified
  and pe.signatures[0].digest == pe.signatures[0].file_digest and pe.signatures[0].countersignatures[0].verified }`, string(file)); len(got) != 1 {
		t.Fatal("an untrusted signer verified", got)
	}
	// A changed byte of code: the digest no longer matches.
	codeSigningRoots = trusted
	file[0x410] ^= 0xFF
	if got := scanText(t, `import "pe" rule r { condition: not pe.signatures[0].verified and pe.signatures[0].digest != pe.signatures[0].file_digest }`, string(file)); len(got) != 1 {
		t.Fatal("a changed file verified", got)
	}
	// An unsigned PE has no signatures.
	if got := scanText(t, `import "pe" rule r { condition: pe.number_of_signatures == 0 and not pe.is_signed }`, string(buildFixture())); len(got) != 1 {
		t.Fatal("unsigned", got)
	}
}
