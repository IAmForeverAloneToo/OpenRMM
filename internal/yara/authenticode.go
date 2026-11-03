package yara

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"time"
	"unicode/utf16"
)

// Authenticode signatures embedded in PE files, for pe.signatures: each
// signature (and nested signature) is parsed from its PKCS #7 SignedData,
// and verified in full: the file's Authenticode hash against the signed
// one, the signer's signature over the signed attributes, and the
// certificate chain to the device's trusted roots for code signing, at the
// countersignature's time when a countersignature verifies. Catalog
// signatures are not embedded and are not seen (as in YARA).

// codeSigningRoots are the trusted roots; nil uses the operating system's
// store (on Windows, its root certificate store). Tests set their own.
var codeSigningRoots *x509.CertPool

const (
	maxSignatures    = 16
	maxCertificates  = 64
	maxNestedDepth   = 3
	maxCertTableSize = 16 << 20
)

var (
	oidSignedData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSpcIndirectData  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidContentType      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidCounterSignature = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	oidSpcOpusInfo      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	oidNestedSignature  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
	oidRFC3161Timestamp = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
	oidTSTInfo          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSHA1             = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidMD5              = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version                   int
	IssuerAndSerial           issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthAttrs                 asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthAttrs               asn1.RawValue `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type spcIndirectData struct {
	Data   asn1.RawValue
	Digest digestInfo
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint digestInfo
	Serial         *big.Int
	GenTime        time.Time `asn1:"generalized"`
}

// peCert is a certificate as pe.signatures describes it.
type peCert struct {
	thumbprint, issuer, subject, algorithm, algorithmOID, serial string
	version                                                      int64
	notBefore, notAfter                                          int64
}

type peCountersignature struct {
	verified          bool
	signTime          int64
	digest, digestAlg string
	chain             []peCert
}

type peSignature struct {
	cert                          peCert // the signer's certificate
	verified                      bool
	digestAlg, digest, fileDigest string
	certificates                  []peCert
	programName                   string
	signerDigest, signerDigestAlg string
	signerChain                   []peCert
	countersignatures             []peCountersignature
}

func hashFor(oid asn1.ObjectIdentifier) (crypto.Hash, string) {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1, "sha1"
	case oid.Equal(oidSHA256):
		return crypto.SHA256, "sha256"
	case oid.Equal(oidSHA384):
		return crypto.SHA384, "sha384"
	case oid.Equal(oidSHA512):
		return crypto.SHA512, "sha512"
	case oid.Equal(oidMD5):
		return crypto.MD5, "md5"
	}
	return 0, ""
}

func digestOf(h crypto.Hash, parts ...[]byte) []byte {
	if h == 0 || !h.Available() {
		return nil
	}
	w := h.New()
	for _, p := range parts {
		w.Write(p)
	}
	return w.Sum(nil)
}

// certificateTable is the file's certificate table, if it has one.
func (p *peFile) certificateTable() (off, size uint32, ok bool) {
	if p.image || len(p.dirs) <= 4 {
		return 0, 0, false
	}
	// The security directory holds a file offset, not an address.
	off, size = p.dirs[4][0], p.dirs[4][1]
	if off == 0 || size < 8 || size > maxCertTableSize || uint64(off)+uint64(size) > uint64(len(p.data)) {
		return 0, 0, false
	}
	return off, size, true
}

// authenticodeDigest hashes the file as Authenticode does: everything but
// the checksum, the security directory entry and the certificate table.
func (p *peFile) authenticodeDigest(h crypto.Hash) []byte {
	off, size, ok := p.certificateTable()
	if !ok {
		return nil
	}
	// The checksum field, and data directory 4 (directories start at 96,
	// or 112 in a 64-bit optional header; 8 bytes each).
	checksum := uint64(p.optOffset) + 64
	dirAt := uint64(p.optOffset) + 96 + 4*8
	if p.is64 {
		dirAt = uint64(p.optOffset) + 112 + 4*8
	}
	end := uint64(off)
	if checksum+4 > dirAt || dirAt+8 > end {
		return nil
	}
	return digestOf(h, p.data[:checksum], p.data[checksum+4:dirAt], p.data[dirAt+8:end], p.data[uint64(off)+uint64(size):])
}

// signatures parses and verifies the embedded signatures.
func (p *peFile) signatures() []peSignature {
	off, size, ok := p.certificateTable()
	if !ok {
		return nil
	}
	var out []peSignature
	table := p.data[off : off+size]
	for at := 0; at+8 <= len(table) && len(out) < maxSignatures; {
		n := int(binary.LittleEndian.Uint32(table[at:]))
		typ := binary.LittleEndian.Uint16(table[at+6:])
		if n < 8 || at+n > len(table) {
			break
		}
		if typ == 2 { // PKCS #7 SignedData
			p.signedData(table[at+8:at+n], 0, &out)
		}
		at += (n + 7) &^ 7
	}
	return out
}

func parseContentInfo(der []byte) (*signedData, bool) {
	// An explicit [0] RawValue keeps its wrapper: Bytes is the SignedData.
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil || !ci.ContentType.Equal(oidSignedData) {
		return nil, false
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, false
	}
	return &sd, true
}

// certificatesOf parses the SignedData's certificates.
func certificatesOf(sd *signedData) []*x509.Certificate {
	var out []*x509.Certificate
	rest := sd.Certificates.Bytes
	for len(rest) > 0 && len(out) < maxCertificates {
		var raw asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			break
		}
		if c, err := x509.ParseCertificate(raw.FullBytes); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func attributes(raw asn1.RawValue) []attribute {
	var out []attribute
	rest := raw.Bytes
	for len(rest) > 0 && len(out) < 64 {
		var a attribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			break
		}
		out = append(out, a)
	}
	return out
}

// value is an attribute's first value.
func (a attribute) value() []byte {
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(a.Values.Bytes, &v); err != nil {
		return nil
	}
	return v.FullBytes
}

func find(attrs []attribute, oid asn1.ObjectIdentifier) []attribute {
	var out []attribute
	for _, a := range attrs {
		if a.Type.Equal(oid) {
			out = append(out, a)
		}
	}
	return out
}

// signer finds the signer's certificate by issuer and serial number.
func signer(certs []*x509.Certificate, si signerInfo) *x509.Certificate {
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, si.IssuerAndSerial.Issuer.FullBytes) && si.IssuerAndSerial.Serial != nil && c.SerialNumber.Cmp(si.IssuerAndSerial.Serial) == 0 {
			return c
		}
	}
	return nil
}

// signedAttrsValid checks a signer's message digest attribute against the
// signed content and its signature over the attributes.
func signedAttrsValid(cert *x509.Certificate, si signerInfo, content []byte) bool {
	h, _ := hashFor(si.DigestAlgorithm.Algorithm)
	if cert == nil || h == 0 || len(si.AuthAttrs.FullBytes) == 0 {
		return false
	}
	md := find(attributes(si.AuthAttrs), oidMessageDigest)
	var got []byte
	if len(md) != 1 {
		return false
	}
	if _, err := asn1.Unmarshal(md[0].value(), &got); err != nil || !bytes.Equal(got, digestOf(h, content)) {
		return false
	}
	// The signature covers the attributes encoded as a SET.
	signed := append([]byte{0x31}, si.AuthAttrs.FullBytes[1:]...)
	return checkSignature(cert, h, signed, si.EncryptedDigest)
}

func checkSignature(cert *x509.Certificate, h crypto.Hash, signed, sig []byte) bool {
	d := digestOf(h, signed)
	if d == nil {
		return false
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, h, d, sig) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, d, sig)
	}
	return false
}

// chainOf is the signer's certificate and the issuers found for it.
func chainOf(leaf *x509.Certificate, certs []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{leaf}
	for c := leaf; len(chain) < 16; {
		var next *x509.Certificate
		for _, d := range certs {
			if bytes.Equal(d.RawSubject, c.RawIssuer) && d != c && d.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
				next = d
				break
			}
		}
		if next == nil || bytes.Equal(c.RawIssuer, c.RawSubject) {
			break
		}
		chain = append(chain, next)
		c = next
	}
	return chain
}

func (p *peFile) signedData(der []byte, depth int, out *[]peSignature) {
	sd, ok := parseContentInfo(der)
	if !ok || len(sd.SignerInfos) != 1 || !sd.ContentInfo.ContentType.Equal(oidSpcIndirectData) {
		return
	}
	var spc spcIndirectData
	var spcRaw asn1.RawValue
	if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &spcRaw); err != nil {
		return
	}
	if _, err := asn1.Unmarshal(spcRaw.FullBytes, &spc); err != nil {
		return
	}
	certs := certificatesOf(sd)
	si := sd.SignerInfos[0]
	leaf := signer(certs, si)
	s := peSignature{}
	h, name := hashFor(spc.Digest.Algorithm.Algorithm)
	s.digestAlg, s.digest = name, hex.EncodeToString(spc.Digest.Digest)
	fileDigest := p.authenticodeDigest(h)
	s.fileDigest = hex.EncodeToString(fileDigest)
	for _, c := range certs {
		s.certificates = append(s.certificates, describeCert(c))
	}
	_, s.signerDigestAlg = hashFor(si.DigestAlgorithm.Algorithm)
	auth := attributes(si.AuthAttrs)
	if md := find(auth, oidMessageDigest); len(md) == 1 {
		var d []byte
		if _, err := asn1.Unmarshal(md[0].value(), &d); err == nil {
			s.signerDigest = hex.EncodeToString(d)
		}
	}
	if opus := find(auth, oidSpcOpusInfo); len(opus) == 1 {
		s.programName = programName(opus[0].value())
	}
	var chain []*x509.Certificate
	if leaf != nil {
		s.cert = describeCert(leaf)
		chain = chainOf(leaf, certs)
		for _, c := range chain {
			s.signerChain = append(s.signerChain, describeCert(c))
		}
	}
	unauth := attributes(si.UnauthAttrs)
	when := time.Now()
	for _, a := range find(unauth, oidCounterSignature) {
		cs := counterSignature(a.value(), certs, si.EncryptedDigest)
		if cs.verified {
			when = time.Unix(cs.signTime, 0)
		}
		s.countersignatures = append(s.countersignatures, cs)
	}
	for _, a := range find(unauth, oidRFC3161Timestamp) {
		cs := rfc3161(a.value(), si.EncryptedDigest)
		if cs.verified {
			when = time.Unix(cs.signTime, 0)
		}
		s.countersignatures = append(s.countersignatures, cs)
	}
	s.verified = fileDigest != nil && bytes.Equal(fileDigest, spc.Digest.Digest) &&
		signedAttrsValid(leaf, si, spcRaw.Bytes) && chainTrusted(leaf, certs, when)
	*out = append(*out, s)
	if depth < maxNestedDepth {
		for _, a := range find(unauth, oidNestedSignature) {
			var vals asn1.RawValue
			rest := a.Values.Bytes
			for len(rest) > 0 && len(*out) < maxSignatures {
				var err error
				if rest, err = asn1.Unmarshal(rest, &vals); err != nil {
					break
				}
				p.signedData(vals.FullBytes, depth+1, out)
			}
		}
	}
}

// chainTrusted verifies the signer's chain to a trusted root for code
// signing at the given time.
func chainTrusted(leaf *x509.Certificate, certs []*x509.Certificate, when time.Time) bool {
	if leaf == nil {
		return false
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		if c != leaf {
			pool.AddCert(c)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: codeSigningRoots, Intermediates: pool, CurrentTime: when, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	return err == nil
}

// counterSignature is a PKCS #9 countersignature: a signer over the
// signature's encrypted digest, with a signing time.
func counterSignature(der []byte, certs []*x509.Certificate, signed []byte) peCountersignature {
	var cs peCountersignature
	var si signerInfo
	if _, err := asn1.Unmarshal(der, &si); err != nil {
		return cs
	}
	_, cs.digestAlg = hashFor(si.DigestAlgorithm.Algorithm)
	auth := attributes(si.AuthAttrs)
	if t := find(auth, oidSigningTime); len(t) == 1 {
		var when time.Time
		if _, err := asn1.Unmarshal(t[0].value(), &when); err == nil {
			cs.signTime = when.Unix()
		}
	}
	if md := find(auth, oidMessageDigest); len(md) == 1 {
		var d []byte
		if _, err := asn1.Unmarshal(md[0].value(), &d); err == nil {
			cs.digest = hex.EncodeToString(d)
		}
	}
	cert := signer(certs, si)
	if cert != nil {
		for _, c := range chainOf(cert, certs) {
			cs.chain = append(cs.chain, describeCert(c))
		}
	}
	cs.verified = cs.signTime != 0 && signedAttrsValid(cert, si, signed)
	return cs
}

// rfc3161 is an RFC 3161 timestamp: a SignedData whose content (TSTInfo)
// imprints the signature's encrypted digest.
func rfc3161(der []byte, signed []byte) peCountersignature {
	var cs peCountersignature
	sd, ok := parseContentInfo(der)
	if !ok || len(sd.SignerInfos) != 1 || !sd.ContentInfo.ContentType.Equal(oidTSTInfo) {
		return cs
	}
	var octets []byte
	if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &octets); err != nil {
		return cs
	}
	var tst tstInfo
	if _, err := asn1.Unmarshal(octets, &tst); err != nil {
		return cs
	}
	h, name := hashFor(tst.MessageImprint.Algorithm.Algorithm)
	cs.digestAlg, cs.digest, cs.signTime = name, hex.EncodeToString(tst.MessageImprint.Digest), tst.GenTime.Unix()
	certs := certificatesOf(sd)
	si := sd.SignerInfos[0]
	cert := signer(certs, si)
	if cert != nil {
		for _, c := range chainOf(cert, certs) {
			cs.chain = append(cs.chain, describeCert(c))
		}
	}
	cs.verified = bytes.Equal(tst.MessageImprint.Digest, digestOf(h, signed)) && signedAttrsValid(cert, si, octets)
	return cs
}

// programName reads SpcSpOpusInfo's program name (a BMP or IA5 string).
func programName(der []byte) string {
	var opus struct {
		Name asn1.RawValue `asn1:"optional,explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &opus); err != nil || len(opus.Name.Bytes) == 0 {
		return ""
	}
	var s asn1.RawValue
	if _, err := asn1.Unmarshal(opus.Name.Bytes, &s); err != nil {
		return ""
	}
	if s.Tag == 0 { // BMP string
		u := make([]uint16, len(s.Bytes)/2)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(s.Bytes[2*i:])
		}
		return string(utf16.Decode(u))
	}
	return string(s.Bytes)
}

var nameOIDs = map[string]string{
	"2.5.4.6": "C", "2.5.4.8": "ST", "2.5.4.7": "L", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.3": "CN",
	"2.5.4.5": "serialNumber", "2.5.4.9": "street", "2.5.4.17": "postalCode", "2.5.4.12": "title", "2.5.4.4": "SN",
	"2.5.4.42": "GN", "2.5.4.15": "businessCategory", "1.2.840.113549.1.9.1": "emailAddress",
	"1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC", "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
	"1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL", "0.9.2342.19200300.100.1.25": "DC",
}

// oneline formats a name as OpenSSL's one-line form: /C=US/O=Example/CN=Name.
func oneline(raw []byte) string {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdns); err != nil {
		return ""
	}
	var b strings.Builder
	for _, rdn := range rdns {
		for _, atv := range rdn {
			key := nameOIDs[atv.Type.String()]
			if key == "" {
				key = atv.Type.String()
			}
			b.WriteString("/" + key + "=")
			switch v := atv.Value.(type) {
			case string:
				b.WriteString(v)
			default:
				b.WriteString(strings.Trim(strings.ReplaceAll(strings.ReplaceAll(fmtAny(v), "\n", " "), "\r", ""), " "))
			}
		}
	}
	return b.String()
}

func fmtAny(v any) string {
	if s, ok := v.(interface{ String() string }); ok {
		return s.String()
	}
	return ""
}

var sigAlgNames = map[string]string{
	"1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
	"1.2.840.113549.1.1.12": "sha384WithRSAEncryption", "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
	"1.2.840.113549.1.1.4": "md5WithRSAEncryption", "1.2.840.113549.1.1.10": "rsassaPss",
	"1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
	"1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}

// signatureOID is the certificate's signature algorithm identifier.
func signatureOID(c *x509.Certificate) string {
	var cert struct {
		TBS   asn1.RawValue
		Alg   pkix.AlgorithmIdentifier
		Value asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.Raw, &cert); err != nil {
		return ""
	}
	return cert.Alg.Algorithm.String()
}

func describeCert(c *x509.Certificate) peCert {
	sum := sha1.Sum(c.Raw)
	oid := signatureOID(c)
	serial := c.SerialNumber.Bytes()
	parts := make([]string, len(serial))
	for i, b := range serial {
		parts[i] = hex.EncodeToString([]byte{b})
	}
	return peCert{
		thumbprint: hex.EncodeToString(sum[:]), issuer: oneline(c.RawIssuer), subject: oneline(c.RawSubject),
		algorithm: sigAlgNames[oid], algorithmOID: oid, serial: strings.Join(parts, ":"),
		version: int64(c.Version), notBefore: c.NotBefore.Unix(), notAfter: c.NotAfter.Unix(),
	}
}
