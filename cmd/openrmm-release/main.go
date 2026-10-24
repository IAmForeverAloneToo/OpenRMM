// Offline release signing: no network client and no application credentials.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/serverupdate"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Modes:
//
//	-create-key DIR -passphrase-stdin
//	    New encrypted key (signing-key.json), public.txt and a sequence counter.
//	-encrypt-key -key DIR/private.pem -last-sequence N -passphrase-stdin
//	    Encrypt an existing plaintext key in place (same public key, so device
//	    pins stay valid), start its counter at N, then delete private.pem.
//	-key DIR/signing-key.json -passphrase-stdin -binary EXE -version V -out FILE [-sequence N]
//	    Sign with the next sequence from the key's counter (or an explicit higher one).
//	-key private.pem -binary EXE -version V -sequence N -out FILE
//	    Legacy plaintext key; the sequence must be given explicitly.
//
//	-server-release -key DIR/signing-key.json -passphrase-stdin -version V -sequence N
//	    -image REPOSITORY -image-id sha256:... [-digest sha256:...] [-notes FILE] -out FILE
//	    Sign a server release pinning the image. It uses the
//	    sequence of the agent release built with it and consumes none.
//
// With -agent EXE the -binary artifact is the agent MSI (manifest format
// 2): the manifest binds the MSI and records the hash of the
// openrmm-agent.exe it installs.
func run(stdin io.Reader) error {
	f := flag.NewFlagSet("release", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	keygen := f.String("create-key", "", "")
	encrypt := f.Bool("encrypt-key", false, "")
	key := f.String("key", "", "")
	binary := f.String("binary", "", "")
	agent := f.String("agent", "", "")
	version := f.String("version", "", "")
	sequence := f.Int64("sequence", 0, "")
	last := f.Int64("last-sequence", -1, "")
	fromStdin := f.Bool("passphrase-stdin", false, "")
	out := f.String("out", "", "")
	days := f.Int("days", 30, "")
	serverRelease := f.Bool("server-release", false, "")
	image := f.String("image", "", "")
	imageID := f.String("image-id", "", "")
	digest := f.String("digest", "", "")
	notes := f.String("notes", "", "")
	if f.Parse(os.Args[1:]) != nil || f.NArg() != 0 || *sequence < 0 {
		return agentupdate.ErrInvalid
	}
	passphrase := func() ([]byte, error) {
		if !*fromStdin {
			return nil, errKey
		}
		return readPassphrase(stdin)
	}
	switch {
	case *keygen != "":
		if *encrypt || *key != "" || *binary != "" || *out != "" {
			return agentupdate.ErrInvalid
		}
		p, e := passphrase()
		if e != nil {
			return e
		}
		_, priv, e := ed25519.GenerateKey(nil)
		if e != nil {
			return e
		}
		if e = privatefs.CreateDirectory(*keygen); e != nil {
			return e
		}
		if e = storeSealed(*keygen, priv, p, 0); e != nil {
			return e
		}
		fmt.Println("Created an encrypted offline signing key; keep its folder and passphrase outside the server and source control.")
		return nil
	case *encrypt:
		if *key == "" || *last < 0 || *binary != "" || *out != "" {
			return agentupdate.ErrInvalid
		}
		priv, e := readPlainKey(*key)
		if e != nil {
			return e
		}
		p, e := passphrase()
		if e != nil {
			return e
		}
		dir := filepath.Dir(*key)
		if e = storeSealed(dir, priv, p, *last); e != nil {
			return e
		}
		raw, e := os.ReadFile(filepath.Join(dir, sealedKeyFile))
		if e != nil {
			return e
		}
		check, e := openKey(raw, p)
		if e != nil || !check.Equal(priv) {
			return errKey
		}
		if e = os.Remove(*key); e != nil {
			return e
		}
		fmt.Println("Encrypted the signing key; the plaintext copy was deleted. Device key pins are unchanged.")
		return nil
	}
	if *serverRelease {
		return signServer(*key, *version, *sequence, *image, *imageID, *digest, *notes, *out, *days, passphrase)
	}
	if *key == "" || *binary == "" || *out == "" || *days < 1 || *days > 90 {
		return agentupdate.ErrInvalid
	}
	var priv ed25519.PrivateKey
	if filepath.Base(*key) == sealedKeyFile {
		raw, e := os.ReadFile(*key)
		if e != nil {
			return errKey
		}
		p, e := passphrase()
		if e != nil {
			return e
		}
		if priv, e = openKey(raw, p); e != nil {
			return e
		}
		// Validate the artifact before consuming a sequence number.
		hash, size, e := agentupdate.FileHash(*binary)
		if e != nil {
			return e
		}
		agentHash, e := agentArtifact(*agent)
		if e != nil {
			return e
		}
		probe := manifest(priv, *version, 1, hash, size, *days, agentHash)
		if !agentupdate.Valid(probe) || agentupdate.Inspect(*binary, probe) != nil {
			return agentupdate.ErrInvalid
		}
		if *sequence, e = nextSequence(filepath.Dir(*key), *sequence); e != nil {
			return e
		}
	} else {
		if *sequence == 0 {
			return agentupdate.ErrInvalid
		}
		var e error
		if priv, e = readPlainKey(*key); e != nil {
			return e
		}
	}
	hash, size, e := agentupdate.FileHash(*binary)
	if e != nil {
		return e
	}
	agentHash, e := agentArtifact(*agent)
	if e != nil {
		return e
	}
	m := manifest(priv, *version, *sequence, hash, size, *days, agentHash)
	if !agentupdate.Valid(m) || agentupdate.Inspect(*binary, m) != nil {
		return agentupdate.ErrInvalid
	}
	release := protocol.SignedAgentRelease{Manifest: m, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, agentupdate.Message(m)))}
	data, _ := json.Marshal(release)
	if e = writeNew(*out, data); e != nil {
		return e
	}
	fmt.Printf("Signed exact Windows agent artifact; sequence %d; release ID: %s\n", m.Sequence, agentupdate.ReleaseID(release))
	if agentupdate.MSI(m) {
		fmt.Printf("Package: MSI; installed agent SHA-256: %s\n", m.AgentHash)
	}
	return nil
}

func manifest(priv ed25519.PrivateKey, version string, sequence int64, hash string, size int64, days int, agentHash string) protocol.AgentManifest {
	now := time.Now()
	pub := priv.Public().(ed25519.PublicKey)
	m := protocol.AgentManifest{Format: 1, Product: "OpenRMMAgent", OS: "windows", Architecture: "amd64", Version: version, Sequence: sequence, Size: size, Hash: hash, KeyID: agentupdate.Digest(pub), Issued: now.Unix(), Expires: now.Add(time.Duration(days) * 24 * time.Hour).Unix()}
	if agentHash != "" {
		m.Format, m.Package, m.AgentHash = 2, "msi", agentHash
	}
	return m
}

// agentArtifact hashes the executable packaged in an MSI release after
// checking that it is a 64-bit Windows program. No path means format 1.
func agentArtifact(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	hash, size, e := agentupdate.FileHash(path)
	if e != nil {
		return "", e
	}
	probe := protocol.AgentManifest{Format: 1, Product: "OpenRMMAgent", OS: "windows", Architecture: "amd64", Version: "probe", Sequence: 1, Size: size, Hash: hash, KeyID: hash, Issued: 1, Expires: 2}
	if agentupdate.Inspect(path, probe) != nil {
		return "", agentupdate.ErrInvalid
	}
	return hash, nil
}

func storeSealed(dir string, priv ed25519.PrivateKey, passphrase []byte, last int64) error {
	sealed, e := sealKey(priv, passphrase)
	if e != nil {
		return e
	}
	if e = writeNew(filepath.Join(dir, sealedKeyFile), sealed); e != nil {
		return e
	}
	public := []byte(hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	if existing, e := os.ReadFile(filepath.Join(dir, publicKeyFile)); e == nil {
		if string(existing) != string(public) {
			return errKey
		}
	} else if e = writeNew(filepath.Join(dir, publicKeyFile), public); e != nil {
		return e
	}
	return writeCounter(filepath.Join(dir, counterFile), last, true)
}

func readPlainKey(path string) (ed25519.PrivateKey, error) {
	file, e := os.Open(path)
	if e != nil {
		return nil, agentupdate.ErrInvalid
	}
	raw, e := io.ReadAll(io.LimitReader(file, 8193))
	file.Close()
	if e != nil || len(raw) > 8192 {
		return nil, agentupdate.ErrInvalid
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, agentupdate.ErrInvalid
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, agentupdate.ErrInvalid
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, agentupdate.ErrInvalid
	}
	return priv, nil
}

// signServer signs a server release. With the sealed key the sequence must
// already be used by the counter (the agent release of the same build).
func signServer(key, version string, sequence int64, image, imageID, digest, notesPath, out string, days int, passphrase func() ([]byte, error)) error {
	if key == "" || out == "" || sequence < 1 || days < 1 || days > 400 {
		return agentupdate.ErrInvalid
	}
	text := ""
	if notesPath != "" {
		raw, e := os.ReadFile(notesPath)
		if e != nil || len(raw) > serverupdate.MaxNotes {
			return agentupdate.ErrInvalid
		}
		text = string(raw)
	}
	var priv ed25519.PrivateKey
	if filepath.Base(key) == sealedKeyFile {
		raw, e := os.ReadFile(key)
		if e != nil {
			return errKey
		}
		p, e := passphrase()
		if e != nil {
			return e
		}
		if priv, e = openKey(raw, p); e != nil {
			return e
		}
		last, e := lastSequence(filepath.Dir(key))
		if e != nil || sequence > last {
			return agentupdate.ErrInvalid
		}
	} else {
		var e error
		if priv, e = readPlainKey(key); e != nil {
			return e
		}
	}
	now := time.Now()
	m := serverupdate.Manifest{Product: serverupdate.Product, Version: version, Sequence: sequence, Image: image, ImageID: imageID, Digest: digest, Notes: text,
		KeyID: agentupdate.Digest(priv.Public().(ed25519.PublicKey)), Issued: now.Unix(), Expires: now.Add(time.Duration(days) * 24 * time.Hour).Unix()}
	if !serverupdate.Valid(m) {
		return agentupdate.ErrInvalid
	}
	data, _ := json.Marshal(serverupdate.Sign(priv, m))
	if e := writeNew(out, data); e != nil {
		return e
	}
	fmt.Printf("Signed server release %s; sequence %d; image %s\n", m.Version, m.Sequence, serverupdate.ImageRef(m))
	return nil
}

func main() {
	if run(os.Stdin) != nil {
		fmt.Fprintln(os.Stderr, "Release operation failed; check explicit paths, signing key, passphrase and release metadata.")
		os.Exit(1)
	}
}
