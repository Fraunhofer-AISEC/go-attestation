package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/Fraunhofer-AISEC/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

// GetAkQualifiedName gets the Attestation Key Qualified Name which is the
// hash of the public area of the key concatenated with the qualified names
// of all parent keys. This name acts as the unique identifier for the AK
// TODO check calculation again
func GetAkQualifiedName(TPM *attest.TPM, ak *attest.AK) ([]byte, error) {

	if TPM == nil {
		return nil, fmt.Errorf("failed to get AK Qualified Name - TPM is not opened")
	}
	if ak == nil {
		return nil, fmt.Errorf("failed to get AK Qualified Name - AK does not exist")
	}

	// This is a TPMT_PUBLIC structure
	pub := ak.AttestationParameters().Public

	// TPMT_PUBLIC Contains algorithm used for hashing the public area to get
	// the name (nameAlg)
	tpm2Pub, err := tpm2.DecodePublic(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to Decode AK Public - %v", err)
	}

	if tpm2Pub.NameAlg != tpm2.AlgSHA256 {
		return nil, errors.New("failed to Get AK public - unsupported hash algorithm")
	}

	// Name of object is nameAlg || Digest(TPMT_PUBLIC)
	alg := make([]byte, 2)
	binary.BigEndian.PutUint16(alg, uint16(tpm2Pub.NameAlg))
	digestPub := sha256.Sum256(pub)
	name := append(alg, digestPub[:]...)

	// TPMS_CREATION_DATA contains parentQualifiedName
	createData := ak.AttestationParameters().CreateData
	tpm2CreateData, err := tpm2.DecodeCreationData(createData)
	if err != nil {
		return nil, fmt.Errorf("failed to Decode Creation Data: %v", err)
	}

	parentAlg := make([]byte, 2)
	binary.BigEndian.PutUint16(parentAlg, uint16(tpm2CreateData.ParentNameAlg))
	parentQualifiedName := append(parentAlg, tpm2CreateData.ParentQualifiedName.Digest.Value...)

	// QN_AK := H_AK(QN_Parent || NAME_AK)
	buf := append(parentQualifiedName[:], name[:]...)
	qualifiedNameDigest := sha256.Sum256(buf)
	qualifiedName := append(alg, qualifiedNameDigest[:]...)

	fmt.Printf("AK Name:           %v\n", hex.EncodeToString(name[:]))
	fmt.Printf("AK Qualified Name: %v\n", hex.EncodeToString(qualifiedName[:]))

	return qualifiedName, nil
}

func CreateIkCsr(priv crypto.PrivateKey, alg x509.SignatureAlgorithm) ([]byte, error) {
	tmpl := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "CMC Identity Key",
			Country:      []string{"DE"},
			Province:     []string{"BY"},
			Locality:     []string{"Munich"},
			Organization: []string{"Test Company"},
		},
		SignatureAlgorithm: alg,
		// TODO DNSNames: ,
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}
	tmp := &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created CSR: %v", err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to check signature of created CSR: %v", err)
	}

	return tmp.Bytes(), nil
}

func CreateAkCsr(priv crypto.PrivateKey, alg x509.SignatureAlgorithm) ([]byte, error) {
	tmpl := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "CMC Attestation Key",
			Country:      []string{"DE"},
			Province:     []string{"BY"},
			Locality:     []string{"Munich"},
			Organization: []string{"Test Company"},
		},
		SignatureAlgorithm: alg,
		// TODO DNSNames: ,
	}

	der, err := CreateCertificateRequest(rand.Reader, &tmpl, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %v", err)
	}
	tmp := &bytes.Buffer{}
	pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created CSR: %v", err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to check signature of created CSR: %v", err)
	}

	return tmp.Bytes(), nil
}

func main() {
	fmt.Println("go-attestation testing tool")

	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		fmt.Printf("activate credential failed: OpenTPM returned %v\n", err)
		return
	}

	// EK ---------------------------------------------------------
	eks, err := tpm.EKs()
	if err != nil {
		fmt.Printf("failed to load EKs - %v\n", err)
		return
	}
	fmt.Printf("Found %v EK(s)\n", len(eks))

	// AK --------------------------------------------------------
	fmt.Println("Creating new AK")
	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		fmt.Printf("failed to create new AK - %v\n", err)
		return
	}

	// TODO Get AK private handle to sign AK CSR (possible, if restricted flags
	// are set correct so that it is clear that the object was NOT created in the TPM)
	akPriv := ak.Private()

	akCsr, err := CreateAkCsr(akPriv, x509.SHA256WithRSA)
	if err != nil {
		fmt.Printf("failed to create CSR: %v\n", err)
	} else {
		fmt.Printf("AK CSR: %v\n", string(akCsr))
	}

	// IK -------------------------------------------------------------
	ikConfig := &attest.KeyConfig{}
	ikConfig.Algorithm = attest.ECDSA
	ikConfig.Size = 256

	ik, err := tpm.NewKey(ak, ikConfig)
	if err != nil {
		fmt.Printf("failed to create new IK: %v\n", err)
		return
	}

	ikPub := ik.Public()
	ikPriv, err := ik.Private(ikPub)
	if err != nil {
		fmt.Printf("Failed to get private key\n")
		return
	}

	ikCsr, err := CreateIkCsr(ikPriv, x509.ECDSAWithSHA256)
	if err != nil {
		fmt.Printf("failed to create CSR: %v\n", err)
		return
	}
	fmt.Printf("IK CSR: %v\n", string(ikCsr))

	tpm.Close()

	fmt.Println("Finished")
}
