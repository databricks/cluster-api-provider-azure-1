package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func ParsePEM(pemData []byte) (privateKey any, certificate *x509.Certificate, err error) {
	privateKeyBlock, clientCertData := pem.Decode(pemData)
	if privateKeyBlock == nil {
		return nil, nil, errors.New("no private key found")
	}
	privateKey, err = x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	clientCertBlock, _ := pem.Decode(clientCertData)
	if clientCertBlock == nil {
		return nil, nil, errors.New("no certificate found")
	}
	certificate, err = x509.ParseCertificate(clientCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return privateKey, certificate, nil
}
