// This file is part of MinIO Console Server
// Copyright (c) 2020 MinIO, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cluster

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	miniov2 "github.com/minio/operator/pkg/apis/minio.min.io/v2"
	"k8s.io/klog/v2"
)

func generateOperatorCryptoData() ([]byte, []byte, error) {
	privateKey, err := newPrivateKey(miniov2.DefaultEllipticCurve)
	if err != nil {
		klog.Errorf("Unexpected error during the ECDSA Key generation: %v", err)
		return nil, nil, err
	}

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		klog.Errorf("Unexpected error during encoding the ECDSA Private Key: %v", err)
		return nil, nil, err
	}

	opCommon := fmt.Sprintf("operator.%s.svc.%s", miniov2.GetNSFromFile(), miniov2.GetClusterDomain())

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   opCommon,
			Organization: []string{"Acme Co"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA512,
		DNSNames:           []string{"operator", opCommon},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		klog.Errorf("Unexpected error during creating the CSR: %v", err)
		return nil, nil, err
	}
	return privKeyBytes, csrBytes, nil
}

// createConsoleTLSCSR handles all the steps required to create the CSR: from creation of keys, submitting CSR and
// finally creating a secret that Console deployment will use to mount private key and certificate for TLS
// This Method Blocks till the CSR Request is approved via kubectl approve
func (c *Controller) createOperatorTLSCSR(ctx context.Context, tenant *miniov2.Tenant) error {
	privKeysBytes, csrBytes, err := generateOperatorCryptoData()
	if err != nil {
		klog.Errorf("Private Key and CSR generation failed with error: %v", err)
		return err
	}

	ns := miniov2.GetNSFromFile()

	err = c.createCertificate(ctx, tenant.ConsolePodLabels(), tenant.ConsoleCSRName(), ns, csrBytes, tenant)
	if err != nil {
		klog.Errorf("Unexpected error during the creation of the csr/%s: %v", tenant.ConsoleCSRName(), err)
		return err
	}

	// fetch certificate from CSR
	certbytes, err := c.fetchCertificate(ctx, tenant.ConsoleCSRName())
	if err != nil {
		klog.Errorf("Unexpected error during the creation of the csr/%s: %v", tenant.ConsoleCSRName(), err)
		return err
	}

	// PEM encode private ECDSA key
	encodedPrivKey := pem.EncodeToMemory(&pem.Block{Type: privateKeyType, Bytes: privKeysBytes})

	// Create secret for Console Deployment to use
	err = c.createSecret(ctx, tenant, tenant.ConsolePodLabels(), tenant.ConsoleTLSSecretName(), encodedPrivKey, certbytes)
	if err != nil {
		klog.Errorf("Unexpected error during the creation of the secret/%s: %v", tenant.ConsoleTLSSecretName(), err)
		return err
	}

	return nil
}
