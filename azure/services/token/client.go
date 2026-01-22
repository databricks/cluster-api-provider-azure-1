/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package token

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/pkg/errors"
	"sigs.k8s.io/cluster-api-provider-azure/azure"
	"sigs.k8s.io/cluster-api-provider-azure/util/tele"
)

// AzureClient to get azure active directory token.
type AzureClient struct {
	aadToken *azidentity.ClientCertificateCredential
}

// NewClient creates a new azure active directory token client from an authorizer.
func NewClient(auth azure.Authorizer, clientCert []byte) (*AzureClient, error) {
	aadToken, err := newAzureActiveDirectoryTokenClientFromCertificate(auth.TenantID(),
		auth.ClientID(),
		auth.CloudEnvironment(),
		clientCert)
	if err != nil {
		return nil, err
	}
	return &AzureClient{
		aadToken: aadToken,
	}, nil
}

// newAzureActiveDirectoryTokenClientFromCertificate creates a new aad token client from an authorizer.
func newAzureActiveDirectoryTokenClientFromCertificate(tenantID, clientID, envName string, clientCert []byte) (*azidentity.ClientCertificateCredential, error) {
	cliOpts, err := azure.ARMClientOptions(envName)
	if err != nil {
		return nil, errors.Wrap(err, "error while getting client options")
	}
	clientOptions := &azidentity.ClientCertificateCredentialOptions{
		ClientOptions:        cliOpts.ClientOptions,
		SendCertificateChain: true,
	}
	certificates, privateKey, err := azidentity.ParseCertificates(clientCert, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse client certificate")
	}
	cred, err := azidentity.NewClientCertificateCredential(tenantID, clientID, certificates, privateKey, clientOptions)
	if err != nil {
		return nil, errors.Wrap(err, "error while getting az client secret credentials")
	}
	return cred, nil
}

// GetAzureActiveDirectoryToken gets the token for authentication with azure active directory.
func (ac *AzureClient) GetAzureActiveDirectoryToken(ctx context.Context, resourceID string) (string, error) {
	ctx, _, done := tele.StartSpanWithLogger(ctx, "aadToken.GetToken")
	defer done()

	spnAccessToken, err := ac.aadToken.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{resourceID + "/.default"}})
	if err != nil {
		return "", errors.Wrap(err, "failed to get token")
	}
	return spnAccessToken.Token, nil
}
