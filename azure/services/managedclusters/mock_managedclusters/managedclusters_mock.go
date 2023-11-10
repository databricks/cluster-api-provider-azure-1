/*
Copyright The Kubernetes Authors.

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

// Code generated by MockGen. DO NOT EDIT.
// Source: ../managedclusters.go

// Package mock_managedclusters is a generated GoMock package.
package mock_managedclusters

import (
	context "context"
	reflect "reflect"
	"sigs.k8s.io/cluster-api-provider-azure/azure/scope"

	autorest "github.com/Azure/go-autorest/autorest"
	gomock "github.com/golang/mock/gomock"
	v1 "k8s.io/api/core/v1"
	v1beta1 "sigs.k8s.io/cluster-api-provider-azure/api/v1beta1"
	azure "sigs.k8s.io/cluster-api-provider-azure/azure"
	scope "sigs.k8s.io/cluster-api-provider-azure/azure/scope"
	v1beta10 "sigs.k8s.io/cluster-api/api/v1beta1"
)

// MockManagedClusterScope is a mock of ManagedClusterScope interface.
type MockManagedClusterScope struct {
	ctrl     *gomock.Controller
	recorder *MockManagedClusterScopeMockRecorder
}

// MockManagedClusterScopeMockRecorder is the mock recorder for MockManagedClusterScope.
type MockManagedClusterScopeMockRecorder struct {
	mock *MockManagedClusterScope
}

// NewMockManagedClusterScope creates a new mock instance.
func NewMockManagedClusterScope(ctrl *gomock.Controller) *MockManagedClusterScope {
	mock := &MockManagedClusterScope{ctrl: ctrl}
	mock.recorder = &MockManagedClusterScopeMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManagedClusterScope) EXPECT() *MockManagedClusterScopeMockRecorder {
	return m.recorder
}

// AdditionalTags mocks base method.
func (m *MockManagedClusterScope) AdditionalTags() v1beta1.Tags {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AdditionalTags")
	ret0, _ := ret[0].(v1beta1.Tags)
	return ret0
}

// AdditionalTags indicates an expected call of AdditionalTags.
func (mr *MockManagedClusterScopeMockRecorder) AdditionalTags() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AdditionalTags", reflect.TypeOf((*MockManagedClusterScope)(nil).AdditionalTags))
}

// Authorizer mocks base method.
func (m *MockManagedClusterScope) Authorizer() autorest.Authorizer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Authorizer")
	ret0, _ := ret[0].(autorest.Authorizer)
	return ret0
}

// Authorizer indicates an expected call of Authorizer.
func (mr *MockManagedClusterScopeMockRecorder) Authorizer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Authorizer", reflect.TypeOf((*MockManagedClusterScope)(nil).Authorizer))
}

// AvailabilitySetEnabled mocks base method.
func (m *MockManagedClusterScope) AvailabilitySetEnabled() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AvailabilitySetEnabled")
	ret0, _ := ret[0].(bool)
	return ret0
}

// AvailabilitySetEnabled indicates an expected call of AvailabilitySetEnabled.
func (mr *MockManagedClusterScopeMockRecorder) AvailabilitySetEnabled() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AvailabilitySetEnabled", reflect.TypeOf((*MockManagedClusterScope)(nil).AvailabilitySetEnabled))
}

// BaseURI mocks base method.
func (m *MockManagedClusterScope) BaseURI() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BaseURI")
	ret0, _ := ret[0].(string)
	return ret0
}

// BaseURI indicates an expected call of BaseURI.
func (mr *MockManagedClusterScopeMockRecorder) BaseURI() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BaseURI", reflect.TypeOf((*MockManagedClusterScope)(nil).BaseURI))
}

// ClientID mocks base method.
func (m *MockManagedClusterScope) ClientID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClientID")
	ret0, _ := ret[0].(string)
	return ret0
}

// ClientID indicates an expected call of ClientID.
func (mr *MockManagedClusterScopeMockRecorder) ClientID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClientID", reflect.TypeOf((*MockManagedClusterScope)(nil).ClientID))
}

// ClientSecret mocks base method.
func (m *MockManagedClusterScope) ClientSecret() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClientSecret")
	ret0, _ := ret[0].(string)
	return ret0
}

// ClientSecret indicates an expected call of ClientSecret.
func (mr *MockManagedClusterScopeMockRecorder) ClientSecret() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClientSecret", reflect.TypeOf((*MockManagedClusterScope)(nil).ClientSecret))
}

// CloudEnvironment mocks base method.
func (m *MockManagedClusterScope) CloudEnvironment() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloudEnvironment")
	ret0, _ := ret[0].(string)
	return ret0
}

// CloudEnvironment indicates an expected call of CloudEnvironment.
func (mr *MockManagedClusterScopeMockRecorder) CloudEnvironment() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloudEnvironment", reflect.TypeOf((*MockManagedClusterScope)(nil).CloudEnvironment))
}

// CloudProviderConfigOverrides mocks base method.
func (m *MockManagedClusterScope) CloudProviderConfigOverrides() *v1beta1.CloudProviderConfigOverrides {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloudProviderConfigOverrides")
	ret0, _ := ret[0].(*v1beta1.CloudProviderConfigOverrides)
	return ret0
}

// CloudProviderConfigOverrides indicates an expected call of CloudProviderConfigOverrides.
func (mr *MockManagedClusterScopeMockRecorder) CloudProviderConfigOverrides() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloudProviderConfigOverrides", reflect.TypeOf((*MockManagedClusterScope)(nil).CloudProviderConfigOverrides))
}

// ClusterName mocks base method.
func (m *MockManagedClusterScope) ClusterName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClusterName")
	ret0, _ := ret[0].(string)
	return ret0
}

// ClusterName indicates an expected call of ClusterName.
func (mr *MockManagedClusterScopeMockRecorder) ClusterName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClusterName", reflect.TypeOf((*MockManagedClusterScope)(nil).ClusterName))
}

// DeleteLongRunningOperationState mocks base method.
func (m *MockManagedClusterScope) DeleteLongRunningOperationState(arg0, arg1 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DeleteLongRunningOperationState", arg0, arg1)
}

// DeleteLongRunningOperationState indicates an expected call of DeleteLongRunningOperationState.
func (mr *MockManagedClusterScopeMockRecorder) DeleteLongRunningOperationState(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteLongRunningOperationState", reflect.TypeOf((*MockManagedClusterScope)(nil).DeleteLongRunningOperationState), arg0, arg1)
}

// FailureDomains mocks base method.
func (m *MockManagedClusterScope) FailureDomains() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FailureDomains")
	ret0, _ := ret[0].([]string)
	return ret0
}

// FailureDomains indicates an expected call of FailureDomains.
func (mr *MockManagedClusterScopeMockRecorder) FailureDomains() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FailureDomains", reflect.TypeOf((*MockManagedClusterScope)(nil).FailureDomains))
}

// GetAllAgentPoolSpecs mocks base method.
func (m *MockManagedClusterScope) GetAllAgentPoolSpecs(ctx context.Context) ([]azure.AgentPoolSpec, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAllAgentPoolSpecs", ctx)
	ret0, _ := ret[0].([]azure.AgentPoolSpec)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAllAgentPoolSpecs indicates an expected call of GetAllAgentPoolSpecs.
func (mr *MockManagedClusterScopeMockRecorder) GetAllAgentPoolSpecs(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllAgentPoolSpecs", reflect.TypeOf((*MockManagedClusterScope)(nil).GetAllAgentPoolSpecs), ctx)
}

// GetKubeConfigData mocks base method.
func (m *MockManagedClusterScope) GetKubeConfigData() []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetKubeConfigData")
	ret0, _ := ret[0].([]byte)
	return ret0
}

// GetKubeConfigData indicates an expected call of GetKubeConfigData.
func (mr *MockManagedClusterScopeMockRecorder) GetKubeConfigData() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetKubeConfigData", reflect.TypeOf((*MockManagedClusterScope)(nil).GetKubeConfigData))
}

// GetLongRunningOperationState mocks base method.
func (m *MockManagedClusterScope) GetLongRunningOperationState(arg0, arg1 string) *v1beta1.Future {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLongRunningOperationState", arg0, arg1)
	ret0, _ := ret[0].(*v1beta1.Future)
	return ret0
}

// GetLongRunningOperationState indicates an expected call of GetLongRunningOperationState.
func (mr *MockManagedClusterScopeMockRecorder) GetLongRunningOperationState(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLongRunningOperationState", reflect.TypeOf((*MockManagedClusterScope)(nil).GetLongRunningOperationState), arg0, arg1)
}

// GetManagedControlPlaneCredentialsProvider mocks base method.
func (m *MockManagedClusterScope) GetManagedControlPlaneCredentialsProvider() *scope.ManagedControlPlaneCredentialsProvider {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetManagedControlPlaneCredentialsProvider")
	ret0, _ := ret[0].(*scope.ManagedControlPlaneCredentialsProvider)
	return ret0
}

// GetManagedControlPlaneCredentialsProvider indicates an expected call of GetManagedControlPlaneCredentialsProvider.
func (mr *MockManagedClusterScopeMockRecorder) GetManagedControlPlaneCredentialsProvider() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetManagedControlPlaneCredentialsProvider", reflect.TypeOf((*MockManagedClusterScope)(nil).GetManagedControlPlaneCredentialsProvider))
}

// HashKey mocks base method.
func (m *MockManagedClusterScope) HashKey() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HashKey")
	ret0, _ := ret[0].(string)
	return ret0
}

// HashKey indicates an expected call of HashKey.
func (mr *MockManagedClusterScopeMockRecorder) HashKey() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HashKey", reflect.TypeOf((*MockManagedClusterScope)(nil).HashKey))
}

// Location mocks base method.
func (m *MockManagedClusterScope) Location() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Location")
	ret0, _ := ret[0].(string)
	return ret0
}

// Location indicates an expected call of Location.
func (mr *MockManagedClusterScopeMockRecorder) Location() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Location", reflect.TypeOf((*MockManagedClusterScope)(nil).Location))
}

// MakeEmptyKubeConfigSecret mocks base method.
func (m *MockManagedClusterScope) MakeEmptyKubeConfigSecret() v1.Secret {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MakeEmptyKubeConfigSecret")
	ret0, _ := ret[0].(v1.Secret)
	return ret0
}

// MakeEmptyKubeConfigSecret indicates an expected call of MakeEmptyKubeConfigSecret.
func (mr *MockManagedClusterScopeMockRecorder) MakeEmptyKubeConfigSecret() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MakeEmptyKubeConfigSecret", reflect.TypeOf((*MockManagedClusterScope)(nil).MakeEmptyKubeConfigSecret))
}

// ManagedClusterAnnotations mocks base method.
func (m *MockManagedClusterScope) ManagedClusterAnnotations() map[string]string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ManagedClusterAnnotations")
	ret0, _ := ret[0].(map[string]string)
	return ret0
}

// ManagedClusterAnnotations indicates an expected call of ManagedClusterAnnotations.
func (mr *MockManagedClusterScopeMockRecorder) ManagedClusterAnnotations() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ManagedClusterAnnotations", reflect.TypeOf((*MockManagedClusterScope)(nil).ManagedClusterAnnotations))
}

// ManagedClusterSpec mocks base method.
func (m *MockManagedClusterScope) ManagedClusterSpec() (azure.ManagedClusterSpec, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ManagedClusterSpec")
	ret0, _ := ret[0].(azure.ManagedClusterSpec)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ManagedClusterSpec indicates an expected call of ManagedClusterSpec.
func (mr *MockManagedClusterScopeMockRecorder) ManagedClusterSpec() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ManagedClusterSpec", reflect.TypeOf((*MockManagedClusterScope)(nil).ManagedClusterSpec))
}

// ResourceGroup mocks base method.
func (m *MockManagedClusterScope) ResourceGroup() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ResourceGroup")
	ret0, _ := ret[0].(string)
	return ret0
}

// ResourceGroup indicates an expected call of ResourceGroup.
func (mr *MockManagedClusterScopeMockRecorder) ResourceGroup() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResourceGroup", reflect.TypeOf((*MockManagedClusterScope)(nil).ResourceGroup))
}

// SetControlPlaneEndpoint mocks base method.
func (m *MockManagedClusterScope) SetControlPlaneEndpoint(arg0 v1beta10.APIEndpoint) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetControlPlaneEndpoint", arg0)
}

// SetControlPlaneEndpoint indicates an expected call of SetControlPlaneEndpoint.
func (mr *MockManagedClusterScopeMockRecorder) SetControlPlaneEndpoint(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetControlPlaneEndpoint", reflect.TypeOf((*MockManagedClusterScope)(nil).SetControlPlaneEndpoint), arg0)
}

// SetKubeConfigData mocks base method.
func (m *MockManagedClusterScope) SetKubeConfigData(arg0 []byte) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetKubeConfigData", arg0)
}

// SetKubeConfigData indicates an expected call of SetKubeConfigData.
func (mr *MockManagedClusterScopeMockRecorder) SetKubeConfigData(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetKubeConfigData", reflect.TypeOf((*MockManagedClusterScope)(nil).SetKubeConfigData), arg0)
}

// SetLongRunningOperationState mocks base method.
func (m *MockManagedClusterScope) SetLongRunningOperationState(arg0 *v1beta1.Future) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetLongRunningOperationState", arg0)
}

// SetLongRunningOperationState indicates an expected call of SetLongRunningOperationState.
func (mr *MockManagedClusterScopeMockRecorder) SetLongRunningOperationState(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetLongRunningOperationState", reflect.TypeOf((*MockManagedClusterScope)(nil).SetLongRunningOperationState), arg0)
}

// SubscriptionID mocks base method.
func (m *MockManagedClusterScope) SubscriptionID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SubscriptionID")
	ret0, _ := ret[0].(string)
	return ret0
}

// SubscriptionID indicates an expected call of SubscriptionID.
func (mr *MockManagedClusterScopeMockRecorder) SubscriptionID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SubscriptionID", reflect.TypeOf((*MockManagedClusterScope)(nil).SubscriptionID))
}

// TenantID mocks base method.
func (m *MockManagedClusterScope) TenantID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TenantID")
	ret0, _ := ret[0].(string)
	return ret0
}

// TenantID indicates an expected call of TenantID.
func (mr *MockManagedClusterScopeMockRecorder) TenantID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TenantID", reflect.TypeOf((*MockManagedClusterScope)(nil).TenantID))
}

// GetManagedControlPlaneCredentialsProvider mocks base method.
func (m *MockManagedClusterScope) GetManagedControlPlaneCredentialsProvider() *scope.ManagedControlPlaneCredentialsProvider {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetManagedControlPlaneCredentialsProvider")
	ret0, _ := ret[0].(*scope.ManagedControlPlaneCredentialsProvider)
	return ret0
}

// GetManagedControlPlaneCredentialsProvider indicates an expected call of GetManagedControlPlaneCredentialsProvider.
func (mr *MockManagedClusterScopeMockRecorder) GetManagedControlPlaneCredentialsProvider() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetManagedControlPlaneCredentialsProvider", reflect.TypeOf((*MockManagedClusterScope)(nil).GetManagedControlPlaneCredentialsProvider))
}

// UpdateDeleteStatus mocks base method.
func (m *MockManagedClusterScope) UpdateDeleteStatus(arg0 v1beta10.ConditionType, arg1 string, arg2 error) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UpdateDeleteStatus", arg0, arg1, arg2)
}

// UpdateDeleteStatus indicates an expected call of UpdateDeleteStatus.
func (mr *MockManagedClusterScopeMockRecorder) UpdateDeleteStatus(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateDeleteStatus", reflect.TypeOf((*MockManagedClusterScope)(nil).UpdateDeleteStatus), arg0, arg1, arg2)
}

// UpdatePatchStatus mocks base method.
func (m *MockManagedClusterScope) UpdatePatchStatus(arg0 v1beta10.ConditionType, arg1 string, arg2 error) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UpdatePatchStatus", arg0, arg1, arg2)
}

// UpdatePatchStatus indicates an expected call of UpdatePatchStatus.
func (mr *MockManagedClusterScopeMockRecorder) UpdatePatchStatus(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdatePatchStatus", reflect.TypeOf((*MockManagedClusterScope)(nil).UpdatePatchStatus), arg0, arg1, arg2)
}

// UpdatePutStatus mocks base method.
func (m *MockManagedClusterScope) UpdatePutStatus(arg0 v1beta10.ConditionType, arg1 string, arg2 error) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UpdatePutStatus", arg0, arg1, arg2)
}

// UpdatePutStatus indicates an expected call of UpdatePutStatus.
func (mr *MockManagedClusterScopeMockRecorder) UpdatePutStatus(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdatePutStatus", reflect.TypeOf((*MockManagedClusterScope)(nil).UpdatePutStatus), arg0, arg1, arg2)
}
