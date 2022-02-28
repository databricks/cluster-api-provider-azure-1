/*
Copyright 2020 The Kubernetes Authors.

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

package managedclusters

import (
	"context"
	"fmt"
	"net"

	"github.com/Azure/azure-sdk-for-go/services/containerservice/mgmt/2021-05-01/containerservice"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1alpha4"

	infrav1alpha4 "sigs.k8s.io/cluster-api-provider-azure/api/v1alpha4"
	"sigs.k8s.io/cluster-api-provider-azure/azure"
	"sigs.k8s.io/cluster-api-provider-azure/util/tele"
)

var (
	defaultUser     string = "azureuser"
	managedIdentity string = "msi"
)

// ManagedClusterScope defines the scope interface for a managed cluster.
type ManagedClusterScope interface {
	logr.Logger
	azure.ClusterDescriber
	ManagedClusterSpec() (azure.ManagedClusterSpec, error)
	GetAgentPoolSpecs(ctx context.Context) ([]azure.AgentPoolSpec, error)
	SetControlPlaneEndpoint(clusterv1.APIEndpoint)
	MakeEmptyKubeConfigSecret() corev1.Secret
	GetKubeConfigData() []byte
	SetKubeConfigData([]byte)
}

// Service provides operations on azure resources.
type Service struct {
	Scope ManagedClusterScope
	Client
}

func convertToResourceReferences(resources []string) *[]containerservice.ResourceReference {
	resourceReferences := make([]containerservice.ResourceReference, len(resources))
	for i := range resources {
		resourceReferences[i] = containerservice.ResourceReference{ID: &resources[i]}
	}
	return &resourceReferences
}

// New creates a new service.
func New(scope ManagedClusterScope) *Service {
	return &Service{
		Scope:  scope,
		Client: NewClient(scope),
	}
}

// Reconcile idempotently creates or updates a managed cluster, if possible.
//gocyclo:ignore
func (s *Service) Reconcile(ctx context.Context) error {
	ctx, span := tele.Tracer().Start(ctx, "managedclusters.Service.Reconcile")
	defer span.End()

	managedClusterSpec, err := s.Scope.ManagedClusterSpec()
	if err != nil {
		return errors.Wrap(err, "failed to get managed cluster spec")
	}

	isCreate := false
	existingMC, err := s.Client.Get(ctx, managedClusterSpec.ResourceGroupName, managedClusterSpec.Name)
	// Transient or other failure not due to 404
	if err != nil && !azure.ResourceNotFound(err) {
		return errors.Wrap(err, "failed to fetch existing managed cluster")
	}

	// We are creating this cluster for the first time.
	// Configure the agent pool, rest will be handled by machinepool controller
	// We do this here because AKS will only let us mutate agent pools via managed
	// clusters API at create time, not update.
	if azure.ResourceNotFound(err) {
		isCreate = true
		// Add system agent pool to cluster spec that will be submitted to the API
		managedClusterSpec.AgentPools, err = s.Scope.GetAgentPoolSpecs(ctx)
		if err != nil {
			return errors.Wrapf(err, "failed to get agent pool specs for managed cluster %s", s.Scope.ClusterName())
		}
	}

	managedCluster := containerservice.ManagedCluster{
		Identity: &containerservice.ManagedClusterIdentity{
			Type: containerservice.ResourceIdentityTypeSystemAssigned,
		},
		Location: &managedClusterSpec.Location,
		Tags:     *to.StringMapPtr(managedClusterSpec.Tags),
		ManagedClusterProperties: &containerservice.ManagedClusterProperties{
			NodeResourceGroup: &managedClusterSpec.NodeResourceGroupName,
			EnableRBAC:        to.BoolPtr(true),
			DNSPrefix:         &managedClusterSpec.Name,
			KubernetesVersion: &managedClusterSpec.Version,
			ServicePrincipalProfile: &containerservice.ManagedClusterServicePrincipalProfile{
				ClientID: &managedIdentity,
			},
			AgentPoolProfiles: &[]containerservice.ManagedClusterAgentPoolProfile{},
			NetworkProfile: &containerservice.NetworkProfile{
				NetworkPlugin:   containerservice.NetworkPlugin(managedClusterSpec.NetworkPlugin),
				LoadBalancerSku: containerservice.LoadBalancerSku(managedClusterSpec.LoadBalancerSKU),
				NetworkPolicy:   containerservice.NetworkPolicy(managedClusterSpec.NetworkPolicy),
			},
			DisableLocalAccounts: managedClusterSpec.DisableLocalAccounts,
		},
	}

	if managedClusterSpec.PodCIDR != "" {
		managedCluster.NetworkProfile.PodCidr = &managedClusterSpec.PodCIDR
	}

	if managedClusterSpec.ServiceCIDR != "" {
		if managedClusterSpec.DNSServiceIP == nil {
			managedCluster.NetworkProfile.ServiceCidr = &managedClusterSpec.ServiceCIDR
			ip, _, err := net.ParseCIDR(managedClusterSpec.ServiceCIDR)
			if err != nil {
				return fmt.Errorf("failed to parse service cidr: %w", err)
			}
			// HACK: set the last octet of the IP to .10
			// This ensures the dns IP is valid in the service cidr without forcing the user
			// to specify it in both the Capi cluster and the Azure control plane.
			// https://golang.org/src/net/ip.go#L48
			ip[15] = byte(10)
			dnsIP := ip.String()
			managedCluster.NetworkProfile.DNSServiceIP = &dnsIP
		} else {
			managedCluster.NetworkProfile.DNSServiceIP = managedClusterSpec.DNSServiceIP
		}
	}

	for i := range managedClusterSpec.AgentPools {
		pool := managedClusterSpec.AgentPools[i]
		profile := containerservice.ManagedClusterAgentPoolProfile{
			Name:         &pool.Name,
			VMSize:       &pool.SKU,
			OsDiskSizeGB: &pool.OSDiskSizeGB,
			Count:        &pool.Replicas,
			Type:         containerservice.AgentPoolTypeVirtualMachineScaleSets,
			Mode:         containerservice.AgentPoolMode(pool.Mode),
		}

		if pool.VnetSubnetID != "" {
			profile.VnetSubnetID = &pool.VnetSubnetID
		} else {
			profile.VnetSubnetID = &managedClusterSpec.VnetSubnetID
		}

		if pool.MaxCount != nil {
			profile.MaxCount = pool.MaxCount
		}

		if pool.MinCount != nil {
			profile.MinCount = pool.MinCount
		}

		if pool.EnableAutoScaling != nil {
			profile.EnableAutoScaling = pool.EnableAutoScaling
		}

		if pool.EnableFIPS != nil {
			profile.EnableFIPS = pool.EnableFIPS
		}

		if pool.EnableNodePublicIP != nil {
			profile.EnableNodePublicIP = pool.EnableNodePublicIP
		}

		if pool.NodeLabels != nil {
			profile.NodeLabels = pool.NodeLabels
		}

		if pool.NodeTaints != nil {
			profile.NodeTaints = &pool.NodeTaints
		}

		if pool.OsDiskType != nil {
			profile.OsDiskType = containerservice.OSDiskType(*pool.OsDiskType)
		}

		if pool.AvailabilityZones != nil {
			profile.AvailabilityZones = &pool.AvailabilityZones
		}

		if pool.ScaleSetPriority != nil {
			profile.ScaleSetPriority = containerservice.ScaleSetPriority(*pool.ScaleSetPriority)
		}

		if pool.MaxPods != nil {
			profile.MaxPods = pool.MaxPods
		}

		if pool.KubeletConfig != nil {
			profile.KubeletConfig = (*containerservice.KubeletConfig)(pool.KubeletConfig)
		}

		*managedCluster.AgentPoolProfiles = append(*managedCluster.AgentPoolProfiles, profile)
	}

	if managedClusterSpec.AADProfile != nil {
		managedCluster.AadProfile = &containerservice.ManagedClusterAADProfile{
			Managed:             &managedClusterSpec.AADProfile.Managed,
			EnableAzureRBAC:     &managedClusterSpec.AADProfile.EnableAzureRBAC,
			AdminGroupObjectIDs: &managedClusterSpec.AADProfile.AdminGroupObjectIDs,
		}
	}

	if managedClusterSpec.Sku != nil {
		var tier containerservice.ManagedClusterSKUTier
		if managedClusterSpec.Sku.Tier == "Paid" {
			tier = containerservice.ManagedClusterSKUTierPaid
		} else {
			tier = containerservice.ManagedClusterSKUTierFree
		}
		managedCluster.Sku = &containerservice.ManagedClusterSKU{
			Name: containerservice.ManagedClusterSKUNameBasic,
			Tier: tier,
		}
	}

	if managedClusterSpec.SSHPublicKey != nil {
		managedCluster.LinuxProfile = &containerservice.LinuxProfile{
			AdminUsername: &defaultUser,
			SSH: &containerservice.SSHConfiguration{
				PublicKeys: &[]containerservice.SSHPublicKey{
					{
						KeyData: managedClusterSpec.SSHPublicKey,
					},
				},
			},
		}
	}

	if managedClusterSpec.LoadBalancerProfile != nil {
		managedCluster.NetworkProfile.LoadBalancerProfile = &containerservice.ManagedClusterLoadBalancerProfile{
			AllocatedOutboundPorts: managedClusterSpec.LoadBalancerProfile.AllocatedOutboundPorts,
			IdleTimeoutInMinutes:   managedClusterSpec.LoadBalancerProfile.IdleTimeoutInMinutes,
		}
		if managedClusterSpec.LoadBalancerProfile.ManagedOutboundIPs != nil {
			managedCluster.NetworkProfile.LoadBalancerProfile.ManagedOutboundIPs = &containerservice.ManagedClusterLoadBalancerProfileManagedOutboundIPs{Count: managedClusterSpec.LoadBalancerProfile.ManagedOutboundIPs}
		}
		if len(managedClusterSpec.LoadBalancerProfile.OutboundIPPrefixes) > 0 {
			managedCluster.NetworkProfile.LoadBalancerProfile.OutboundIPPrefixes = &containerservice.ManagedClusterLoadBalancerProfileOutboundIPPrefixes{
				PublicIPPrefixes: convertToResourceReferences(managedClusterSpec.LoadBalancerProfile.OutboundIPPrefixes),
			}
		}
		if len(managedClusterSpec.LoadBalancerProfile.OutboundIPs) > 0 {
			managedCluster.NetworkProfile.LoadBalancerProfile.OutboundIPs = &containerservice.ManagedClusterLoadBalancerProfileOutboundIPs{
				PublicIPs: convertToResourceReferences(managedClusterSpec.LoadBalancerProfile.OutboundIPs),
			}
		}
	}

	if managedClusterSpec.APIServerAccessProfile != nil {
		managedCluster.APIServerAccessProfile = &containerservice.ManagedClusterAPIServerAccessProfile{
			AuthorizedIPRanges:             &managedClusterSpec.APIServerAccessProfile.AuthorizedIPRanges,
			EnablePrivateCluster:           managedClusterSpec.APIServerAccessProfile.EnablePrivateCluster,
			PrivateDNSZone:                 managedClusterSpec.APIServerAccessProfile.PrivateDNSZone,
			EnablePrivateClusterPublicFQDN: managedClusterSpec.APIServerAccessProfile.EnablePrivateClusterPublicFQDN,
		}
	}

	if isCreate {
		managedCluster, err = s.Client.CreateOrUpdate(ctx, managedClusterSpec.ResourceGroupName, managedClusterSpec.Name, managedCluster)
		if err != nil {
			return fmt.Errorf("failed to create managed cluster, %w", err)
		}
	} else {
		ps := *existingMC.ManagedClusterProperties.ProvisioningState
		if ps != string(infrav1alpha4.Canceled) && ps != string(infrav1alpha4.Failed) && ps != string(infrav1alpha4.Succeeded) {
			msg := fmt.Sprintf("Unable to update existing managed cluster in non terminal state. Managed cluster must be in one of the following provisioning states: canceled, failed, or succeeded. Actual state: %s", ps)
			klog.V(2).Infof(msg)
			return errors.New(msg)
		}

		// Normalize properties for the desired (CR spec) and existing managed
		// cluster, so that we check only those fields that were specified in
		// the initial CreateOrUpdate request and that can be modified.
		// Without comparing to normalized properties, we would always get a
		// difference in desired and existing, which would result in sending
		// unnecessary Azure API requests.
		propertiesNormalized := &containerservice.ManagedClusterProperties{
			KubernetesVersion:    managedCluster.ManagedClusterProperties.KubernetesVersion,
			NetworkProfile:       &containerservice.NetworkProfile{},
			DisableLocalAccounts: managedCluster.ManagedClusterProperties.DisableLocalAccounts,
		}

		existingMCPropertiesNormalized := &containerservice.ManagedClusterProperties{
			KubernetesVersion:    existingMC.ManagedClusterProperties.KubernetesVersion,
			NetworkProfile:       &containerservice.NetworkProfile{},
			DisableLocalAccounts: existingMC.ManagedClusterProperties.DisableLocalAccounts,
		}

		if managedCluster.AadProfile != nil {
			propertiesNormalized.AadProfile = &containerservice.ManagedClusterAADProfile{
				Managed:             managedCluster.AadProfile.Managed,
				EnableAzureRBAC:     managedCluster.AadProfile.EnableAzureRBAC,
				AdminGroupObjectIDs: managedCluster.AadProfile.AdminGroupObjectIDs,
			}
		}

		if existingMC.AadProfile != nil {
			existingMCPropertiesNormalized.AadProfile = &containerservice.ManagedClusterAADProfile{
				Managed:             existingMC.AadProfile.Managed,
				EnableAzureRBAC:     existingMC.AadProfile.EnableAzureRBAC,
				AdminGroupObjectIDs: existingMC.AadProfile.AdminGroupObjectIDs,
			}
		}

		if managedCluster.NetworkProfile != nil && managedCluster.NetworkProfile.LoadBalancerProfile != nil {
			propertiesNormalized.NetworkProfile.LoadBalancerProfile = &containerservice.ManagedClusterLoadBalancerProfile{
				ManagedOutboundIPs:     managedCluster.NetworkProfile.LoadBalancerProfile.ManagedOutboundIPs,
				OutboundIPPrefixes:     managedCluster.NetworkProfile.LoadBalancerProfile.OutboundIPPrefixes,
				OutboundIPs:            managedCluster.NetworkProfile.LoadBalancerProfile.OutboundIPs,
				AllocatedOutboundPorts: managedCluster.NetworkProfile.LoadBalancerProfile.AllocatedOutboundPorts,
				IdleTimeoutInMinutes:   managedCluster.NetworkProfile.LoadBalancerProfile.IdleTimeoutInMinutes,
			}
		}

		if existingMC.NetworkProfile != nil && existingMC.NetworkProfile.LoadBalancerProfile != nil {
			existingMCPropertiesNormalized.NetworkProfile.LoadBalancerProfile = &containerservice.ManagedClusterLoadBalancerProfile{
				ManagedOutboundIPs:     existingMC.NetworkProfile.LoadBalancerProfile.ManagedOutboundIPs,
				OutboundIPPrefixes:     existingMC.NetworkProfile.LoadBalancerProfile.OutboundIPPrefixes,
				OutboundIPs:            existingMC.NetworkProfile.LoadBalancerProfile.OutboundIPs,
				AllocatedOutboundPorts: existingMC.NetworkProfile.LoadBalancerProfile.AllocatedOutboundPorts,
				IdleTimeoutInMinutes:   existingMC.NetworkProfile.LoadBalancerProfile.IdleTimeoutInMinutes,
			}
		}

		if managedCluster.APIServerAccessProfile != nil {
			propertiesNormalized.APIServerAccessProfile = &containerservice.ManagedClusterAPIServerAccessProfile{
				AuthorizedIPRanges: managedCluster.APIServerAccessProfile.AuthorizedIPRanges,
			}
		}

		if existingMC.APIServerAccessProfile != nil {
			existingMCPropertiesNormalized.APIServerAccessProfile = &containerservice.ManagedClusterAPIServerAccessProfile{
				AuthorizedIPRanges: existingMC.APIServerAccessProfile.AuthorizedIPRanges,
			}
		}

		clusterNormalized := &containerservice.ManagedCluster{
			ManagedClusterProperties: propertiesNormalized,
		}
		existingMCClusterNormalized := &containerservice.ManagedCluster{
			ManagedClusterProperties: existingMCPropertiesNormalized,
		}

		if managedCluster.Sku != nil {
			clusterNormalized.Sku = managedCluster.Sku
		}
		if existingMC.Sku != nil {
			existingMCClusterNormalized.Sku = existingMC.Sku
		}

		diff := cmp.Diff(existingMCClusterNormalized, clusterNormalized)
		if diff != "" {
			klog.V(2).Infof("Update required (+new -old):\n%s", diff)
			managedCluster, err = s.Client.CreateOrUpdate(ctx, managedClusterSpec.ResourceGroupName, managedClusterSpec.Name, managedCluster)
			if err != nil {
				return fmt.Errorf("failed to update managed cluster, %w", err)
			}
		} else {
			// No update required, but use the MC fetched from Azure for reading fields below.
			// This is to ensure the read-only fields like Fqdn from the existing MC are used for updating the
			// AzureManagedCluster.
			managedCluster = existingMC
		}
	}

	// Update control plane endpoint.
	if managedCluster.ManagedClusterProperties != nil && managedCluster.ManagedClusterProperties.Fqdn != nil {
		endpoint := clusterv1.APIEndpoint{
			Host: *managedCluster.ManagedClusterProperties.Fqdn,
			Port: 443,
		}
		s.Scope.SetControlPlaneEndpoint(endpoint)
	} else {
		// Fail if cluster api endpoint is not available.
		return fmt.Errorf("failed to get API endpoint for managed cluster")
	}

	// Update kubeconfig data
	// Always fetch credentials in case of rotation
	kubeConfigData, err := s.Client.GetCredentials(ctx, s.Scope.ResourceGroup(), s.Scope.ClusterName())
	if err != nil {
		return errors.Wrap(err, "failed to get credentials for managed cluster")
	}
	s.Scope.SetKubeConfigData(kubeConfigData)

	return nil
}

// Delete deletes the virtual network with the provided name.
func (s *Service) Delete(ctx context.Context) error {
	ctx, span := tele.Tracer().Start(ctx, "managedclusters.Service.Delete")
	defer span.End()

	klog.V(2).Infof("Deleting managed cluster  %s ", s.Scope.ClusterName())
	err := s.Client.Delete(ctx, s.Scope.ResourceGroup(), s.Scope.ClusterName())
	if err != nil {
		if azure.ResourceNotFound(err) {
			// already deleted
			return nil
		}
		return errors.Wrapf(err, "failed to delete managed cluster %s in resource group %s", s.Scope.ClusterName(), s.Scope.ResourceGroup())
	}

	klog.V(2).Infof("successfully deleted managed cluster %s ", s.Scope.ClusterName())
	return nil
}
