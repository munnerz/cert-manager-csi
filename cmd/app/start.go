/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package app

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/cert-manager/csi-lib/driver"
	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/klog/klogr"
	"k8s.io/utils/clock"

	"github.com/jetstack/cert-manager-csi/cmd/app/options"
	"github.com/jetstack/cert-manager-csi/pkg/apis/v1alpha1"
)

var (
	opts *options.Options
)

func init() {
	flag.Set("logtostderr", "true")

	flag.CommandLine.Parse([]string{})

	RootCmd.Flags().AddGoFlagSet(flag.CommandLine)

	opts = options.AddFlags(RootCmd)
}

var RootCmd = &cobra.Command{
	Use:   "cert-manager-csi",
	Short: "Container Storage Interface driver to issue certificates from Cert-Manager",
	RunE: func(cmd *cobra.Command, args []string) error {

		log := klogr.New()

		restConfig, err := rest.InClusterConfig()
		if err != nil {
			panic("cannot load in-cluster config")
		}

		store, err := storage.NewFilesystem(log, opts.DataRoot)
		if err != nil {
			panic("failed to setup filesystem: " + err.Error())
		}

		d, err := driver.New(opts.Endpoint, log, driver.Options{
			DriverName:    opts.DriverName,
			DriverVersion: "v0.0.1",
			NodeID:        opts.NodeID,
			Store:         store,
			Manager: manager.NewManagerOrDie(manager.Options{
				Client:             cmclient.NewForConfigOrDie(restConfig),
				MetadataReader:     store,
				Clock:              clock.RealClock{},
				Log:                log,
				GeneratePrivateKey: (&keygen{store: store}).generatePrivateKey,
				GenerateRequest:    generateRequest,
				SignRequest:        signRequest,
				WriteKeypair:       (&writer{store: store}).writeKeypair,
			}),
		})
		if err != nil {
			return fmt.Errorf("failed to setup driver: " + err.Error())
		}

		if err := d.Run(); err != nil {
			return fmt.Errorf("failed running driver: " + err.Error())
		}

		return nil
	},
}

// keygen wraps the storage backend to allow for re-using private keys when
// re-issuing a certificate.
type keygen struct {
	store *storage.Filesystem
}

// generatePrivateKey generates a 2048-bit RSA private key
func (k *keygen) generatePrivateKey(meta metadata.Metadata) (crypto.PrivateKey, error) {
	// Currently no options are exposed for customising the kind of key generated
	genPrivateKey := func() (crypto.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }

	// By default, generate a new private key each time.
	if meta.VolumeContext[v1alpha1.ReusePrivateKey] != "true" {
		return genPrivateKey()
	}

	bytes, err := k.store.ReadFile(meta.VolumeID, "tls.key")
	if errors.Is(err, storage.ErrNotFound) {
		// Generate a new key if one is not found on disk
		return genPrivateKey()
	}

	pk, err := pki.DecodePrivateKeyBytes(bytes)
	if err != nil {
		// Generate a new key if the existing one cannot be decoded
		return genPrivateKey()
	}

	return pk, nil
}

func generateRequest(meta metadata.Metadata) (*manager.CertificateRequestBundle, error) {
	namespace := meta.VolumeContext["csi.storage.k8s.io/pod.namespace"]

	uris, err := parseURIs(meta.VolumeContext[v1alpha1.URISANsKey])
	if err != nil {
		return nil, fmt.Errorf("invalid URI provided in %q attribute: %w", v1alpha1.URISANsKey, err)
	}

	ips := parseIPAddresses(meta.VolumeContext[v1alpha1.IPSANsKey])

	dnsNames := strings.Split(meta.VolumeContext[v1alpha1.DNSNamesKey], ",")
	commonName := meta.VolumeContext[v1alpha1.CommonNameKey]

	duration := cmapi.DefaultCertificateDuration
	if durStr, ok := meta.VolumeContext[v1alpha1.DurationKey]; ok {
		duration, err = time.ParseDuration(durStr)
		if err != nil {
			return nil, fmt.Errorf("invalid %q attribute: %w", v1alpha1.DurationKey, err)
		}
	}

	isCA := false
	if isCAStr, ok := meta.VolumeContext[v1alpha1.IsCAKey]; ok {
		switch strings.ToLower(isCAStr) {
		case "true":
			isCA = true
		case "false":
			isCA = false
		}
	}

	return &manager.CertificateRequestBundle{
		Request: &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: commonName,
			},
			DNSNames:    dnsNames,
			IPAddresses: ips,
			URIs:        uris,
		},
		IsCA:      isCA,
		Namespace: namespace,
		Duration:  duration,
		Usages:    keyUsagesFromAttributes(meta.VolumeContext[v1alpha1.KeyUsagesKey]),
		IssuerRef: cmmeta.ObjectReference{
			Name:  meta.VolumeContext[v1alpha1.IssuerNameKey],
			Kind:  meta.VolumeContext[v1alpha1.IssuerKindKey],
			Group: meta.VolumeContext[v1alpha1.IssuerGroupKey],
		},
		Annotations: nil,
	}, nil
}

func signRequest(_ metadata.Metadata, key crypto.PrivateKey, request *x509.CertificateRequest) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, request, key)
}

// writer wraps the storage backend to allow access for writing data
type writer struct {
	store storage.Interface
}

func (w *writer) writeKeypair(meta metadata.Metadata, key crypto.PrivateKey, chain []byte, ca []byte) error {
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey)),
		},
	)

	pkFile := "tls.key"
	if meta.VolumeContext[v1alpha1.KeyFileKey] != "" {
		pkFile = meta.VolumeContext[v1alpha1.KeyFileKey]
	}
	crtFile := "tls.crt"
	if meta.VolumeContext[v1alpha1.CertFileKey] != "" {
		crtFile = meta.VolumeContext[v1alpha1.CertFileKey]
	}
	caFile := "ca.crt"
	if meta.VolumeContext[v1alpha1.CAFileKey] != "" {
		caFile = meta.VolumeContext[v1alpha1.CAFileKey]
	}

	nextIssuanceTime, err := calculateNextIssuanceTime(meta, chain)
	if err != nil {
		return fmt.Errorf("calculating next issuance time: %w", err)
	}

	if err := w.store.WriteFiles(meta.VolumeID, map[string][]byte{
		pkFile:  keyPEM,
		crtFile: chain,
		caFile:  ca,
	}); err != nil {
		return fmt.Errorf("writing data: %w", err)
	}

	meta.NextIssuanceTime = &nextIssuanceTime
	if err := w.store.WriteMetadata(meta.VolumeID, meta); err != nil {
		return fmt.Errorf("writing metadata: %w", err)
	}

	return nil
}

func calculateNextIssuanceTime(meta metadata.Metadata, chain []byte) (time.Time, error) {
	block, _ := pem.Decode(chain)
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing issued certificate: %w", err)
	}

	actualDuration := crt.NotAfter.Sub(crt.NotBefore)
	// if not explicitly set, renew once a certificate is 2/3rds of the way through its lifetime
	renewBeforeNotAfter := actualDuration / 3
	if meta.VolumeContext[v1alpha1.RenewBeforeKey] != "" {
		renewBeforeDuration, err := time.ParseDuration(meta.VolumeContext[v1alpha1.RenewBeforeKey])
		if err != nil {
			return time.Time{}, fmt.Errorf("parsing requested renew-before duration: %w", err)
		}

		// If the requested renewBefore would cause the certificate to be immediately re-issued,
		// ignore the requested renew before and renew 2/3rds of the way through its lifetime.
		if crt.NotBefore.Add(renewBeforeDuration).Before(crt.NotAfter) {
			renewBeforeNotAfter = renewBeforeDuration
		}
	}

	return crt.NotAfter.Add(-renewBeforeNotAfter), nil
}

func parseIPAddresses(ips string) []net.IP {
	if len(ips) == 0 {
		return nil
	}

	ipsS := strings.Split(ips, ",")

	var ipAddresses []net.IP

	for _, ipName := range ipsS {
		ip := net.ParseIP(ipName)
		if ip != nil {
			ipAddresses = append(ipAddresses, ip)
		}
	}

	return ipAddresses
}

func parseURIs(uris string) ([]*url.URL, error) {
	if len(uris) == 0 {
		return nil, nil
	}

	urisS := strings.Split(uris, ",")

	var urisURL []*url.URL

	for _, uriS := range urisS {
		uri, err := url.Parse(uriS)
		if err != nil {
			return nil, err
		}

		urisURL = append(urisURL, uri)
	}

	return urisURL, nil
}

func keyUsagesFromAttributes(usagesCSV string) []cmapi.KeyUsage {
	if len(usagesCSV) == 0 {
		return nil
	}

	var keyUsages []cmapi.KeyUsage
	for _, usage := range strings.Split(usagesCSV, ",") {
		keyUsages = append(keyUsages, cmapi.KeyUsage(strings.TrimSpace(usage)))
	}

	return keyUsages
}
