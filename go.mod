module github.com/jetstack/cert-manager-csi

go 1.12

require (
	github.com/container-storage-interface/spec v1.4.0
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/jetstack/cert-manager v1.3.1
	github.com/kubernetes-csi/csi-lib-utils v0.9.1
	github.com/onsi/ginkgo v1.12.1
	github.com/onsi/gomega v1.10.1
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.1.1
	github.pie.apple.com/munnerz/cert-manager-csi-lib v0.0.0-20210507150201-6ee52b5094f2
	golang.org/x/net v0.0.0-20210224082022-3d97a244fca7
	google.golang.org/grpc v1.37.0
	k8s.io/api v0.21.0
	k8s.io/apimachinery v0.21.0
	k8s.io/client-go v0.21.0
	k8s.io/klog v1.0.0
	k8s.io/kubectl v0.21.0
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
	sigs.k8s.io/kind v0.8.1
)
