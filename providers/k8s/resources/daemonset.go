package resources

import (
	"errors"
	"sync"

	"go.mondoo.com/cnquery/llx"
	"go.mondoo.com/cnquery/providers-sdk/v1/util/convert"
	"go.mondoo.com/cnquery/providers/k8s/connection/shared/resources"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type mqlK8sDaemonsetInternal struct {
	lock sync.Mutex
	obj  *appsv1.DaemonSet
}

func (k *mqlK8s) daemonsets() ([]interface{}, error) {
	return k8sResourceToMql(k.MqlRuntime, "daemonsets", func(kind string, resource runtime.Object, obj metav1.Object, objT metav1.Type) (interface{}, error) {
		ts := obj.GetCreationTimestamp()

		manifest, err := convert.JsonToDict(resource)
		if err != nil {
			return nil, err
		}

		podSpec, err := resources.GetPodSpec(resource)
		if err != nil {
			return nil, err
		}

		podSpecDict, err := convert.JsonToDict(podSpec)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(k.MqlRuntime, "k8s.daemonset", map[string]*llx.RawData{
			"id":              llx.StringData(objIdFromK8sObj(obj, objT)),
			"uid":             llx.StringData(string(obj.GetUID())),
			"resourceVersion": llx.StringData(obj.GetResourceVersion()),
			"name":            llx.StringData(obj.GetName()),
			"namespace":       llx.StringData(obj.GetNamespace()),
			"kind":            llx.StringData(objT.GetKind()),
			"created":         llx.TimeData(ts.Time),
			"manifest":        llx.DictData(manifest),
			"podSpec":         llx.DictData(podSpecDict),
		})
		if err != nil {
			return nil, err
		}

		d, ok := resource.(*appsv1.DaemonSet)
		if !ok {
			return nil, errors.New("not a k8s daemonset")
		}
		r.(*mqlK8sDaemonset).obj = d
		return r, nil
	})
}

func (k *mqlK8sDaemonset) id() (string, error) {
	return k.Id.Data, nil
}

// func (p *mqlK8sDaemonset) init(args *resources.Args) (*resources.Args, K8sDaemonset, error) {
// 	return initNamespacedResource[K8sDaemonset](args, p.MotorRuntime, func(k K8s) ([]interface{}, error) { return k.Daemonsets() })
// }

func (k *mqlK8sDaemonset) annotations() (map[string]interface{}, error) {
	return convert.MapToInterfaceMap(k.obj.GetAnnotations()), nil
}

func (k *mqlK8sDaemonset) labels() (map[string]interface{}, error) {
	return convert.MapToInterfaceMap(k.obj.GetLabels()), nil
}

func (k *mqlK8sDaemonset) initContainers() ([]interface{}, error) {
	return getContainers(k.obj, &k.obj.ObjectMeta, k.MqlRuntime, InitContainerType)
}

func (k *mqlK8sDaemonset) containers() ([]interface{}, error) {
	return getContainers(k.obj, &k.obj.ObjectMeta, k.MqlRuntime, ContainerContainerType)
}