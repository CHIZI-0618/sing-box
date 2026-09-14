//go:build with_ebpf && (linux || android)

package runtime

import "testing"

func TestTCRuntimeNetworkInfoIsValueOnlySnapshot(t *testing.T) {
	runtime := &tcDataPlane{
		delivery: &tcDeliveryLink{deliveryName: "sb-delivery0"},
		routing: &tcPolicyRouting{
			mark:     0x10000,
			table:    2022,
			priority: 10000,
		},
	}
	info := runtime.NetworkInfo()
	if info.DeliveryInterface != "sb-delivery0" || info.RoutingMark != 0x10000 || info.RoutingTable != 2022 || info.RoutingPriority != 10000 {
		t.Fatalf("unexpected TC network snapshot: %+v", info)
	}

	// Mutating the runtime after the read must not mutate a previously returned
	// snapshot or expose the runtime's concrete resource owners.
	runtime.delivery.deliveryName = "changed"
	runtime.routing.table = 3033
	if info.DeliveryInterface != "sb-delivery0" || info.RoutingTable != 2022 {
		t.Fatalf("TC network snapshot aliases runtime state: %+v", info)
	}
}
