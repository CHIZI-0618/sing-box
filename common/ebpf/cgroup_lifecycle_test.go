//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"os"
	"strings"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// newUndetachableCgroupBackend builds a backend whose close cannot finish.
//
// The cgroup handle is a real directory, so the exclusive lock and the file
// descriptor behave exactly as they do in production, and one slot is marked
// attached with a real program but no link. Detaching that slot therefore takes
// the raw path and asks the kernel to detach from a plain directory, which
// fails the way an undetachable program does. A nil program would not do: the
// raw detach reads its descriptor and would crash rather than fail.
func newUndetachableCgroupBackend(t *testing.T) (*CgroupBackend, string, *CiliumEBPF.Map) {
	t.Helper()
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Type: CiliumEBPF.SocketFilter,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		t.Skipf("cannot load a program to detach: %v", err)
	}
	t.Cleanup(func() { _ = program.Close() })

	directory := t.TempDir()
	cgroupFile, err := os.Open(directory)
	if err != nil {
		t.Fatalf("open the stand-in cgroup: %v", err)
	}
	if err = unix.Flock(int(cgroupFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = cgroupFile.Close()
		t.Fatalf("lock the stand-in cgroup: %v", err)
	}
	// A real map, so a test can tell whether the close actually released the map
	// handles rather than only the ones it happens to look at.
	mapInstance, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("cannot create a map to release: %v", err)
	}
	programs := make([]*CiliumEBPF.Program, cgroupProgramCount)
	programs[cgroupProgramCount-1] = program
	backend := &CgroupBackend{cgroupPath: directory}
	backend.runtime = &cgroupRuntime{
		cgroupFile: cgroupFile,
		maps:       map[string]*CiliumEBPF.Map{"test": mapInstance},
		programs:   programs,
	}
	backend.runtime.attached[cgroupProgramCount-1] = true
	t.Cleanup(func() {
		if backend.runtime != nil && backend.runtime.cgroupFile != nil {
			_ = backend.runtime.cgroupFile.Close()
		}
	})
	return backend, directory, mapInstance
}

// lockable reports whether the directory can be opened and exclusively locked,
// which is what PrepareCgroup does before it will take a cgroup over.
func lockable(t *testing.T, directory string) bool {
	t.Helper()
	file, err := os.Open(directory)
	if err != nil {
		t.Fatalf("open %s: %v", directory, err)
	}
	defer file.Close()
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil
}

// TestCgroupBackendCloseRetainsRuntimeWhenDetachFails pins the deliberate half
// of the behaviour: a close that cannot detach keeps everything it would need to
// try again, and says so rather than reporting success.
func TestCgroupBackendCloseRetainsRuntimeWhenDetachFails(t *testing.T) {
	backend, directory, mapInstance := newUndetachableCgroupBackend(t)

	if err := backend.Close(); err == nil {
		t.Fatal("a close that could not detach reported success")
	}
	if mapInstance.FD() < 0 {
		t.Fatal("the map handle was released even though the close did not finish")
	}
	if backend.IsClosed() {
		t.Fatal("the backend reports itself closed after a failed detach")
	}
	if backend.runtime == nil {
		t.Fatal("the runtime was dropped, losing the handles a retry needs")
	}
	if backend.runtime.cgroupFile == nil {
		t.Fatal("the cgroup handle was dropped, so no retry can detach anything")
	}
	// The retained handle still holds the lock, which is what a later
	// PrepareCgroup on the same cgroup would have to take.
	if lockable(t, directory) {
		t.Fatal("the retained cgroup handle no longer holds its lock")
	}
}

// TestCgroupBackendCloseReleasesResourcesOnceDetachIsNotNeeded covers the
// manageability question: the retained state is not inert, and a later close
// finishes the job.
//
// It does not show that a second detach succeeds. The attached flag is cleared
// by hand to represent the program no longer being attached, which is the state
// a successful detach would leave; making the detach itself succeed would need a
// real cgroup and a really attached program. What it does show is that once
// nothing is left to detach, the close releases the map handle and the cgroup
// handle, and the cgroup can be locked again.
func TestCgroupBackendCloseReleasesResourcesOnceDetachIsNotNeeded(t *testing.T) {
	backend, directory, mapInstance := newUndetachableCgroupBackend(t)

	if err := backend.Close(); err == nil {
		t.Fatal("a close that could not detach reported success")
	}

	backend.runtime.attached[cgroupProgramCount-1] = false

	if err := backend.Close(); err != nil {
		t.Fatalf("the later close did not finish: %v", err)
	}
	if !backend.IsClosed() {
		t.Fatal("the backend still reports itself open after a close that finished")
	}
	if mapInstance.FD() >= 0 {
		t.Fatalf("the map handle survived the close: fd=%d", mapInstance.FD())
	}
	if !lockable(t, directory) {
		t.Fatal("the cgroup is still locked, so it cannot be taken over again")
	}
}

// TestCgroupBackendCloseIsIdempotentOnceClosed covers the ordinary repeat: a
// close after a successful one does nothing and reports nothing.
func TestCgroupBackendCloseIsIdempotentOnceClosed(t *testing.T) {
	backend, _, _ := newUndetachableCgroupBackend(t)
	backend.runtime.attached[cgroupProgramCount-1] = false

	if err := backend.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := backend.Close(); err != nil {
		t.Fatalf("a repeated close reported an error: %v", err)
	}
	if !backend.IsClosed() {
		t.Fatal("the backend does not report itself closed")
	}
}

// TestCgroupLockBlocksAnotherOpen states the property the retained handle turns
// into a problem: the lock belongs to the open file, so a second open of the
// same cgroup cannot take it while the first is held, and PrepareCgroup reports
// that as the cgroup being owned by somebody else.
func TestCgroupLockBlocksAnotherOpen(t *testing.T) {
	directory := t.TempDir()
	first, err := os.Open(directory)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err = unix.Flock(int(first.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = first.Close()
		t.Fatalf("lock: %v", err)
	}
	if lockable(t, directory) {
		t.Fatal("a second open took the lock while the first still held it")
	}
	if err = first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !lockable(t, directory) {
		t.Fatal("the lock outlived the handle that held it")
	}
}

// TestLockCgroupFileReportsHeldLockNeutrally covers what a caller is told when
// the cgroup is already locked. The holder may be another running instance or a
// handle this process itself kept after a close that could not finish, and the
// lock alone does not say which, so the message must not name a cause. EBUSY is
// kept because callers match on it.
func TestLockCgroupFileReportsHeldLockNeutrally(t *testing.T) {
	directory := t.TempDir()
	holder, err := os.Open(directory)
	if err != nil {
		t.Fatalf("open the holder: %v", err)
	}
	defer holder.Close()
	if err = unix.Flock(int(holder.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("lock the holder: %v", err)
	}

	contender, err := os.Open(directory)
	if err != nil {
		t.Fatalf("open the contender: %v", err)
	}
	defer contender.Close()

	err = lockCgroupFile(contender)
	if err == nil {
		t.Fatal("locking a cgroup that is already locked reported success")
	}
	if !errors.Is(err, unix.EBUSY) {
		t.Fatalf("error = %v, want it to still report EBUSY", err)
	}
	message := err.Error()
	for _, expected := range []string{
		"the exclusive lock on this cgroup is already held",
		"another active instance",
		"an earlier close that did not finish",
		"lock cgroup",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("error = %q, want it to mention %q", message, expected)
		}
	}
	// The message must not settle on one cause.
	if strings.Contains(message, "another eBPF inbound is already active") {
		t.Fatalf("error = %q, still names another inbound as the cause", message)
	}
}

func TestLockCgroupFileSucceedsOnFreeCgroup(t *testing.T) {
	directory := t.TempDir()
	file, err := os.Open(directory)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer file.Close()
	if err = lockCgroupFile(file); err != nil {
		t.Fatalf("locking a free cgroup failed: %v", err)
	}
	if lockable(t, directory) {
		t.Fatal("the lock was not actually taken")
	}
}

// TestLockCgroupFileKeepsOtherErrorsShaped covers the errors that are not a lock
// conflict: they keep going through the shared mapping, which is what turns a
// permission failure into its own explanation.
func TestLockCgroupFileKeepsOtherErrorsShaped(t *testing.T) {
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err = file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Flocking a closed descriptor fails with EBADF rather than EWOULDBLOCK.
	err = lockCgroupFile(file)
	if err == nil {
		t.Fatal("locking through a closed descriptor reported success")
	}
	if errors.Is(err, unix.EBUSY) {
		t.Fatalf("error = %v, want it not to be reported as a lock conflict", err)
	}
	if !strings.Contains(err.Error(), "lock cgroup") {
		t.Fatalf("error = %q, want it to name the operation", err)
	}
}

// TestCgroupBackendRequiresRebuild is TestTCBackendRequiresRebuild's cgroup
// counterpart, covering the same public accessor protocol/ebpf's
// bypass_rule_set coordinator relies on. Mirrors
// TestSharedNetworkBackendRequiresRebuild.
func TestCgroupBackendRequiresRebuild(t *testing.T) {
	var backend CgroupBackend
	if backend.RequiresRebuild() {
		t.Fatal("a fresh backend reports that it requires a rebuild")
	}

	backend.runtime = &cgroupRuntime{}
	if backend.IsClosed() {
		t.Fatal("a backend with a runtime reports itself closed")
	}
	if backend.RequiresRebuild() {
		t.Fatal("an open backend reports that it requires a rebuild")
	}

	backend.health.invalidate("cgroup", "test policy")
	if backend.IsClosed() {
		t.Fatal("invalidation must not make the backend look closed")
	}
	if !backend.RequiresRebuild() {
		t.Fatal("an invalidated backend does not report that it requires a rebuild")
	}

	var absent *CgroupBackend
	if absent.RequiresRebuild() {
		t.Fatal("a nil backend reports that it requires a rebuild")
	}
}
