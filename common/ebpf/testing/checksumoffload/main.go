//go:build linux

// checksumoffload verifies TC packet rewriting against real NIC offload.
// It is a manual hardware test; see the companion documentation before use.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	statusPass        = "PASS"
	statusFail        = "FAIL"
	statusUnsupported = "UNSUPPORTED"
	statusNotTested   = "NOT_TESTED"
)

var (
	offloadFeatures = []string{
		"rx-checksumming",
		"tx-checksumming",
		"generic-segmentation-offload",
		"tcp-segmentation-offload",
		"generic-receive-offload",
		"tx-udp-segmentation",
	}
	offloadMatrix = []offloadCombination{
		{name: "all-on", states: featureStates(true, true, true, true, true, true)},
		{name: "all-off", states: featureStates(false, false, false, false, false, false)},
		{name: "tx-checksum-off-only", states: featureStates(true, false, true, true, true, true)},
		{name: "tso-gso-off-only", states: featureStates(true, true, false, false, true, false)},
	}
	packetLossPattern = regexp.MustCompile(`([0-9]+)% packet loss`)
)

type config struct {
	localInterface   string
	remoteHost       string
	remoteUser       string
	downstreamHost   string
	downstreamUser   string
	diagnosticsURL   string
	diagnosticsToken string
	fakeIPTarget     string
	remoteIPv6       string
	tcpPort          int
	udpPort          int
	pingCount        int
	transferBytes    int
	outputDirectory  string
	testRole         string
	ssh              []string
	downstreamSSH    []string
}

type offloadCombination struct {
	name   string
	states map[string]bool
}

type result struct {
	combination string
	check       string
	status      string
	detail      string
}

type runner struct {
	config   config
	report   *os.File
	writer   *csv.Writer
	results  []result
	original map[string]string
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	configuration, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		return 1
	}
	if err = os.MkdirAll(configuration.outputDirectory, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "create output directory:", err)
		return 4
	}
	report, err := os.Create(filepath.Join(configuration.outputDirectory, "report.tsv"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "create report:", err)
		return 4
	}
	r := &runner{config: configuration, report: report, original: make(map[string]string)}
	r.writer = csv.NewWriter(report)
	r.writer.Comma = '\t'
	if err = r.writer.Write([]string{"feature_state", "check", "result", "detail"}); err != nil {
		_ = report.Close()
		fmt.Fprintln(os.Stderr, "write report header:", err)
		return 4
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer func() {
		r.restoreOffload(context.Background())
		r.writer.Flush()
		_ = r.report.Close()
	}()

	if err = r.captureOriginal(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "read offload state:", err)
		return 2
	}
	for _, combination := range offloadMatrix {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "interrupted")
			return 1
		}
		r.runCombination(ctx, combination)
	}
	r.writer.Flush()
	if err = r.writer.Error(); err != nil {
		fmt.Fprintln(os.Stderr, "write report:", err)
		return 4
	}
	return r.summary()
}

func loadConfig() (config, error) {
	c := config{
		localInterface:   os.Getenv("LOCAL_IFACE"),
		remoteHost:       os.Getenv("REMOTE_HOST"),
		remoteUser:       envOr("REMOTE_SSH_USER", "root"),
		downstreamHost:   os.Getenv("DOWNSTREAM_HOST"),
		diagnosticsURL:   os.Getenv("DUT_DIAGNOSTICS_URL"),
		diagnosticsToken: os.Getenv("DUT_DIAGNOSTICS_TOKEN"),
		fakeIPTarget:     os.Getenv("REMOTE_FAKEIP_TARGET"),
		remoteIPv6:       os.Getenv("REMOTE_IPV6"),
		outputDirectory:  envOr("OUT_DIR", "./checksum-offload-report"),
		testRole:         envOr("TEST_ROLE", "both"),
		ssh:              strings.Fields(envOr("SSH", "ssh -o BatchMode=yes -o ConnectTimeout=5")),
		downstreamSSH:    strings.Fields(envOr("DOWNSTREAM_SSH", "ssh -o BatchMode=yes -o ConnectTimeout=5")),
	}
	c.downstreamUser = envOr("DOWNSTREAM_SSH_USER", c.remoteUser)
	var err error
	if c.pingCount, err = envInt("PING_COUNT", 20); err != nil {
		return c, err
	}
	if c.transferBytes, err = envInt("TRANSFER_BYTES", 8<<20); err != nil {
		return c, err
	}
	if c.tcpPort, err = optionalPort("REMOTE_PORT_TCP"); err != nil {
		return c, err
	}
	if c.udpPort, err = optionalPort("REMOTE_PORT_UDP"); err != nil {
		return c, err
	}
	for name, value := range map[string]string{
		"LOCAL_IFACE":          c.localInterface,
		"REMOTE_HOST":          c.remoteHost,
		"FAKEIP_PREFIX":        os.Getenv("FAKEIP_PREFIX"),
		"REMOTE_FAKEIP_TARGET": c.fakeIPTarget,
	} {
		if value == "" {
			return c, fmt.Errorf("%s is required", name)
		}
	}
	fakeIPPrefix, err := netip.ParsePrefix(os.Getenv("FAKEIP_PREFIX"))
	if err != nil {
		return c, fmt.Errorf("FAKEIP_PREFIX: %w", err)
	}
	fakeIPTarget, err := netip.ParseAddr(c.fakeIPTarget)
	if err != nil {
		return c, fmt.Errorf("REMOTE_FAKEIP_TARGET: %w", err)
	}
	if !fakeIPPrefix.Contains(fakeIPTarget) {
		return c, fmt.Errorf("REMOTE_FAKEIP_TARGET is outside FAKEIP_PREFIX")
	}
	if c.remoteIPv6 != "" {
		if address, parseErr := netip.ParseAddr(c.remoteIPv6); parseErr != nil || !address.Is6() {
			return c, fmt.Errorf("REMOTE_IPV6 must be an IPv6 address")
		}
	}
	if c.testRole != "local" && c.testRole != "shared" && c.testRole != "both" {
		return c, fmt.Errorf("TEST_ROLE must be local, shared, or both")
	}
	if c.testRole != "local" && c.downstreamHost == "" {
		return c, fmt.Errorf("TEST_ROLE=%s requires DOWNSTREAM_HOST", c.testRole)
	}
	if len(c.ssh) == 0 || len(c.downstreamSSH) == 0 {
		return c, fmt.Errorf("SSH commands must not be empty")
	}
	return c, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func optionalPort(name string) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return 0, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s must be a valid port", name)
	}
	return port, nil
}

func featureStates(values ...bool) map[string]bool {
	states := make(map[string]bool, len(offloadFeatures))
	for index, feature := range offloadFeatures {
		states[feature] = values[index]
	}
	return states
}

func (r *runner) captureOriginal(ctx context.Context) error {
	states, err := r.readFeatures(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "original %s offload state:\n", r.config.localInterface)
	for _, feature := range offloadFeatures {
		state := states[feature]
		if state == "" {
			state = "unsupported"
		}
		r.original[feature] = state
		fmt.Fprintf(os.Stderr, "  %s = %s\n", feature, state)
	}
	return nil
}

func (r *runner) readFeatures(ctx context.Context) (map[string]string, error) {
	output, err := commandOutput(ctx, nil, "ethtool", "-k", r.config.localInterface)
	if err != nil {
		return nil, err
	}
	states := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		if fields[1] == "on" || fields[1] == "off" {
			states[name] = fields[1]
		}
	}
	return states, nil
}

func (r *runner) restoreOffload(ctx context.Context) {
	for _, feature := range offloadFeatures {
		state := r.original[feature]
		if state != "on" && state != "off" {
			continue
		}
		restoreCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, _ = commandOutput(restoreCtx, nil, "ethtool", "-K", r.config.localInterface, feature, state)
		cancel()
	}
	if len(r.original) > 0 {
		fmt.Fprintf(os.Stderr, "restored %s offload settings\n", r.config.localInterface)
	}
}

func (r *runner) applyCombination(ctx context.Context, combination offloadCombination) bool {
	ok := true
	for _, feature := range offloadFeatures {
		want := "off"
		if combination.states[feature] {
			want = "on"
		}
		if r.original[feature] == "unsupported" {
			fmt.Fprintf(os.Stderr, "warning: %s is unsupported on %s\n", feature, r.config.localInterface)
			ok = false
			continue
		}
		if _, err := commandOutput(ctx, nil, "ethtool", "-K", r.config.localInterface, feature, want); err != nil {
			fmt.Fprintf(os.Stderr, "warning: set %s=%s: %v\n", feature, want, err)
			ok = false
		}
	}
	states, err := r.readFeatures(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: read final offload state:", err)
		return false
	}
	for _, feature := range offloadFeatures {
		want := "off"
		if combination.states[feature] {
			want = "on"
		}
		if r.original[feature] != "unsupported" && states[feature] != want {
			fmt.Fprintf(os.Stderr, "warning: %s=%s was not confirmed (reported %q)\n", feature, want, states[feature])
			ok = false
		}
	}
	return ok
}

func (r *runner) runCombination(ctx context.Context, combination offloadCombination) {
	fmt.Fprintf(os.Stderr, "=== combination: %s ===\n", combination.name)
	if !r.applyCombination(ctx, combination) {
		r.record(combination.name, "combination_setup", statusUnsupported, "one or more requested features could not be applied; no traffic checks ran")
		return
	}
	localCapture := filepath.Join(r.config.outputDirectory, combination.name+".local.pcap")
	remoteCapture := "/tmp/offload_check_" + combination.name + ".pcap"
	captureCtx, cancelCapture := context.WithCancel(ctx)
	localCaptureCommand := exec.CommandContext(captureCtx, "tcpdump", "-i", r.config.localInterface, "-w", localCapture)
	_ = localCaptureCommand.Start()
	_, _ = r.remote(ctx, false, nil, "nohup timeout 40 tcpdump -i any -w "+remoteCapture+" >/dev/null 2>&1 &")
	time.Sleep(time.Second)

	r.checkBypass(ctx, combination.name)
	if r.config.testRole == "local" || r.config.testRole == "both" {
		r.checkPing(ctx, combination.name, false, 4, r.config.fakeIPTarget)
		if r.config.remoteIPv6 != "" {
			r.checkPing(ctx, combination.name, false, 6, r.config.remoteIPv6)
		}
		r.checkTCP(ctx, combination.name, false)
		r.checkUDP(ctx, combination.name, false)
	} else {
		r.record(combination.name, "local_data_plane", statusNotTested, "excluded by TEST_ROLE")
	}
	if r.config.testRole == "shared" || r.config.testRole == "both" {
		r.checkPing(ctx, combination.name, true, 4, r.config.fakeIPTarget)
		if r.config.remoteIPv6 != "" {
			r.checkPing(ctx, combination.name, true, 6, r.config.remoteIPv6)
		}
		r.checkTCP(ctx, combination.name, true)
		r.checkUDP(ctx, combination.name, true)
	} else {
		r.record(combination.name, "shared_data_plane", statusNotTested, "excluded by TEST_ROLE")
	}

	cancelCapture()
	if localCaptureCommand.Process != nil {
		_ = localCaptureCommand.Wait()
	}
	_, _ = r.remote(context.Background(), false, nil, "pkill -f 'tcpdump -i any -w "+remoteCapture+"'")
	remoteData, err := r.remote(context.Background(), false, nil, "cat "+remoteCapture)
	if err == nil {
		_ = os.WriteFile(filepath.Join(r.config.outputDirectory, combination.name+".remote.pcap"), remoteData, 0o644)
	}
}

func (r *runner) checkBypass(ctx context.Context, label string) {
	marker := fmt.Sprintf("offload-check-%d", time.Now().UnixNano())
	output, err := r.remote(ctx, false, strings.NewReader(marker+"\n"), "cat")
	if err != nil {
		r.record(label, "bypass_passthrough", statusFail, "remote SSH control channel failed: "+err.Error())
		return
	}
	if strings.TrimSpace(string(output)) != marker {
		r.record(label, "bypass_passthrough", statusFail, "SSH control-channel payload was corrupted")
		return
	}
	r.record(label, "bypass_passthrough", statusPass, "SSH control-channel round trip intact")
}

func (r *runner) checkPing(ctx context.Context, label string, downstream bool, family int, target string) {
	check := fmt.Sprintf("local_fakeip_icmp_v%d", family)
	if downstream {
		check = fmt.Sprintf("shared_fakeip_icmp_v%d", family)
	}
	var before uint64
	var err error
	if downstream && r.config.diagnosticsURL != "" {
		before, err = r.counter(ctx, "fakeip_icmp_replies")
		if err != nil {
			r.record(label, check, statusFail, "read diagnostics before ping: "+err.Error())
			return
		}
	}
	ping := "ping"
	if family == 6 {
		ping = "ping6"
	}
	args := []string{"-c", strconv.Itoa(r.config.pingCount), "-q", target}
	var output []byte
	if downstream {
		output, err = r.remote(ctx, true, nil, strings.Join(append([]string{ping}, args...), " "))
	} else {
		output, err = commandOutput(ctx, nil, ping, args...)
	}
	if err != nil {
		r.record(label, check, statusFail, "ping failed: "+strings.TrimSpace(string(output)))
		return
	}
	loss := packetLossPattern.FindSubmatch(output)
	if len(loss) != 2 || string(loss[1]) != "0" {
		r.record(label, check, statusFail, "unexpected packet loss: "+strings.TrimSpace(string(output)))
		return
	}
	detail := fmt.Sprintf("0%% loss over %d pings", r.config.pingCount)
	if downstream && r.config.diagnosticsURL != "" {
		after, counterErr := r.counter(ctx, "fakeip_icmp_replies")
		if counterErr != nil {
			r.record(label, check, statusFail, "read diagnostics after ping: "+counterErr.Error())
			return
		}
		if after <= before {
			r.record(label, check, statusFail, fmt.Sprintf("ping passed but fakeip_icmp_replies did not advance (%d -> %d)", before, after))
			return
		}
		detail += fmt.Sprintf("; fakeip_icmp_replies advanced %d -> %d", before, after)
	}
	r.record(label, check, statusPass, detail)
}

func (r *runner) checkTCP(ctx context.Context, label string, downstream bool) {
	if r.config.tcpPort == 0 {
		return
	}
	check, receivePath := "local_shared_rewrite_tcp", "/tmp/offload_check_tcp.bin"
	if downstream {
		check, receivePath = "shared_rewrite_tcp", "/tmp/offload_check_tcp_shared.bin"
	}
	payload, err := randomPayload(r.config.transferBytes)
	if err != nil {
		r.record(label, check, statusFail, "prepare payload: "+err.Error())
		return
	}
	var rewriteBefore uint64
	if downstream && r.config.diagnosticsURL != "" {
		rewriteBefore, err = r.counter(ctx, "rewrite_failures")
		if err != nil {
			r.record(label, check, statusFail, "read diagnostics before transfer: "+err.Error())
			return
		}
	}
	listener, err := r.startRemote(ctx, "timeout 30 nc -l -p "+strconv.Itoa(r.config.tcpPort)+" > "+receivePath)
	if err != nil {
		r.record(label, check, statusFail, "start remote receiver: "+err.Error())
		return
	}
	time.Sleep(time.Second)
	if downstream {
		sendPath := "/tmp/offload_check_tcp_shared_sent.bin"
		if _, err = r.remote(ctx, true, bytes.NewReader(payload), "cat > "+sendPath); err == nil {
			_, err = r.remote(ctx, true, nil, "timeout 25 nc -q1 "+r.config.fakeIPTarget+" "+strconv.Itoa(r.config.tcpPort)+" < "+sendPath)
		}
	} else {
		transferCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		_, err = commandOutput(transferCtx, bytes.NewReader(payload), "nc", "-q1", r.config.fakeIPTarget, strconv.Itoa(r.config.tcpPort))
		cancel()
	}
	waitCommand(listener)
	if err != nil {
		r.record(label, check, statusFail, "transfer failed: "+err.Error())
		return
	}
	if err = r.compareRemotePayload(ctx, payload, receivePath); err != nil {
		r.record(label, check, statusFail, err.Error())
		return
	}
	if downstream && r.config.diagnosticsURL != "" {
		after, counterErr := r.counter(ctx, "rewrite_failures")
		if counterErr != nil {
			r.record(label, check, statusFail, "read diagnostics after transfer: "+counterErr.Error())
			return
		}
		if after > rewriteBefore {
			r.record(label, check, statusFail, fmt.Sprintf("rewrite_failures advanced %d -> %d", rewriteBefore, after))
			return
		}
	}
	r.record(label, check, statusPass, fmt.Sprintf("received payload matches (%d bytes, %s)", len(payload), payloadHash(payload)))
}

func (r *runner) checkUDP(ctx context.Context, label string, downstream bool) {
	if r.config.udpPort == 0 {
		return
	}
	check, receivePath := "local_shared_rewrite_udp", "/tmp/offload_check_udp.bin"
	if downstream {
		check, receivePath = "shared_rewrite_udp", "/tmp/offload_check_udp_shared.bin"
	}
	payload, err := randomPayload(65000)
	if err != nil {
		r.record(label, check, statusFail, "prepare payload: "+err.Error())
		return
	}
	for attempt := 1; attempt <= 3; attempt++ {
		listener, startErr := r.startRemote(ctx, "timeout 15 nc -u -l -p "+strconv.Itoa(r.config.udpPort)+" -w 10 > "+receivePath)
		if startErr != nil {
			r.record(label, check, statusFail, "start remote receiver: "+startErr.Error())
			return
		}
		time.Sleep(time.Second)
		if downstream {
			sendPath := "/tmp/offload_check_udp_shared_sent.bin"
			if _, err = r.remote(ctx, true, bytes.NewReader(payload), "cat > "+sendPath); err == nil {
				_, err = r.remote(ctx, true, nil, "nc -u -q1 -w2 "+r.config.fakeIPTarget+" "+strconv.Itoa(r.config.udpPort)+" < "+sendPath)
			}
		} else {
			_, err = commandOutput(ctx, bytes.NewReader(payload), "nc", "-u", "-q1", "-w2", r.config.fakeIPTarget, strconv.Itoa(r.config.udpPort))
		}
		waitCommand(listener)
		received, readErr := r.remote(ctx, false, nil, "cat "+receivePath)
		if readErr != nil {
			r.record(label, check, statusFail, fmt.Sprintf("read attempt %d receipt: %v", attempt, readErr))
			return
		}
		if len(received) == 0 {
			fmt.Fprintf(os.Stderr, "warning: no UDP data received on attempt %d/3 (send error %v); retrying\n", attempt, err)
			continue
		}
		if sha256.Sum256(received) != sha256.Sum256(payload) {
			r.record(label, check, statusFail, fmt.Sprintf("content mismatch on attempt %d", attempt))
			return
		}
		r.record(label, check, statusPass, fmt.Sprintf("received datagram matches on attempt %d/3 (%s)", attempt, payloadHash(payload)))
		return
	}
	r.record(label, check, statusFail, "no data received after 3 attempts")
}

func (r *runner) compareRemotePayload(ctx context.Context, sent []byte, path string) error {
	received, err := r.remote(ctx, false, nil, "cat "+path)
	if err != nil {
		return fmt.Errorf("read received payload: %w", err)
	}
	if sha256.Sum256(received) != sha256.Sum256(sent) {
		return fmt.Errorf("content mismatch: sent %s, received %s", payloadHash(sent), payloadHash(received))
	}
	return nil
}

func randomPayload(size int) ([]byte, error) {
	payload := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, payload)
	return payload, err
}

func payloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (r *runner) counter(ctx context.Context, name string) (uint64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.config.diagnosticsURL, nil)
	if err != nil {
		return 0, err
	}
	if r.config.diagnosticsToken != "" {
		request.Header.Set("Authorization", "Bearer "+r.config.diagnosticsToken)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return 0, fmt.Errorf("HTTP status %s", response.Status)
	}
	var document struct {
		EBPF []struct {
			Counters map[string]uint64 `json:"counters"`
		} `json:"ebpf"`
	}
	if err = json.NewDecoder(response.Body).Decode(&document); err != nil {
		return 0, err
	}
	if len(document.EBPF) == 0 {
		return 0, errors.New("diagnostics contains no eBPF inbound")
	}
	value, loaded := document.EBPF[0].Counters[name]
	if !loaded {
		return 0, fmt.Errorf("counter %s is absent", name)
	}
	return value, nil
}

func (r *runner) remote(ctx context.Context, downstream bool, input io.Reader, command string) ([]byte, error) {
	base, user, host := r.config.ssh, r.config.remoteUser, r.config.remoteHost
	if downstream {
		base, user, host = r.config.downstreamSSH, r.config.downstreamUser, r.config.downstreamHost
	}
	arguments := append(append([]string(nil), base[1:]...), user+"@"+host, command)
	return commandStdout(ctx, input, base[0], arguments...)
}

func (r *runner) startRemote(ctx context.Context, command string) (*exec.Cmd, error) {
	base := r.config.ssh
	arguments := append(append([]string(nil), base[1:]...), r.config.remoteUser+"@"+r.config.remoteHost, command)
	cmd := exec.CommandContext(ctx, base[0], arguments...)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func waitCommand(command *exec.Cmd) {
	if command != nil {
		_ = command.Wait()
	}
}

func commandOutput(ctx context.Context, input io.Reader, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdin = input
	return command.CombinedOutput()
}

func commandStdout(ctx context.Context, input io.Reader, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdin = input
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil && stderr.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return output, err
}

func (r *runner) record(combination, check, status, detail string) {
	entry := result{combination: combination, check: check, status: status, detail: detail}
	r.results = append(r.results, entry)
	if err := r.writer.Write([]string{combination, check, status, detail}); err != nil {
		fmt.Fprintln(os.Stderr, "write report entry:", err)
	}
	fmt.Fprintf(os.Stderr, "%s\t%s\t%s\t%s\n", combination, check, status, detail)
}

func (r *runner) summary() int {
	counts := make(map[string]int)
	for _, entry := range r.results {
		counts[entry.status]++
	}
	fmt.Fprintf(os.Stderr, "summary: %d PASS, %d FAIL, %d UNSUPPORTED, %d NOT_TESTED (TEST_ROLE=%s)\n",
		counts[statusPass], counts[statusFail], counts[statusUnsupported], counts[statusNotTested], r.config.testRole)
	switch {
	case counts[statusFail] > 0:
		return 1
	case counts[statusPass] == 0:
		return 2
	case counts[statusUnsupported] > 0:
		return 3
	default:
		return 0
	}
}
