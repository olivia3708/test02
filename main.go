package main

import (
	"context"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultPort               = "8080"
	compatSeenodeDefaultPort  = "80"
	fallbackSelfMemMB         = 64
	fallbackWorkerMemMB       = 256
	defaultGOMAXPROCS         = 2
	gatewayMemPercent         = 14
	workerMemPercent          = 54
	httpDrainTimeout          = 8 * time.Second
	edgeKeepAlivePeriod       = 15 * time.Second
	drainPropagationWindow    = 450 * time.Millisecond
	startupOrchestrationDelay = 4 * time.Second
	dnsPropagationSettleDelay = 4 * time.Second
	tcpUserTimeoutOpt         = 18
)

func cgroupMemoryLimit() (uint64, bool) {
	candidates := []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		if s == "" || s == "max" {
			continue
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 || n >= 1<<50 {
			continue
		}
		return n, true
	}
	return 0, false
}

func deriveMemoryBudget() (gwMB, workerMB int) {
	// Safe defaults calibrated for Seenode's 0.5 GB (512 MiB) Basic/Trial tier
	gwMB, workerMB = fallbackSelfMemMB, fallbackWorkerMemMB
	limit, limited := cgroupMemoryLimit()
	if limited {
		totalMB := int(limit >> 20)
		gwMB = totalMB * gatewayMemPercent / 100
		workerMB = totalMB * workerMemPercent / 100

		// Cap combined soft ceiling at <= 68% of container RAM to prevent OOM-Kill (Exit 137)
		allowedMB := totalMB * 68 / 100
		if gwMB < 48 {
			gwMB = 48
		}
		if workerMB < 64 {
			workerMB = 64
		}
		if total := gwMB + workerMB; total > allowedMB && allowedMB >= 112 {
			gwMB = allowedMB * gatewayMemPercent / 68
			workerMB = allowedMB * workerMemPercent / 68
		}
	}

	gwMB = getEnvInt("BERMUDA_SELF_MEM_MB", gwMB)
	workerMB = getEnvInt("BERMUDA_WORKER_MEM_MB", workerMB)
	return gwMB, workerMB
}

func applyMemoryCeiling(selfMB int) {
	if selfMB < 48 {
		selfMB = 48
	}
	debug.SetMemoryLimit(int64(selfMB) << 20)
	debug.SetGCPercent(100)
}

func cgroupCPUQuota() (float64, bool) {
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 && f[0] != "max" {
			q, e1 := strconv.ParseFloat(f[0], 64)
			p, e2 := strconv.ParseFloat(f[1], 64)
			if e1 == nil && e2 == nil && q > 0 && p > 0 {
				return q / p, true
			}
		}
	}
	qb, e1 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	pb, e2 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if e1 == nil && e2 == nil {
		q, e3 := strconv.ParseFloat(strings.TrimSpace(string(qb)), 64)
		p, e4 := strconv.ParseFloat(strings.TrimSpace(string(pb)), 64)
		if e3 == nil && e4 == nil && q > 0 && p > 0 {
			return q / p, true
		}
	}
	return 0, false
}

func applyGOMAXPROCS() int {
	n := getEnvInt("BERMUDA_GOMAXPROCS", 0)
	if n == 0 {
		if q, ok := cgroupCPUQuota(); ok {
			n = int(math.Ceil(q))
		}
	}
	if n < 2 {
		n = defaultGOMAXPROCS
	}
	if cpus := runtime.NumCPU(); n > cpus && cpus > 0 {
		n = cpus
	}
	runtime.GOMAXPROCS(n)
	return n
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "${{") || strings.HasPrefix(h, "$") {
		return ""
	}
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if slashIdx := strings.IndexByte(h, '/'); slashIdx != -1 {
		h = h[:slashIdx]
	}
	h = strings.TrimRight(h, "/.")
	if idx := strings.Index(h, ":"); idx != -1 && !strings.Contains(h, "]") {
		h = h[:idx]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

// isSeenodeCnameAlias distinguishes Seenode cluster load-balancer CNAME targets
// (such as "up-de-fra1-k8s-1.apps.run-on-seenode.com" or "de-fra1-1.ingress.seenode.app")
// from an application's own public service domain (such as "test02.seenode.app").
func isSeenodeCnameAlias(h string) bool {
	h = cleanHost(h)
	if h == "" {
		return false
	}
	return strings.Contains(h, ".apps.run-on-seenode.com") ||
		strings.Contains(h, ".ingress.seenode.") ||
		strings.Contains(h, ".prod.seenode.com") ||
		strings.Contains(h, "upcloudlb.com") ||
		(strings.HasPrefix(h, "up-") && strings.HasSuffix(h, ".run-on-seenode.com"))
}

func isSeenodeManagedDomain(h string) bool {
	h = cleanHost(h)
	if h == "" {
		return false
	}
	return isSeenodeCnameAlias(h) ||
		strings.Contains(h, "seenode.app") ||
		strings.Contains(h, "seenode.com") ||
		strings.HasSuffix(h, "-service") ||
		strings.HasSuffix(h, ".cluster.local") ||
		strings.HasSuffix(h, ".svc") ||
		strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".local")
}

func isSeenodePublicDomain(h string) bool {
	h = cleanHost(h)
	if h == "" || isSeenodeCnameAlias(h) {
		return false
	}
	return (strings.Contains(h, "seenode.app") ||
		strings.Contains(h, "cloud.seenode.com") ||
		strings.Contains(h, "run-on-seenode.com")) &&
		!strings.HasSuffix(h, ".internal") &&
		!strings.HasSuffix(h, ".local") &&
		!strings.HasSuffix(h, ".cluster.local") &&
		!strings.HasSuffix(h, ".svc") &&
		!strings.HasSuffix(h, "-service")
}

func normalizeRegion(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "de-fra") || strings.Contains(s, "frankfurt") || strings.Contains(s, "fra") || strings.Contains(s, "eu-central") || strings.Contains(s, "germany") || strings.Contains(s, "de"):
		return "de-fra1"
	case strings.Contains(s, "fi-hel") || strings.Contains(s, "helsinki") || strings.Contains(s, "finland") || strings.Contains(s, "hel"):
		return "fi-hel1"
	case strings.Contains(s, "nl-ams") || strings.Contains(s, "europe-west4") || strings.Contains(s, "amsterdam") || strings.Contains(s, "nl"):
		return "europe-west4"
	case strings.Contains(s, "uk-lon") || strings.Contains(s, "london") || strings.Contains(s, "uk"):
		return "uk-lon1"
	case strings.Contains(s, "us-east") || strings.Contains(s, "virginia") || strings.Contains(s, "nyc") || strings.Contains(s, "chi"):
		return "us-east4"
	case strings.Contains(s, "us-west") || strings.Contains(s, "california") || strings.Contains(s, "oregon") || strings.Contains(s, "sjc"):
		return "us-west"
	case strings.Contains(s, "sg-sin") || strings.Contains(s, "singapore") || strings.Contains(s, "asia") || strings.Contains(s, "sin"):
		return "asia-southeast1"
	default:
		return "de-fra1"
	}
}

func resolveInfrastructureDomains() (seenodeDomain, customDomain string) {
	publicURL := cleanHost(getEnv("SEENODE_PUBLIC_URL", getEnv("SEENODE_STATIC_URL", "")))
	publicDomain := cleanHost(getEnv("SEENODE_PUBLIC_DOMAIN", getEnv("SEENODE_DOMAIN", "")))
	explicitSeenode := cleanHost(getEnv("SEENODE_DEFAULT_DOMAIN", getEnv("BERMUDA_SEENODE_DOMAIN", "")))
	customEnv := cleanHost(getEnv("CUSTOM_DOMAIN", getEnv("BERMUDA_CUSTOM_DOMAIN", "")))

	for _, candidate := range []string{explicitSeenode, publicDomain, publicURL} {
		if isSeenodePublicDomain(candidate) {
			seenodeDomain = candidate
			break
		}
	}

	for _, candidate := range []string{customEnv, publicDomain, publicURL, explicitSeenode} {
		if candidate != "" && !isSeenodeManagedDomain(candidate) {
			customDomain = candidate
			break
		}
	}

	return seenodeDomain, customDomain
}

func orchestrateCloudInfrastructure(
	ctx context.Context,
	sup *Supervisor,
	gw *Gateway,
	sn *SeenodeClient,
	cf *CloudflareClient,
	initialSN string,
	initialCF string,
	region string,
) {
	for i := 0; i < 120 && !sup.IsReady(); i++ {
		if !sleepContext(ctx, 250*time.Millisecond) {
			return
		}
	}

	if !sleepContext(ctx, startupOrchestrationDelay) {
		return
	}

	seenodeDomain := cleanHost(initialSN)
	customDomain := cleanHost(initialCF)
	if curSN, curCF, _ := sup.GetInfrastructureDomains(); seenodeDomain == "" || customDomain == "" {
		if seenodeDomain == "" && isSeenodePublicDomain(curSN) {
			seenodeDomain = curSN
		}
		if customDomain == "" && curCF != "" && !isSeenodeManagedDomain(curCF) {
			customDomain = curCF
		}
	}

	topologyUpdated := false
	loggedAfterDiscovery := false

	syncDomains := func(newSN, newCF string) {
		cleanSN := cleanHost(newSN)
		cleanCF := cleanHost(newCF)
		if isSeenodePublicDomain(cleanSN) {
			if seenodeDomain == "" || (!isFullSeenodeServiceDomain(seenodeDomain) && isFullSeenodeServiceDomain(cleanSN)) {
				if seenodeDomain != cleanSN {
					seenodeDomain = cleanSN
					topologyUpdated = true
				}
			}
		}
		if cleanCF != "" && !isSeenodeManagedDomain(cleanCF) {
			if customDomain == "" || strings.HasSuffix(cleanCF, "."+customDomain) {
				if customDomain != cleanCF {
					customDomain = cleanCF
					topologyUpdated = true
				}
			}
		}
		sup.SetInfrastructureDomains(seenodeDomain, customDomain, region)
		gw.SetInfrastructureDomains(seenodeDomain, customDomain, region)
		if cf != nil {
			if seenodeDomain != "" {
				cf.SetSeenodeOrigin(seenodeDomain)
			}
			if customDomain != "" {
				cf.SetPreferredDomain(customDomain)
			}
		}
		if sn != nil {
			if seenodeDomain != "" {
				sn.SetServiceDomain(seenodeDomain)
			}
			if customDomain != "" {
				sn.SetCustomDomain(customDomain)
			}
		}
	}

	if sn != nil && sn.IsConfigured() {
		if srvDom, err := sn.EnsureServiceDomain(ctx); err == nil && srvDom != "" {
			syncDomains(srvDom, "")
		} else if err != nil {
			log.Printf("[Seenode] Notice: Service domain lookup: %v", err)
		}

		if reg := sn.GetDiscoveredRegion(); reg != "" {
			region = normalizeRegion(reg)
			sup.SetInfrastructureDomains(seenodeDomain, customDomain, region)
			gw.SetInfrastructureDomains(seenodeDomain, customDomain, region)
		}

		if sup.IsMasterKeyAutoGenerated() && !strings.EqualFold(getEnv("BERMUDA_PERSIST_KEY", "true"), "false") {
			sn.PersistMasterKey(ctx, sup.MasterKey())
			if !sleepContext(ctx, 2*time.Second) {
				return
			}
		}
	}

	if cf != nil && cf.Token != "" {
		probeCtx, probeCancel := context.WithTimeout(ctx, 12*time.Second)
		if cfDom, err := cf.FetchZoneDomain(probeCtx); err == nil && cfDom != "" {
			syncDomains(cf.GetSeenodeOrigin(), cfDom)
		} else if err != nil {
			log.Printf("[Cloudflare] Notice: Zone domain discovery: %v", err)
		}
		probeCancel()
	}

	// Immediately log the synchronized BMB1 bundle as soon as Seenode/Cloudflare domains are discovered,
	// so the operator never has to wait for custom-domain ACME TLS polling to copy the complete bundle.
	if topologyUpdated && ctx.Err() == nil {
		log.Printf("[Runtime] Synchronized Topology: SeenodeDomain=%q | CloudflareDomain=%q | Region=%q",
			seenodeDomain, customDomain, region)
		sup.LogProvisioningLink("")
		loggedAfterDiscovery = true
	}

	var customDomInfo *SeenodeCustomDomainInfo
	var cnameRecordID string
	var cfDNSProvisioned bool

	if customDomain != "" && (sn != nil || seenodeDomain != "") {
		if sn != nil && sn.IsConfigured() {
			info, err := sn.EnsureCustomDomain(ctx, customDomain)
			if err != nil {
				log.Printf("[Seenode] Notice: Custom domain registration (%s): %v", customDomain, err)
			} else if info != nil {
				customDomInfo = info
				syncDomains(sn.GetServiceDomain(), info.Domain)
			}
		}
		if customDomInfo == nil && seenodeDomain != "" {
			certState := "PENDING_TLS"
			isValid := probeCustomDomainTLS(ctx, customDomain, defaultSeenodeIngressCNAME)
			if isValid {
				certState = "VALID"
			}
			customDomInfo = &SeenodeCustomDomainInfo{
				Domain:            customDomain,
				CNAMETarget:       defaultSeenodeIngressCNAME,
				CertificateStatus: certState,
				SSLReady:          isValid,
				RouteReady:        isValid,
				Ready:             isValid,
			}
		}
		if customDomInfo != nil && cf != nil && cf.Token != "" {
			recID, dnsErr := cf.ProvisionSeenodeDNS(ctx, customDomInfo)
			if dnsErr != nil {
				log.Printf("[Cloudflare] Warning: Automated Seenode DNS provisioning: %v", dnsErr)
			} else {
				cnameRecordID = recID
				cfDNSProvisioned = true
				_ = sleepContext(ctx, dnsPropagationSettleDelay)
			}
		}
	}

	if cf != nil && cf.Token != "" && ctx.Err() == nil {
		cf.Tune(ctx)
		syncDomains(cf.GetSeenodeOrigin(), cf.CachedZoneDomain())
	}

	autoOrange := !strings.EqualFold(getEnv("BERMUDA_CF_AUTO_ORANGE", "true"), "false")
	if cf != nil && customDomInfo != nil && !customDomInfo.IsCertificateValid() && autoOrange && ctx.Err() == nil {
		if cfDNSProvisioned || customDomInfo.RecordsVerified {
			log.Printf("[Seenode] Waiting for Let's Encrypt TLS & Route readiness on %s before enabling Cloudflare Orange Cloud...", customDomInfo.Domain)
			if sn != nil && sn.IsConfigured() {
				updatedInfo, valid := sn.WaitCustomDomainCertificate(ctx, customDomInfo.ID, customDomInfo.Domain, defaultSNCertPollWait)
				if valid && updatedInfo != nil {
					cf.PromoteCustomDomainToOrangeCloud(ctx, updatedInfo.Domain, updatedInfo.CNAMETarget, cnameRecordID)
				} else if ctx.Err() == nil {
					go watchAndPromoteCustomDomain(ctx, sn, cf, customDomInfo, cnameRecordID)
				}
			} else {
				go watchAndPromoteCustomDomain(ctx, nil, cf, customDomInfo, cnameRecordID)
			}
		} else if cf.GetZoneID() != "" {
			go watchAndPromoteCustomDomain(ctx, sn, cf, customDomInfo, cnameRecordID)
		}
	}

	if sn != nil && sn.IsConfigured() && ctx.Err() == nil {
		sn.TuneComputeAndNetwork(ctx)
	}

	if ctx.Err() == nil && !loggedAfterDiscovery && (topologyUpdated || sn != nil || cf != nil) {
		log.Printf("[Runtime] Synchronized Topology: SeenodeDomain=%q | CloudflareDomain=%q | Region=%q",
			seenodeDomain, customDomain, region)
		sup.LogProvisioningLink("")
	}
}

func watchAndPromoteCustomDomain(
	parent context.Context,
	sn *SeenodeClient,
	cf *CloudflareClient,
	info *SeenodeCustomDomainInfo,
	cnameRecordID string,
) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if sn != nil && sn.IsConfigured() {
				latest, err := sn.FetchCustomDomainStatus(ctx, info.ID, info.Domain)
				if err == nil && latest != nil && latest.IsCertificateValid() {
					log.Printf("[Seenode] ✓ Deferred TLS & Route validation completed for %s (%s)",
						latest.Domain, latest.CertificateStatus)
					cf.PromoteCustomDomainToOrangeCloud(ctx, latest.Domain, latest.CNAMETarget, cnameRecordID)
					return
				}
			} else if probeCustomDomainTLS(ctx, info.Domain, info.CNAMETarget) {
				log.Printf("[Seenode] ✓ Direct Origin TLS + Route Identity verified for %s", info.Domain)
				cf.PromoteCustomDomainToOrangeCloud(ctx, info.Domain, info.CNAMETarget, cnameRecordID)
				return
			}
		}
	}
}

func bindDualListeners(listenCfg *net.ListenConfig, primaryPort string) ([]net.Listener, []string, error) {
	strictMode := strings.EqualFold(getEnv("BERMUDA_STRICT_PORT", "false"), "true")

	seenPorts := make(map[string]struct{}, 4)
	var portsToTry []string
	addPort := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, exists := seenPorts[p]; !exists {
			seenPorts[p] = struct{}{}
			portsToTry = append(portsToTry, p)
		}
	}

	addPort(primaryPort)
	if !strictMode {
		addPort(defaultPort)
		addPort(compatSeenodeDefaultPort)
		addPort("3000")
	}

	var listeners []net.Listener
	var boundAddrs []string
	var firstErr error

	for i, p := range portsToTry {
		addr := "0.0.0.0:" + p
		ln, err := listenCfg.Listen(context.Background(), "tcp", addr)
		if err != nil {
			if i == 0 {
				firstErr = err
				if strictMode {
					return nil, nil, err
				}
				log.Printf("[Gateway] Notice: Primary port :%s unavailable (%v); binding compatibility ports...", p, err)
			}
			continue
		}
		listeners = append(listeners, ln)
		boundAddrs = append(boundAddrs, ":"+p)
	}

	if len(listeners) == 0 {
		return nil, nil, firstErr
	}
	return listeners, boundAddrs, nil
}

func teardown(
	srv *http.Server,
	gw *Gateway,
	sup *Supervisor,
	supCancel context.CancelFunc,
	cloudCancel context.CancelFunc,
	graceful bool,
) {
	hardDeadline := time.Now().Add(22 * time.Second)

	if cloudCancel != nil {
		cloudCancel()
	}

	gw.SetDraining()
	if graceful {
		log.Println("[Gateway] Stage 1/5: Health status set to 503 (traffic shedding)...")
		time.Sleep(drainPropagationWindow)
	}

	if graceful {
		log.Println("[Gateway] Stage 2/5: Draining HTTP listeners and active XHTTP streams...")
		httpDeadline := minTime(hardDeadline.Add(-7*time.Second), time.Now().Add(11*time.Second))
		httpCtx, cancelHTTP := context.WithDeadline(context.Background(), httpDeadline)
		if err := srv.Shutdown(httpCtx); err != nil {
			log.Printf("[Gateway] HTTP drain timeout (%v); closing listeners", err)
			_ = srv.Close()
		} else {
			log.Println("[Gateway] HTTP listeners drained cleanly")
		}
		cancelHTTP()

		log.Println("[Gateway] Stage 3/5: Waiting for active upgraded WebSocket tunnels...")
		tunnelDeadline := minTime(hardDeadline.Add(-5*time.Second), time.Now().Add(httpDrainTimeout))
		if tunnelDeadline.After(time.Now()) {
			tunnelCtx, cancelTunnel := context.WithDeadline(context.Background(), tunnelDeadline)
			gw.WaitTunnels(tunnelCtx)
			cancelTunnel()
		}
	} else {
		_ = srv.Close()
	}

	log.Println("[Gateway] Stage 4/5: Closing remaining sockets and idle pools...")
	gw.CloseTunnels()
	gw.CloseIdleBackendConns()

	log.Println("[Gateway] Stage 5/5: Stopping worker process group...")
	supCancel()
	remainingSupTime := time.Until(hardDeadline)
	if remainingSupTime <= 0 {
		remainingSupTime = 2 * time.Second
	}
	sup.Stop(remainingSupTime)
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.Println("[Gateway] Initializing BERMUDA PORTAL Edge Router (Seenode + Cloudflare Edition)...")

	gwMB, workerMB := deriveMemoryBudget()
	procs := applyGOMAXPROCS()

	_ = syscall.Setenv("BERMUDA_WORKER_MEM_MB", strconv.Itoa(workerMB))
	_ = syscall.Setenv("BERMUDA_WORKER_GOMAXPROCS", strconv.Itoa(procs))
	log.Printf("[Runtime] Resource budget calibrated: Gateway=%dMiB, Worker=%dMiB (GOGC=100) | GOMAXPROCS=%d",
		gwMB, workerMB, procs)

	sigCtx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSig()

	port := getEnv("BERMUDA_LISTEN_PORT", getEnv("PORT", defaultPort))
	seenodeDomain, customDomain := resolveInfrastructureDomains()

	rawRegion := getEnv("BERMUDA_REGION", getEnv("SEENODE_REGION", getEnv("REGION", "")))
	region := normalizeRegion(rawRegion)

	// NewSupervisor initializes credentials, in-memory config, and subreaper in <1ms without
	// blocking on network I/O, allowing HTTP listeners to bind immediately on container boot.
	sup := NewSupervisor()

	cfToken := sanitizeCloudflareToken(getEnv("CLOUDFLARE_API_TOKEN", getEnv("BERMUDA_CF_API_TOKEN", "")))
	cfZoneID := sanitizeExplicitCredential(getEnv("CLOUDFLARE_ZONE_ID", getEnv("BERMUDA_CF_ZONE_ID", "")))
	var cf *CloudflareClient
	if cfToken != "" {
		cf = NewCloudflareClient(cfToken, cfZoneID)
		if seenodeDomain != "" {
			cf.SetSeenodeOrigin(seenodeDomain)
		}
		if customDomain != "" {
			cf.SetPreferredDomain(customDomain)
		}
	} else {
		log.Println("[Cloudflare] Notice: CLOUDFLARE_API_TOKEN unset. Edge auto-tuning bypassed.")
	}

	snToken := sanitizeSeenodeToken(getEnv("SEENODE_API_TOKEN", getEnv("SEENODE_TOKEN", getEnv("BERMUDA_SEENODE_TOKEN", ""))))
	var sn *SeenodeClient
	if snToken != "" {
		sn = NewSeenodeClient(snToken)
		if seenodeDomain != "" {
			sn.SetServiceDomain(seenodeDomain)
		}
		if customDomain != "" {
			sn.SetCustomDomain(customDomain)
		}
	} else {
		log.Println("[Seenode] Notice: SEENODE_API_TOKEN unset. Seenode API self-provisioning bypassed.")
	}

	sup.SetInfrastructureDomains(seenodeDomain, customDomain, region)
	primaryLogDomain := customDomain
	if primaryLogDomain == "" {
		primaryLogDomain = seenodeDomain
	}
	if primaryLogDomain != "" {
		sup.SetPublicDomain(primaryLogDomain)
	}

	log.Printf("[Runtime] Initial Topology: SeenodeDomain=%q | CloudflareDomain=%q | Region=%q",
		seenodeDomain, customDomain, region)

	gw := NewGateway(sup, cf, seenodeDomain, customDomain, region)
	gw.SetSeenodeClient(sn)

	topologyUpdater := func(snDom, cfDom string) {
		sup.SetInfrastructureDomains(snDom, cfDom, region)
		gw.SetInfrastructureDomains(snDom, cfDom, region)
	}
	if cf != nil {
		cf.SetTopologyCallback(topologyUpdater)
	}
	if sn != nil {
		sn.SetTopologyCallback(topologyUpdater)
	}

	srv := &http.Server{
		Addr:              "0.0.0.0:" + port,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       16 * time.Minute,
		MaxHeaderBytes:    32 << 10,
		ConnState:         gw.TrackConnState,
	}

	listenCfg := net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     edgeKeepAlivePeriod,
			Interval: edgeKeepAlivePeriod,
			Count:    4,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeoutOpt, 90000)
			})
			return nil
		},
	}

	// Bind HTTP listeners FIRST before starting worker bootstrap so Kubernetes/Traefik
	// immediately registers the Pod endpoint in `customers/web-*-service` subsets.
	listeners, boundAddrs, err := bindDualListeners(&listenCfg, port)
	if err != nil {
		log.Fatalf("[Gateway] Fatal: Cannot bind HTTP listener on :%s: %v", port, err)
	}

	serverErrCh := make(chan error, len(listeners))
	log.Printf("[Gateway] Edge listeners active on %s (PID %d, GOMAXPROCS=%d)",
		strings.Join(boundAddrs, " & "), os.Getpid(), procs)

	for _, ln := range listeners {
		activeLn := ln
		go func() {
			if err := srv.Serve(activeLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case serverErrCh <- err:
				default:
				}
			}
		}()
	}

	supCtx, supCancel := context.WithCancel(context.Background())
	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Run(supCtx)
	}()

	// Apply tight gateway memory ceiling after initial worker bootstrap finishes
	go func() {
		select {
		case <-sup.BootstrapDone():
		case <-sigCtx.Done():
			return
		}
		runtime.GC()
		debug.FreeOSMemory()
		applyMemoryCeiling(gwMB)
	}()

	cloudCtx, cloudCancel := context.WithCancel(sigCtx)
	defer cloudCancel()
	if sn != nil || cf != nil {
		go orchestrateCloudInfrastructure(cloudCtx, sup, gw, sn, cf, seenodeDomain, customDomain, region)
	}

	select {
	case err := <-serverErrCh:
		log.Printf("[Gateway] Fatal: HTTP server error: %v", err)
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case err := <-supErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[Gateway] Fatal: Worker supervisor halted: %v", err)
		}
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case <-sigCtx.Done():
		log.Println("[Gateway] Termination signal received. Initiating graceful teardown...")
	}

	teardown(srv, gw, sup, supCancel, cloudCancel, true)
	log.Println("[Gateway] BERMUDA PORTAL Edge Router shutdown complete. Exit 0.")
}
