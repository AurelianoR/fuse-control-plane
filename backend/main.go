package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// ── Data Models ──────────────────────────────────────────────────────────────

// TokenData represents an active brokered cloud session
type TokenData struct {
	ID          string `json:"id"`
	Vendor      string `json:"vendor"`
	Provider    string `json:"provider"`
	Resource    string `json:"resource"`
	Scope       string `json:"scope"`
	ExpiresIn   string `json:"expires_in"`
	RiskLevel   string `json:"risk_level"`
	IsCritical  bool   `json:"is_critical"`
	LastSeen    string `json:"last_seen"`
	TokenUsage  int    `json:"token_usage"`   // simulated API calls / token consumption
	UsageLimit  int    `json:"usage_limit"`   // max allowed calls in session
}

// RevokeRequest is the payload for the revoke endpoint
type RevokeRequest struct {
	TokenID string `json:"token_id"`
}

// UsageSnapshot represents a point-in-time usage metric for the metrics endpoint
type UsageSnapshot struct {
	Timestamp   string         `json:"timestamp"`
	TotalTokens int            `json:"total_tokens"`
	ByProvider  map[string]int `json:"by_provider"`
	CriticalCount int          `json:"critical_count"`
}

// ── In-Memory Store ──────────────────────────────────────────────────────────

var (
	mu           sync.RWMutex
	activeTokens = []TokenData{
		{
			ID: "tok_az_1", Vendor: "Datadog Monitoring", Provider: "azure",
			Resource: "Subscription: Prod-EU", Scope: "ReaderRole",
			ExpiresIn: "45 mins", RiskLevel: "Low", IsCritical: false,
			LastSeen: time.Now().Format(time.RFC3339), TokenUsage: 1240, UsageLimit: 5000,
		},
		{
			ID: "tok_aws_2", Vendor: "Terraform Cloud Runner", Provider: "aws",
			Resource: "Account: Data-Lake-01", Scope: "s3:PutObject, s3:ListBucket",
			ExpiresIn: "12 mins", RiskLevel: "Low", IsCritical: false,
			LastSeen: time.Now().Format(time.RFC3339), TokenUsage: 890, UsageLimit: 2000,
		},
		{
			ID: "tok_gcp_3", Vendor: "External Dev Agency", Provider: "gcp",
			Resource: "Project: ML-Compute-Beta", Scope: "roles/editor (Over-Permissive)",
			ExpiresIn: "Static Key", RiskLevel: "Critical", IsCritical: true,
			LastSeen: time.Now().Format(time.RFC3339), TokenUsage: 12450, UsageLimit: 1000,
		},
		{
			ID: "tok_az_4", Vendor: "GitHub Actions CI/CD", Provider: "azure",
			Resource: "Subscription: Staging", Scope: "ContributorRole",
			ExpiresIn: "58 mins", RiskLevel: "Medium", IsCritical: false,
			LastSeen: time.Now().Format(time.RFC3339), TokenUsage: 340, UsageLimit: 3000,
		},
		{
			ID: "tok_aws_5", Vendor: "Grafana Observability", Provider: "aws",
			Resource: "Account: Prod-US-East", Scope: "CloudWatchReadOnly",
			ExpiresIn: "30 mins", RiskLevel: "Low", IsCritical: false,
			LastSeen: time.Now().Format(time.RFC3339), TokenUsage: 7800, UsageLimit: 10000,
		},
	}
	revokedIDs = map[string]bool{}
	auditLog   []string
)

// ── CORS Middleware ──────────────────────────────────────────────────────────

func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func jsonHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// GET /api/tokens — returns all active (non-revoked) sessions
func getTokensHandler(w http.ResponseWriter, r *http.Request) {
	jsonHeader(w)
	mu.RLock()
	defer mu.RUnlock()

	result := []TokenData{}
	for _, t := range activeTokens {
		if !revokedIDs[t.ID] {
			result = append(result, t)
		}
	}
	json.NewEncoder(w).Encode(result)
}

// POST /api/tokens/revoke — revokes a specific session by ID
func revokeTokenHandler(w http.ResponseWriter, r *http.Request) {
	jsonHeader(w)
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TokenID == "" {
		http.Error(w, `{"error":"invalid request body, token_id required"}`, http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	found := false
	for _, t := range activeTokens {
		if t.ID == req.TokenID {
			found = true
			revokedIDs[t.ID] = true
			entry := fmt.Sprintf("[%s] REVOKED | ID: %s | Vendor: %s | Provider: %s | Scope: %s",
				time.Now().Format(time.RFC3339), t.ID, t.Vendor, t.Provider, t.Scope)
			auditLog = append(auditLog, entry)
			log.Println("🔴 " + entry)
			break
		}
	}

	if !found {
		http.Error(w, `{"error":"token_id not found"}`, http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"success","message":"Token %s has been revoked at the Cloud Provider root."}`, req.TokenID)
}

// GET /api/metrics — returns aggregated token usage snapshot
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	jsonHeader(w)
	mu.RLock()
	defer mu.RUnlock()

	byProvider := map[string]int{}
	critical := 0
	total := 0

	for _, t := range activeTokens {
		if revokedIDs[t.ID] {
			continue
		}
		byProvider[t.Provider]++
		total++
		if t.IsCritical {
			critical++
		}
	}

	snap := UsageSnapshot{
		Timestamp:     time.Now().Format(time.RFC3339),
		TotalTokens:   total,
		ByProvider:    byProvider,
		CriticalCount: critical,
	}
	json.NewEncoder(w).Encode(snap)
}

// GET /api/audit — returns immutable revocation audit log
func auditHandler(w http.ResponseWriter, r *http.Request) {
	jsonHeader(w)
	mu.RLock()
	defer mu.RUnlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":   len(auditLog),
		"entries": auditLog,
	})
}

// GET /api/health — simple liveness probe for k8s
func healthHandler(w http.ResponseWriter, r *http.Request) {
	jsonHeader(w)
	fmt.Fprint(w, `{"status":"ok","service":"fuse-control-plane"}`)
}

// ── Background: simulate live token usage drift ───────────────────────────────

func simulateUsageDrift() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		mu.Lock()
		for i := range activeTokens {
			if revokedIDs[activeTokens[i].ID] {
				continue
			}
			// Drift usage randomly ±50 calls every 5s to show live data
			delta := rand.Intn(101) - 50
			activeTokens[i].TokenUsage = max(0, activeTokens[i].TokenUsage+delta)
			activeTokens[i].LastSeen = time.Now().Format(time.RFC3339)
		}
		mu.Unlock()
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	go simulateUsageDrift()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", cors(healthHandler))
	mux.HandleFunc("/api/tokens", cors(getTokensHandler))
	mux.HandleFunc("/api/tokens/revoke", cors(revokeTokenHandler))
	mux.HandleFunc("/api/metrics", cors(metricsHandler))
	mux.HandleFunc("/api/audit", cors(auditHandler))

	// Serve frontend static files in production (optional)
	mux.Handle("/", http.FileServer(http.Dir("./frontend")))

	port := "8080"
	log.Printf("🚀 Fuse Control Plane API listening on :%s", port)
	log.Printf("   GET  /api/health")
	log.Printf("   GET  /api/tokens")
	log.Printf("   POST /api/tokens/revoke")
	log.Printf("   GET  /api/metrics")
	log.Printf("   GET  /api/audit")

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
