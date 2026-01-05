package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"errors"

	"github.com/hubble-policy-gen/internal/aggregator"
	"github.com/hubble-policy-gen/internal/flow"
	"github.com/hubble-policy-gen/internal/policy"
)

// CachedPolicy stores a generated policy for download
type CachedPolicy struct {
	Content   []byte
	Filename  string
	CreatedAt time.Time
}

// Server represents the HTTP server for policy generation
type Server struct {
	port  int
	cache map[string]*CachedPolicy
	mu    sync.RWMutex
}

// NewServer creates a new HTTP server
func NewServer(port int) *Server {
	s := &Server{
		port:  port,
		cache: make(map[string]*CachedPolicy),
	}
	// Start cache cleanup goroutine
	go s.cleanupCache()
	return s
}

// cleanupCache removes expired cache entries
func (s *Server) cleanupCache() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, cached := range s.cache {
			// Remove entries older than 10 minutes
			if now.Sub(cached.CreatedAt) > 10*time.Minute {
				delete(s.cache, id)
			}
		}
		s.mu.Unlock()
	}
}

// generateID creates a random ID for caching
func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Start starts the HTTP server
func (s *Server) Start() error {
	http.HandleFunc("/generate", s.corsMiddleware(s.handleGenerate))
	http.HandleFunc("/download/", s.corsMiddleware(s.handleDownload))
	http.HandleFunc("/health", s.corsMiddleware(s.handleHealth))
	http.HandleFunc("/", s.handleIndex)

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("Starting server on %s", addr)
	log.Printf("POST /generate - Send Hubble flow JSON to generate CiliumNetworkPolicy YAML")
	log.Printf("GET /download/{id} - Download generated policy")
	log.Printf("GET /health - Health check endpoint")

	return http.ListenAndServe(addr, nil)
}

// corsMiddleware adds CORS headers and handles preflight requests
func (s *Server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept, X-Grafana-Action, X-Grafana-Device-Id, X-Grafana-Org-Id")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Handle preflight OPTIONS request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// handleIndex serves a simple HTML page with usage instructions
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CF2CNP - Cilium Flow to CiliumNetworkPolicy</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
            background: #0f172a;
            color: #e2e8f0;
        }
        .header {
            display: flex;
            align-items: center;
            gap: 1.5rem;
            margin-bottom: 1rem;
        }
        .logo {
            width: 80px;
            height: 80px;
        }
        h1 { 
            background: linear-gradient(135deg, #06b6d4, #8b5cf6, #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin: 0;
            font-size: 2rem;
        }
        .subtitle {
            color: #94a3b8;
            margin-top: 0.25rem;
        }
        h2 { 
            color: #06b6d4; 
            margin-top: 2rem;
            border-bottom: 1px solid #1e293b;
            padding-bottom: 0.5rem;
        }
        pre {
            background: #1e293b;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            border-left: 4px solid #8b5cf6;
        }
        code { color: #06b6d4; }
        .endpoint {
            background: #1e293b;
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
            border: 1px solid #334155;
        }
        .method { 
            background: linear-gradient(135deg, #06b6d4, #8b5cf6);
            color: #0f172a; 
            padding: 0.25rem 0.5rem; 
            border-radius: 4px; 
            font-weight: bold;
        }
        .path { color: #fbbf24; font-weight: bold; }
        textarea {
            width: 100%;
            height: 300px;
            background: #1e293b;
            color: #e2e8f0;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 1rem;
            font-family: monospace;
            resize: vertical;
        }
        textarea:focus {
            outline: none;
            border-color: #8b5cf6;
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2);
        }
        button {
            background: linear-gradient(135deg, #06b6d4, #8b5cf6);
            color: #0f172a;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
            font-weight: bold;
            margin-top: 1rem;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover { 
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(139, 92, 246, 0.4);
        }
        #result {
            margin-top: 1rem;
            white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <div class="header">
        <svg class="logo" viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg">
            <defs>
                <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#06b6d4"/>
                    <stop offset="50%" style="stop-color:#8b5cf6"/>
                    <stop offset="100%" style="stop-color:#ec4899"/>
                </linearGradient>
            </defs>
            <circle cx="64" cy="64" r="60" fill="#0f172a"/>
            <circle cx="64" cy="64" r="58" fill="none" stroke="url(#grad)" stroke-width="2" opacity="0.7"/>
            <path d="M64 16 L108 40 L108 88 L64 112 L20 88 L20 40 Z" fill="none" stroke="url(#grad)" stroke-width="3" stroke-linejoin="round" opacity="0.6"/>
            <circle cx="28" cy="52" r="5" fill="#06b6d4"/>
            <circle cx="24" cy="64" r="5" fill="#8b5cf6"/>
            <circle cx="28" cy="76" r="5" fill="#ec4899"/>
            <path d="M33 52 L48 58" fill="none" stroke="#06b6d4" stroke-width="2" stroke-linecap="round"/>
            <path d="M29 64 L48 64" fill="none" stroke="#8b5cf6" stroke-width="2" stroke-linecap="round"/>
            <path d="M33 76 L48 70" fill="none" stroke="#ec4899" stroke-width="2" stroke-linecap="round"/>
            <rect x="48" y="50" width="32" height="28" rx="4" fill="#1e293b" stroke="url(#grad)" stroke-width="2"/>
            <path d="M54 64 L70 64 M64 58 L70 64 L64 70" fill="none" stroke="#f8fafc" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            <g transform="translate(86, 48)">
                <rect x="0" y="0" width="20" height="26" rx="2" fill="#1e293b" stroke="#06b6d4" stroke-width="1.5"/>
                <line x1="4" y1="6" x2="16" y2="6" stroke="#06b6d4" stroke-width="1.5" stroke-linecap="round"/>
                <line x1="4" y1="11" x2="14" y2="11" stroke="#06b6d4" stroke-width="1" stroke-linecap="round" opacity="0.6"/>
                <line x1="4" y1="16" x2="12" y2="16" stroke="#06b6d4" stroke-width="1" stroke-linecap="round" opacity="0.6"/>
                <path d="M10 19 L10 22 Q10 25, 13 26 Q16 25, 16 22 L16 19 Z" fill="#06b6d4" opacity="0.8"/>
            </g>
            <g transform="translate(90, 68)">
                <rect x="0" y="0" width="18" height="22" rx="2" fill="#1e293b" stroke="#8b5cf6" stroke-width="1.5"/>
                <line x1="3" y1="5" x2="14" y2="5" stroke="#8b5cf6" stroke-width="1.5" stroke-linecap="round"/>
                <line x1="3" y1="9" x2="12" y2="9" stroke="#8b5cf6" stroke-width="1" stroke-linecap="round" opacity="0.6"/>
                <line x1="3" y1="13" x2="10" y2="13" stroke="#8b5cf6" stroke-width="1" stroke-linecap="round" opacity="0.6"/>
            </g>
        </svg>
        <div>
            <h1>CF2CNP</h1>
            <p class="subtitle">Cilium Flow to CiliumNetworkPolicy</p>
        </div>
    </div>
    <p>Generate CiliumNetworkPolicies from Hubble flow data.</p>

    <h2>API Endpoints</h2>
    
    <div class="endpoint">
        <span class="method">POST</span> <span class="path">/generate</span>
        <p>Send a Hubble flow JSON payload and receive a download URL or direct YAML.</p>
        <p><strong>Content-Type:</strong> application/json</p>
        <p><strong>Response:</strong> JSON with download URL (for Grafana) or YAML file (for curl)</p>
    </div>

    <div class="endpoint">
        <span class="method">GET</span> <span class="path">/download/{id}</span>
        <p>Download a generated policy by ID.</p>
    </div>

    <div class="endpoint">
        <span class="method">GET</span> <span class="path">/health</span>
        <p>Health check endpoint. Returns "OK" if the server is running.</p>
    </div>

    <h2>Try it out</h2>
    <p>Paste your Hubble flow JSON below:</p>
    <textarea id="flowInput" placeholder='{"flow": {"traffic_direction": "INGRESS", ...}}'></textarea>
    <br>
    <button onclick="generatePolicy()">Generate Policy</button>
    
    <pre id="result"></pre>

    <h2>Example using curl</h2>
    <pre><code>curl -X POST http://localhost:8080/generate \
  -H "Content-Type: application/json" \
  -d @flow.json \
  -o policy.yaml</code></pre>

    <script>
        async function generatePolicy() {
            const input = document.getElementById('flowInput').value;
            const result = document.getElementById('result');
            
            try {
                const response = await fetch('/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: input
                });
                
                if (!response.ok) {
                    const error = await response.text();
                    result.textContent = 'Error: ' + error;
                    return;
                }

                const contentType = response.headers.get('Content-Type');
                
                if (contentType && contentType.includes('application/json')) {
                    // JSON response with download URL
                    const data = await response.json();
                    result.textContent = 'Policy generated! Downloading...';
                    
                    // Open download URL
                    window.open(data.download_url, '_blank');
                } else {
                    // Direct YAML response
                    const yaml = await response.text();
                    result.textContent = yaml;
                    
                    // Extract filename from Content-Disposition header or parse from YAML
                    let filename = 'ciliumnetworkpolicy.yaml';
                    const disposition = response.headers.get('Content-Disposition');
                    if (disposition) {
                        const match = disposition.match(/filename="?([^"]+)"?/);
                        if (match) {
                            filename = match[1];
                        }
                    } else {
                        // Fallback: extract name from YAML metadata
                        const nameMatch = yaml.match(/^\s*name:\s*(.+)$/m);
                        const nsMatch = yaml.match(/^\s*namespace:\s*(.+)$/m);
                        if (nameMatch) {
                            const name = nameMatch[1].trim();
                            const ns = nsMatch ? nsMatch[1].trim() : '';
                            filename = ns ? ns + '-' + name + '.yaml' : name + '.yaml';
                        }
                    }
                    
                    const blob = new Blob([yaml], { type: 'application/x-yaml' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    a.click();
                    URL.revokeObjectURL(url);
                }
            } catch (err) {
                result.textContent = 'Error: ' + err.message;
            }
        }
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleDownload serves a cached policy file
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path: /download/{id}
	path := strings.TrimPrefix(r.URL.Path, "/download/")
	if path == "" {
		http.Error(w, "Missing download ID", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	cached, exists := s.cache[path]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Download not found or expired. Please generate the policy again.", http.StatusNotFound)
		return
	}

	// Set headers for file download
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", cached.Filename))
	w.WriteHeader(http.StatusOK)
	w.Write(cached.Content)

	log.Printf("Downloaded policy: %s", cached.Filename)
}

// handleGenerate handles policy generation requests
func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Use POST.", http.StatusMethodNotAllowed)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(body) == 0 {
		http.Error(w, "Request body is empty. Please provide Hubble flow JSON.", http.StatusBadRequest)
		return
	}

	// 🎲 Easter egg: Check for YOLO mode
	bodyStr := strings.TrimSpace(string(body))
	if strings.HasPrefix(bodyStr, "yolo ns") {
		s.handleYoloNs(w, r, bodyStr)
		return
	}

	// Parse the flow
	parsedFlow, err := flow.ParseFlowFromBytes(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse flow JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Aggregate flows (even though we have just one)
	flows := []*flow.ParsedFlow{parsedFlow}
	aggregatedFlows := aggregator.AggregateFlows(flows)

	if len(aggregatedFlows) == 0 {
		http.Error(w, "No valid flows found in request", http.StatusBadRequest)
		return
	}

	// Generate policy YAML
	generator := policy.NewGenerator("")
	yamlBytes, err := generator.GeneratePoliciesYAML(aggregatedFlows)
	if err != nil {
		if errors.Is(err, policy.ErrReplyFlow) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to generate policy: %v", err), http.StatusInternalServerError)
		return
	}

	// Determine filename from policy
	filename := "ciliumnetworkpolicy.yaml"
	if len(aggregatedFlows) > 0 {
		agg := aggregatedFlows[0]
		var namespace, appName string
		if agg.Direction == "INGRESS" {
			namespace = agg.DestNamespace
			appName = getAppName(agg.DestLabels)
		} else {
			namespace = agg.SourceNamespace
			appName = getAppName(agg.SourceLabels)
		}
		if namespace != "" && appName != "" {
			filename = fmt.Sprintf("%s-%s.yaml", namespace, sanitizeName(appName))
		}
	}

	// Check if request comes from Grafana or wants JSON response
	acceptHeader := r.Header.Get("Accept")
	grafanaAction := r.Header.Get("X-Grafana-Action")
	wantsJSON := strings.Contains(acceptHeader, "application/json") || grafanaAction != ""

	if wantsJSON {
		// Use flow UUID as cache ID, fallback to generated ID if empty
		id := parsedFlow.UUID
		if id == "" {
			id = generateID()
		}

		s.mu.Lock()
		s.cache[id] = &CachedPolicy{
			Content:   yamlBytes,
			Filename:  filename,
			CreatedAt: time.Now(),
		}
		s.mu.Unlock()

		// Build download URL
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		host := r.Host
		downloadURL := fmt.Sprintf("%s://%s/download/%s", scheme, host, id)

		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := map[string]string{
			"filename":     filename,
			"download_url": downloadURL,
			"message":      "Policy generated successfully. Use the download_url to download the file.",
		}
		json.NewEncoder(w).Encode(response)

		log.Printf("Generated policy (cached): %s, download: %s", filename, downloadURL)
	} else {
		// Direct file download for curl/wget
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		w.WriteHeader(http.StatusOK)
		w.Write(yamlBytes)

		log.Printf("Generated policy (direct): %s", filename)
	}
}

// handleYoloNs handles the YOLO namespace easter egg
func (s *Server) handleYoloNs(w http.ResponseWriter, r *http.Request, bodyStr string) {
	// Parse namespace from "yolo ns <namespace>" or default to "default"
	namespace := "default"
	parts := strings.Fields(bodyStr)
	if len(parts) >= 3 {
		namespace = parts[2]
	}

	log.Printf("YOLO MODE ACTIVATED for namespace: %s", namespace)

	// Generate the YOLO policy
	yamlBytes, err := policy.YOLONamespacePolicyYAML(namespace)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate YOLO policy: %v", err), http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("%s-yolo-allow-all-in-namespace.yaml", namespace)

	// Check if request comes from Grafana or wants JSON response
	acceptHeader := r.Header.Get("Accept")
	grafanaAction := r.Header.Get("X-Grafana-Action")
	wantsJSON := strings.Contains(acceptHeader, "application/json") || grafanaAction != ""

	if wantsJSON {
		id := generateID()

		s.mu.Lock()
		s.cache[id] = &CachedPolicy{
			Content:   yamlBytes,
			Filename:  filename,
			CreatedAt: time.Now(),
		}
		s.mu.Unlock()

		// Build download URL
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		host := r.Host
		downloadURL := fmt.Sprintf("%s://%s/download/%s", scheme, host, id)

		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := map[string]string{
			"filename":     filename,
			"download_url": downloadURL,
			"message":      "YOLO! Policy generated. Use the download_url to download the file.",
		}
		json.NewEncoder(w).Encode(response)

		log.Printf("Generated YOLO policy (cached): %s, download: %s", filename, downloadURL)
	} else {
		// Direct file download
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		w.WriteHeader(http.StatusOK)
		w.Write(yamlBytes)

		log.Printf("Generated YOLO policy (direct): %s", filename)
	}
}

// getAppName extracts the application name from labels
func getAppName(labels map[string]string) string {
	// Priority order for app name
	priorityLabels := []string{
		"app.kubernetes.io/name",
		"app.kubernetes.io/instance",
		"app.kubernetes.io/component",
	}
	fallbackLabels := []string{
		"app",
		"k8s-app",
		"name",
		"component",
		"instance",
	}

	for _, label := range priorityLabels {
		if name, ok := labels[label]; ok {
			return name
		}
	}
	for _, label := range fallbackLabels {
		if name, ok := labels[label]; ok {
			return name
		}
	}
	return "policy"
}

// sanitizeName ensures the name is valid for filenames
func sanitizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	// Remove any characters that aren't alphanumeric or hyphens
	var result strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result.WriteRune(r)
		}
	}
	return result.String()
}
