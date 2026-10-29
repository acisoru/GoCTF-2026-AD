package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	junge "github.com/skipper-ad/junge-checkers"
	"github.com/skipper-ad/junge-checkers/checkertest"
)

func TestInfo(t *testing.T) {
	result := checkertest.Info(t, checker())
	result.RequireOK(t)
	info := result.Info(t)
	if info.Vulns != 6 || !info.AttackData || info.Puts != 1 || info.Gets != 1 {
		t.Fatalf("unexpected checker info: %+v", info)
	}
}

func TestFlagReferenceRoundTrip(t *testing.T) {
	raw, err := newFlagReference(4, "flight-42", "grant-43", "token-secret", "FLAG_VALUE")
	if err != nil {
		t.Fatal(err)
	}
	ref, state, err := parseFlagReference(raw, "FLAG_VALUE", 4)
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID != "flight-42" || ref.GrantID != "grant-43" || state.Token != "token-secret" {
		t.Fatalf("unexpected decoded state: ref=%+v state=%+v", ref, state)
	}
	if strings.Contains(raw, "token-secret") {
		t.Fatal("public flag reference leaks the service token")
	}
	var public map[string]any
	if err := json.Unmarshal([]byte(raw), &public); err != nil {
		t.Fatalf("flag reference is not JSON: %v", err)
	}
}

func TestFlagReferenceRejectsWrongFlagAndPlace(t *testing.T) {
	raw, err := newFlagReference(2, "ship-1", "", "token-secret", "FLAG_A")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseFlagReference(raw, "FLAG_B", 2); err == nil {
		t.Fatal("wrong flag decrypted private state")
	}
	if _, _, err := parseFlagReference(raw, "FLAG_A", 1); err == nil {
		t.Fatal("wrong place accepted flag reference")
	}
}

func TestUnsupportedPlaceIsCheckFailed(t *testing.T) {
	result := checkertest.Put(t, checker(), "127.0.0.1", "unused", "FLAG", 7)
	result.RequireStatus(t, junge.StatusCheckFailed)
}

func TestCheckerContractAgainstService(t *testing.T) {
	service := newContractService()
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)

	check := checkertest.Check(t, checker(), server.URL)
	check.RequireOK(t)

	for place := 1; place <= 6; place++ {
		t.Run(fmt.Sprintf("place_%d", place), func(t *testing.T) {
			flag := fmt.Sprintf("FLAG_%d_ABCDEFGHIJKLMNOPQRSTUVWXYZ", place)
			put := checkertest.Put(t, checker(), server.URL, "unused", flag, place)
			put.RequireOK(t)

			var public map[string]any
			if err := json.Unmarshal([]byte(put.Stdout), &public); err != nil {
				t.Fatalf("PUT returned invalid JSON flag ID %q: %v", put.Stdout, err)
			}
			id, idOK := public["id"].(string)
			secret, secretOK := public["s"].(string)
			if !idOK || id == "" || !secretOK || secret == "" {
				t.Fatalf("PUT returned incomplete flag ID: %v", public)
			}

			get := checkertest.Get(t, checker(), server.URL, put.Stdout, flag, place)
			get.RequireOK(t)
		})
	}
}

type contractFlight struct {
	manifest   string
	navigation string
}

type contractPackage struct {
	content  []byte
	approved bool
}

type contractService struct {
	mu        sync.Mutex
	next      int
	ships     map[string][]string
	profiles  map[string]string
	jobs      map[string]string
	flights   map[string]contractFlight
	summaries map[string]string
	packages  map[string]contractPackage
}

func newContractService() *contractService {
	return &contractService{
		ships:     make(map[string][]string),
		profiles:  make(map[string]string),
		jobs:      make(map[string]string),
		flights:   make(map[string]contractFlight),
		summaries: make(map[string]string),
		packages:  make(map[string]contractPackage),
	}
}

func (s *contractService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/packages/") && strings.HasSuffix(r.URL.Path, "/content") {
		s.upload(w, r)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/rpc" {
		http.NotFound(w, r)
		return
	}

	var request map[string]any
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, "invalid JSON")
		return
	}
	result, err := s.rpc(request)
	if err != nil {
		s.writeError(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
}

func (s *contractService) rpc(request map[string]any) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	action, _ := request["action"].(string)
	switch action {
	case "register":
		id := s.id("user")
		return map[string]any{"user_id": id, "token": "token-" + id}, nil
	case "create_ship":
		id := s.id("ship")
		s.ships[id] = nil
		return map[string]any{"ship_id": id}, nil
	case "post_message":
		ship := stringField(request, "ship_id")
		s.ships[ship] = append(s.ships[ship], stringField(request, "message"))
		return map[string]any{"ok": true}, nil
	case "read_source_messages":
		return map[string]any{"messages": s.ships[stringField(request, "source_id")]}, nil
	case "bind_source":
		return nil, fmt.Errorf("source exists")
	case "create_profile":
		id := s.id("profile")
		s.profiles[id] = stringField(request, "ship_id")
		return map[string]any{"profile_id": id}, nil
	case "edit_profile":
		s.profiles[stringField(request, "profile_id")] = stringField(request, "ship_id")
		return map[string]any{"ok": true}, nil
	case "create_export":
		id := s.id("job")
		s.jobs[id] = stringField(request, "profile_id")
		return map[string]any{"job_id": id, "state": "DRAFT"}, nil
	case "run_export", "export_result":
		profile := s.jobs[stringField(request, "job_id")]
		return map[string]any{"messages": s.ships[s.profiles[profile]], "state": "DONE"}, nil
	case "create_flight":
		id := s.id("flight")
		s.flights[id] = contractFlight{
			manifest:   stringField(request, "manifest"),
			navigation: stringField(request, "navigation"),
		}
		return map[string]any{"flight_id": id}, nil
	case "read_manifest":
		return map[string]any{"manifest": s.flights[stringField(request, "flight_id")].manifest}, nil
	case "flight_public":
		return map[string]any{"geometry": "M 1 2", "map_version": "map-1", "options": "fast"}, nil
	case "report":
		return map[string]any{"manifest": s.flights[stringField(request, "flight_id")].manifest}, nil
	case "read_navigation":
		return map[string]any{"navigation": s.flights[stringField(request, "flight_id")].navigation}, nil
	case "grant_geometry":
		return map[string]any{"grant_id": s.id("grant")}, nil
	case "delegate":
		return map[string]any{"grant_id": s.id("grant")}, nil
	case "create_summary":
		id := s.id("summary")
		s.summaries[id] = stringField(request, "content")
		return map[string]any{"summary_id": id}, nil
	case "read_summary":
		return map[string]any{"content": s.summaries[stringField(request, "summary_id")]}, nil
	case "import_bulletin":
		return nil, fmt.Errorf("internal source forbidden")
	case "import_result":
		return nil, fmt.Errorf("unknown import")
	case "create_package":
		id := s.id("package")
		s.packages[id] = contractPackage{}
		return map[string]any{"package_id": id}, nil
	case "approve_package":
		id := stringField(request, "package_id")
		pkg := s.packages[id]
		pkg.approved = true
		s.packages[id] = pkg
		return map[string]any{"approved": true}, nil
	case "generate_report":
		pkg := s.packages[stringField(request, "package_id")]
		if !pkg.approved {
			return nil, fmt.Errorf("package not approved")
		}
		content, err := tarFile(pkg.content, stringField(request, "attachment"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"report": content}, nil
	default:
		return nil, fmt.Errorf("unknown action %q", action)
	}
}

func (s *contractService) upload(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "packages" || parts[2] != "content" {
		http.NotFound(w, r)
		return
	}
	content, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, err.Error())
		return
	}
	s.mu.Lock()
	pkg, ok := s.packages[parts[1]]
	if ok {
		pkg.content = content
		s.packages[parts[1]] = pkg
	}
	s.mu.Unlock()
	if !ok {
		s.writeError(w, "unknown package")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *contractService) id(prefix string) string {
	s.next++
	return prefix + "-" + strconv.Itoa(s.next)
}

func (s *contractService) writeError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": message})
}

func stringField(request map[string]any, name string) string {
	value, _ := request[name].(string)
	return value
}

func tarFile(data []byte, name string) (string, error) {
	reader := tar.NewReader(bytes.NewReader(data))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return "", fmt.Errorf("attachment %q not found", name)
		}
		if err != nil {
			return "", err
		}
		if header.Name == name {
			content, err := io.ReadAll(reader)
			return string(content), err
		}
	}
}
