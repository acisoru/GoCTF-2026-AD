package main

import (
	"encoding/json"
	"fmt"
	"time"

	junge "github.com/skipper-ad/junge-checkers"
	"github.com/skipper-ad/junge-checkers/gen"
)

type idResult struct {
	ShipID    string `json:"ship_id"`
	FlightID  string `json:"flight_id"`
	SummaryID string `json:"summary_id"`
	GrantID   string `json:"grant_id"`
	ProfileID string `json:"profile_id"`
	JobID     string `json:"job_id"`
	PackageID string `json:"package_id"`
}

type messagesResult struct {
	Messages []string `json:"messages"`
}

type exportResult struct {
	Messages []string `json:"messages"`
	State    string   `json:"state"`
}

type manifestResult struct {
	Manifest string `json:"manifest"`
}

type flightPublicResult struct {
	Geometry   string `json:"geometry"`
	MapVersion string `json:"map_version"`
	Options    string `json:"options"`
}

type navigationResult struct {
	Navigation string `json:"navigation"`
}

type summaryResult struct {
	Content string `json:"content"`
}

type reportResult struct {
	Manifest string `json:"manifest"`
	Report   string `json:"report"`
}

func checker() junge.Checker {
	return junge.Handler{
		Config: junge.CheckerInfo{
			Vulns:      6,
			Timeout:    15,
			AttackData: true,
			Puts:       1,
			Gets:       1,
		},
		CheckFunc: check,
		PutFunc:   put,
		GetFunc:   get,
	}
}

func check(c *junge.C, host string) {
	api := newServiceClient(c, host)
	account := api.register("Service registration is broken")
	marker := "check-" + gen.String(24)

	var ship idResult
	api.rpc("create_ship", account.Token, nil, &ship, "Ship workflow is broken", junge.StatusMumble)
	if ship.ShipID == "" {
		c.Mumble("Ship workflow is broken", "create_ship returned an empty ship_id")
	}
	api.rpc("post_message", account.Token, map[string]any{
		"ship_id": ship.ShipID,
		"message": marker,
	}, nil, "Ship workflow is broken", junge.StatusMumble)
	var messages messagesResult
	api.rpc("read_source_messages", account.Token, map[string]any{
		"source_id": ship.ShipID,
	}, &messages, "Ship workflow is broken", junge.StatusMumble)
	if !contains(messages.Messages, marker) {
		c.Mumble("Ship workflow is broken", "posted message was not returned")
	}
	api.rpcError("bind_source", account.Token, map[string]any{
		"source_id": ship.ShipID,
	}, "source exists", "Source workflow is broken", junge.StatusMumble)
	checkExportWorkflow(c, api, account.Token, ship.ShipID, marker)

	manifest := "manifest-" + gen.String(24)
	navigation := "navigation-" + gen.String(24)
	flight := createFlight(api, account.Token, manifest, navigation, "Flight workflow is broken", junge.StatusMumble)
	var savedManifest manifestResult
	api.rpc("read_manifest", account.Token, map[string]any{
		"flight_id": flight.FlightID,
	}, &savedManifest, "Flight workflow is broken", junge.StatusMumble)
	if savedManifest.Manifest != manifest {
		c.Mumble("Flight workflow is broken", "read_manifest returned different data")
	}
	var publicFlight flightPublicResult
	api.rpc("flight_public", account.Token, map[string]any{
		"flight_id": flight.FlightID,
	}, &publicFlight, "Flight workflow is broken", junge.StatusMumble)
	if publicFlight.Geometry == "" || publicFlight.MapVersion == "" || publicFlight.Options == "" {
		c.Mumble("Flight workflow is broken", "flight_public returned incomplete route data")
	}
	var report reportResult
	api.rpc("report", account.Token, map[string]any{
		"flight_id": flight.FlightID,
	}, &report, "Flight workflow is broken", junge.StatusMumble)
	if report.Manifest != manifest {
		c.Mumble("Flight workflow is broken", "report returned a different manifest")
	}
	var savedNavigation navigationResult
	api.rpc("read_navigation", account.Token, map[string]any{
		"flight_id": flight.FlightID,
	}, &savedNavigation, "Navigation workflow is broken", junge.StatusMumble)
	if savedNavigation.Navigation != navigation {
		c.Mumble("Navigation workflow is broken", "read_navigation returned different data")
	}
	checkDelegationWorkflow(c, api, account.Token, flight.FlightID)

	var summary idResult
	api.rpc("create_summary", account.Token, map[string]any{
		"content": marker,
	}, &summary, "Summary workflow is broken", junge.StatusMumble)
	var savedSummary summaryResult
	api.rpc("read_summary", account.Token, map[string]any{
		"summary_id": summary.SummaryID,
	}, &savedSummary, "Summary workflow is broken", junge.StatusMumble)
	if savedSummary.Content != marker {
		c.Mumble("Summary workflow is broken", "read_summary returned different data")
	}
	checkImportWorkflow(api, account.Token)

	checkPackageWorkflow(c, api, account.Token, marker)
	c.OK("OK")
}

func put(c *junge.C, req junge.PutRequest) {
	validatePlace(c, req.Vuln)
	api := newServiceClient(c, req.Host)
	account := api.register("Could not save flag")

	var id, grantID string
	switch req.Vuln {
	case 1, 2:
		var ship idResult
		api.rpc("create_ship", account.Token, nil, &ship, "Could not save flag", junge.StatusMumble)
		api.rpc("post_message", account.Token, map[string]any{
			"ship_id": ship.ShipID,
			"message": req.Flag,
		}, nil, "Could not save flag", junge.StatusMumble)
		id = ship.ShipID
	case 3, 4:
		flight := createFlight(api, account.Token, req.Flag, gen.Sentence(), "Could not save flag", junge.StatusMumble)
		id = flight.FlightID
		if req.Vuln == 4 {
			var grant idResult
			api.rpc("grant_geometry", account.Token, map[string]any{
				"flight_id": id,
			}, &grant, "Could not save flag", junge.StatusMumble)
			grantID = grant.GrantID
		}
	case 5:
		var summary idResult
		api.rpc("create_summary", account.Token, map[string]any{
			"content": req.Flag,
		}, &summary, "Could not save flag", junge.StatusMumble)
		id = summary.SummaryID
	case 6:
		flight := createFlight(api, account.Token, gen.Sentence(), req.Flag, "Could not save flag", junge.StatusMumble)
		id = flight.FlightID
	}
	if id == "" || (req.Vuln == 4 && grantID == "") {
		c.Mumble("Could not save flag", "service returned an incomplete object identifier")
	}

	flagID, err := newFlagReference(req.Vuln, id, grantID, account.Token, req.Flag)
	if err != nil {
		c.CheckFailed("Checker failed", err.Error())
	}
	c.OK(flagID, fmt.Sprintf("saved place=%d object=%s", req.Vuln, id))
}

func get(c *junge.C, req junge.GetRequest) {
	validatePlace(c, req.Vuln)
	ref, state, err := parseFlagReference(req.FlagID, req.Flag, req.Vuln)
	if err != nil {
		c.CheckFailed("Checker failed", err.Error())
	}
	api := newServiceClient(c, req.Host)

	var actual string
	switch req.Vuln {
	case 1, 2:
		var result messagesResult
		api.rpc("read_source_messages", state.Token, map[string]any{
			"source_id": ref.ID,
		}, &result, "Could not read flag", junge.StatusCorrupt)
		if contains(result.Messages, req.Flag) {
			actual = req.Flag
		}
	case 3, 4:
		var result manifestResult
		api.rpc("read_manifest", state.Token, map[string]any{
			"flight_id": ref.ID,
		}, &result, "Could not read flag", junge.StatusCorrupt)
		actual = result.Manifest
	case 5:
		var result summaryResult
		api.rpc("read_summary", state.Token, map[string]any{
			"summary_id": ref.ID,
		}, &result, "Could not read flag", junge.StatusCorrupt)
		actual = result.Content
	case 6:
		var result navigationResult
		api.rpc("read_navigation", state.Token, map[string]any{
			"flight_id": ref.ID,
		}, &result, "Could not read flag", junge.StatusCorrupt)
		actual = result.Navigation
	}
	if actual != req.Flag {
		c.Corrupt("Flag was corrupted", fmt.Sprintf("place=%d object=%s", req.Vuln, ref.ID))
	}
	c.OK("OK", fmt.Sprintf("read place=%d object=%s", req.Vuln, ref.ID))
}

func createFlight(api *serviceClient, token, manifest, navigation, public string, failure junge.Status) idResult {
	var flight idResult
	api.rpc("create_flight", token, map[string]any{
		"geometry":    "M " + gen.String(16) + " L " + gen.String(16),
		"map_version": "map-" + gen.String(12),
		"options":     "route-" + gen.String(12),
		"manifest":    manifest,
		"navigation":  navigation,
	}, &flight, public, failure)
	if flight.FlightID == "" {
		api.fail(failure, public, "create_flight returned an empty flight_id")
	}
	return flight
}

func checkExportWorkflow(c *junge.C, api *serviceClient, token, shipID, marker string) {
	var editedShip idResult
	api.rpc("create_ship", token, nil, &editedShip, "Export workflow is broken", junge.StatusMumble)
	if editedShip.ShipID == "" {
		c.Mumble("Export workflow is broken", "create_ship returned an empty ship_id")
	}
	editedMarker := marker + "-edited"
	api.rpc("post_message", token, map[string]any{
		"ship_id": editedShip.ShipID,
		"message": editedMarker,
	}, nil, "Export workflow is broken", junge.StatusMumble)

	var profile idResult
	api.rpc("create_profile", token, map[string]any{
		"ship_id": shipID,
	}, &profile, "Export workflow is broken", junge.StatusMumble)
	if profile.ProfileID == "" {
		c.Mumble("Export workflow is broken", "create_profile returned an empty profile_id")
	}
	api.rpc("edit_profile", token, map[string]any{
		"profile_id": profile.ProfileID,
		"ship_id":    editedShip.ShipID,
	}, nil, "Export workflow is broken", junge.StatusMumble)

	var job idResult
	api.rpc("create_export", token, map[string]any{
		"profile_id": profile.ProfileID,
	}, &job, "Export workflow is broken", junge.StatusMumble)
	if job.JobID == "" {
		c.Mumble("Export workflow is broken", "create_export returned an empty job_id")
	}

	var run exportResult
	api.rpc("run_export", token, map[string]any{
		"job_id": job.JobID,
	}, &run, "Export workflow is broken", junge.StatusMumble)
	if run.State != "DONE" || !contains(run.Messages, editedMarker) {
		c.Mumble("Export workflow is broken", "run_export returned an invalid result")
	}

	var saved exportResult
	api.rpc("export_result", token, map[string]any{
		"job_id": job.JobID,
	}, &saved, "Export workflow is broken", junge.StatusMumble)
	if saved.State != "DONE" || !contains(saved.Messages, editedMarker) {
		c.Mumble("Export workflow is broken", "export_result returned an invalid result")
	}
}

func checkDelegationWorkflow(c *junge.C, api *serviceClient, token, flightID string) {
	var parent idResult
	api.rpc("grant_geometry", token, map[string]any{
		"flight_id": flightID,
	}, &parent, "Delegation workflow is broken", junge.StatusMumble)
	if parent.GrantID == "" {
		c.Mumble("Delegation workflow is broken", "grant_geometry returned an empty grant_id")
	}

	var child idResult
	api.rpc("delegate", token, map[string]any{
		"parent_id": parent.GrantID,
		"rights":    []string{"geometry.read"},
		"expires":   time.Now().Add(time.Hour).Unix(),
	}, &child, "Delegation workflow is broken", junge.StatusMumble)
	if child.GrantID == "" {
		c.Mumble("Delegation workflow is broken", "delegate returned an empty grant_id")
	}
}

func checkImportWorkflow(api *serviceClient, token string) {
	api.rpcError("import_bulletin", token, map[string]any{
		"url": "http://127.0.0.1/",
	}, "internal source forbidden", "Bulletin workflow is broken", junge.StatusMumble)
	api.rpcError("import_result", token, map[string]any{
		"import_id": "import-check-missing",
	}, "unknown import", "Bulletin workflow is broken", junge.StatusMumble)
}

func checkPackageWorkflow(c *junge.C, api *serviceClient, token, marker string) {
	var pkg idResult
	api.rpc("create_package", token, nil, &pkg, "Package workflow is broken", junge.StatusMumble)
	if pkg.PackageID == "" {
		c.Mumble("Package workflow is broken", "create_package returned an empty package_id")
	}
	api.uploadPackage(token, pkg.PackageID, makeTar("attachment.txt", []byte(marker)), "Package workflow is broken", junge.StatusMumble)
	api.rpc("approve_package", token, map[string]any{
		"package_id": pkg.PackageID,
	}, nil, "Package workflow is broken", junge.StatusMumble)
	var report reportResult
	api.rpc("generate_report", token, map[string]any{
		"package_id": pkg.PackageID,
		"attachment": "attachment.txt",
	}, &report, "Package workflow is broken", junge.StatusMumble)
	if report.Report != marker {
		c.Mumble("Package workflow is broken", "generated report returned different data")
	}
}

func validatePlace(c *junge.C, vuln int) {
	if vuln < 1 || vuln > 6 {
		c.CheckFailed("Checker failed", fmt.Sprintf("unsupported vuln/place %d", vuln))
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func prettyReference(raw string) string {
	var value any
	if json.Unmarshal([]byte(raw), &value) != nil {
		return raw
	}
	data, _ := json.Marshal(value)
	return string(data)
}
