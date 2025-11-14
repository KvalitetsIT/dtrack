package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/KvalitetsIT/dtrack/cmd/common"
	"github.com/KvalitetsIT/dtrack/pkg/dependencytrack"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var cfg = &Config{
	LogLevel: "debug",
}

type Config struct {
	AdminPassword        string `json:"admin-password"`
	FrontendBaseUrl      string `json:"frontend-base-url"`
	BaseUrl              string `json:"base-url"`
	DefaultAdminPassword string `json:"default-admin-password"`
	LogLevel             string `json:"log-level"`
	UsersFile            string `json:"users-file"`
	TeamsFile            string `json:"teams-file"`
	GroupsFile           string `json:"groups-file"`
	GithubAdvisoryToken  string `json:"github-advisory-token"`
	GoogleOSVEnabled     bool   `json:"google-osv-enabled"`
	TrivyApiToken        string `json:"trivy-token"`
	TrivyBaseURL         string `json:"trivy-base-url"`
	TrivyIgnoreUnfixed   bool   `json:"trivy-ignore-unfixed"`
	OssIndexApiUsername  string `json:"oss-index-api-username"`
	OssIndexApiToken     string `json:"oss-index-api-token"`
}

func init() {
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "which log level to use, default 'info'")
	flag.StringVar(&cfg.FrontendBaseUrl, "frontend-base-url", "http://localhost:9000", "frontend base url")
	flag.StringVar(&cfg.BaseUrl, "base-url", "http://localhost:9001", "base url of dependencytrack")
	flag.StringVar(&cfg.DefaultAdminPassword, "default-admin-password", "admin", "default admin password")
	flag.StringVar(&cfg.AdminPassword, "admin-password", cfg.AdminPassword, "new admin password")
	flag.StringVar(&cfg.GithubAdvisoryToken, "github-advisory-token", cfg.GithubAdvisoryToken, "github advisory mirroring token")
	flag.StringVar(&cfg.UsersFile, "users-file", "/bootstrap/users.yaml", "file with users to create")
	flag.StringVar(&cfg.TeamsFile, "teams-file", "/bootstrap/teams.yaml", "file with teams to create")
	flag.StringVar(&cfg.GroupsFile, "groups-file", "/bootstrap/groups.yaml", "file with OIDC groups to create")
	flag.BoolVar(&cfg.GoogleOSVEnabled, "google-osv-enabled", cfg.GoogleOSVEnabled, "enable google osv integration")
	flag.StringVar(&cfg.TrivyApiToken, "trivy-api-token", cfg.TrivyApiToken, "trivy api token to use for scanning")
	flag.StringVar(&cfg.TrivyBaseURL, "trivy-base-url", cfg.TrivyBaseURL, "trivy base url")
	flag.BoolVar(&cfg.TrivyIgnoreUnfixed, "trivy-ignore-unfixed", cfg.TrivyIgnoreUnfixed, "ignore unfixed vulnerabilities")
	flag.StringVar(&cfg.OssIndexApiUsername, "oss-index-api-username", cfg.OssIndexApiUsername, "oss index username")
	flag.StringVar(&cfg.OssIndexApiToken, "oss-index-api-token", cfg.OssIndexApiToken, "oss index token")
}

func main() {
	common.ParseFlags()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	log, err := common.SetupLogger(cfg.LogLevel)
	if err != nil {
		log.Fatalf("setup logger: %v", err)
	}

	c, err := dependencytrack.NewManagementClient(cfg.BaseUrl, "admin", cfg.AdminPassword, log.WithField("subsystem", "client"))
	if err != nil {
		log.Fatalf("create dependencytrack client: %v", err)
	}

	version, err := c.Version(ctx)
	if err != nil {
		log.Fatalf("get dependencytrack version: %v", err)
	}

	if strings.TrimSpace(version) == "" {
		log.Fatalf("dependencytrack version is empty, is the server up?")
	}

	log.Infof("dependencytrack version: %s", version)

	err = c.ChangeAdminPassword(ctx, cfg.DefaultAdminPassword, cfg.AdminPassword)
	if err != nil {
		log.Fatalf("change admin password: %v", err)
	}

	// Bootstrap users
	if err := bootstrapUsers(ctx, c, cfg.UsersFile, log); err != nil {
		log.Fatalf("bootstrap users: %v", err)
	}

	// Bootstrap teams
	// This is important to do before OIDC groups as they are mapped to teams
	if err := bootstrapTeams(ctx, c, cfg.TeamsFile, log); err != nil {
		log.Fatalf("bootstrap teams: %v", err)
	}

	// Bootstrap OIDC groups
	if err := bootstrapOidcGroups(ctx, c, cfg.GroupsFile, log); err != nil {
		log.Fatalf("bootstrap OIDC groups: %v", err)
	}

	props, err := c.GetConfigProperties(ctx)
	if err != nil {
		log.Fatalf("get config properties: %v", err)
	}

	var cp []dependencytrack.ConfigProperty
	for _, prop := range props {
		if cfg.GithubAdvisoryToken != "" {
			switch *prop.PropertyName {
			case "github.advisories.enabled":
				if isAlreadySet(prop.PropertyValue, "true") {
					log.Info("github advisory mirroring already enabled")
					continue
				}
				token := "true"
				prop.PropertyValue = &token
				cp = append(cp, prop)
				log.Info("added: github advisory mirroring")
			case "github.advisories.access.token":
				if isAlreadySet(prop.PropertyValue, cfg.GithubAdvisoryToken) {
					log.Info("github advisory mirroring token already set")
					continue
				}
				prop.PropertyValue = &cfg.GithubAdvisoryToken
				cp = append(cp, prop)
				log.Info("added: github advisory mirroring token")
			}
		}

		switch *prop.PropertyName {
		case "nvd.api.enabled":
			if isAlreadySet(prop.PropertyValue, "false") {
				log.Info("nvd api already disabled")
				continue
			}
			enabled := "false"
			prop.PropertyValue = &enabled
			cp = append(cp, prop)
			log.Info("disabled: nvd api")

		case "nvd.api.download.feeds":
			if isAlreadySet(prop.PropertyValue, "true") {
				log.Info("nvd api download feeds already enabled")
				continue
			}
			download := "true"
			prop.PropertyValue = &download
			cp = append(cp, prop)
			log.Info("added: nvd api download feeds")

		case "submission.enabled":
			if *prop.GroupName == "telemetry" {
				if isAlreadySet(prop.PropertyValue, "false") {
					log.Info("telemetry submission already disabled")
					continue
				}
				disabled := "false"
				prop.PropertyValue = &disabled
				cp = append(cp, prop)
				log.Info("disabled: telemetry submission")
			}
		}

		if cfg.GoogleOSVEnabled {
			switch *prop.PropertyName {
			case "google.osv.enabled":
				eco, err := c.GetEcosystems(ctx)
				if err != nil {
					log.Fatalf("get ecosystems: %v", err)
				}
				// if the list is empty we activated all ecosystems
				if len(eco) == 0 {
					log.Info("google osv integration already enabled")
					continue
				}

				if err = updateEcosystems(ctx, c, eco, prop, log); err != nil {
					log.Fatalf("update ecosystems: %v", err)
				}
			}
		}

		if cfg.TrivyApiToken != "" {
			switch *prop.PropertyName {
			case "trivy.enabled":
				if isAlreadySet(prop.PropertyValue, "true") {
					log.Info("trivy integration already enabled")
					continue
				}
				enabled := "true"
				prop.PropertyValue = &enabled
				cp = append(cp, prop)
				log.Info("added: trivy integration")
			case "trivy.api.token":
				// we cant check if the token is already set, so we just set it
				prop.PropertyValue = &cfg.TrivyApiToken
				cp = append(cp, prop)
				log.Info("added: trivy token")
			case "trivy.base.url":
				if isAlreadySet(prop.PropertyValue, cfg.TrivyBaseURL) {
					log.Info("trivy base url already set")
					continue
				}
				prop.PropertyValue = &cfg.TrivyBaseURL
				cp = append(cp, prop)
				log.Info("added: trivy base url")
			case "trivy.ignore.unfixed":
				if isAlreadySet(prop.PropertyValue, "true") {
					log.Info("trivy ignore unfixed already enabled")
					continue
				}
				unfixed := "true"
				prop.PropertyValue = &unfixed
				cp = append(cp, prop)
				log.Info("added: trivy ignore unfixed")
			}
		}

		if cfg.FrontendBaseUrl != "" {
			switch *prop.PropertyName {
			case "base.url":
				if isAlreadySet(prop.PropertyValue, cfg.FrontendBaseUrl) {
					log.Info("general base url already set")
					continue
				}
				prop.PropertyValue = &cfg.FrontendBaseUrl
				cp = append(cp, prop)
				log.Info("added: general base url")
			}
		}

		if cfg.OssIndexApiUsername == "" || cfg.OssIndexApiToken == "" {
			switch *prop.PropertyName {
			case "ossindex.enabled":
				if isAlreadySet(prop.PropertyValue, "false") {
					log.Info("oss index integration already disabled")
					continue
				}
				enabled := "false"
				prop.PropertyValue = &enabled
				cp = append(cp, prop)
				log.Info("disabled: oss index integration")
			}
		} else {
			switch *prop.PropertyName {
			case "ossindex.enabled":
				if isAlreadySet(prop.PropertyValue, "true") {
					log.Info("oss index integration already enabled")
					continue
				}
				enabled := "true"
				prop.PropertyValue = &enabled
				cp = append(cp, prop)
				log.Info("added: oss index integration")
			case "ossindex.api.username":
				if isAlreadySet(prop.PropertyValue, cfg.OssIndexApiUsername) {
					log.Info("oss index username already set")
					continue
				}
				prop.PropertyValue = &cfg.OssIndexApiUsername
				cp = append(cp, prop)
				log.Info("added: oss index username")
			case "ossindex.api.token":
				// we cant check if the token is already set, so we just set it
				prop.PropertyValue = &cfg.OssIndexApiToken
				cp = append(cp, prop)
				log.Info("added: oss index token")
			}
		}
	}

	// only update if we have new properties
	if len(cp) > 0 {
		for _, p := range cp {
			if err = c.ConfigPropertyAggregate(ctx, p); err != nil {
				log.Fatalf("config property aggregate: %v", err)
			}
		}
		log.Info("done: config properties updated")
	}
}

func updateEcosystems(ctx context.Context, c dependencytrack.ManagementClient, eco []string, prop dependencytrack.ConfigProperty, log *logrus.Logger) error {
	chunkSize := 10

	for len(eco) > 0 {
		log.Info("Processing chunk of ecosystems: ", len(eco))
		// Get the next chunk of eco
		end := chunkSize
		if len(eco) < chunkSize {
			end = len(eco)
		}

		chunk := eco[:end]
		eco = eco[end:] // Remove the processed chunk from eco

		propVal := strings.Join(chunk, ";")
		p := dependencytrack.ConfigProperty{
			GroupName:     prop.GroupName,
			PropertyName:  prop.PropertyName,
			PropertyType:  prop.PropertyType,
			PropertyValue: &propVal,
			Description:   prop.Description,
		}

		if err := c.ConfigPropertyAggregate(ctx, p); err != nil {
			return err
		}

		log.Info("Chunk processed and sent. Remaining items:", len(eco))
	}
	return nil
}

func bootstrapUsers(ctx context.Context, c dependencytrack.ManagementClient, usersFilePath string, log *logrus.Logger) error {
	file, err := os.ReadFile(usersFilePath)
	if err != nil {
		return fmt.Errorf("read users file: %w", err)
	}

	type Users struct {
		Users []*dependencytrack.AdminUser `yaml:"users"`
	}
	users := &Users{}
	if err := yaml.Unmarshal(file, users); err != nil {
		return fmt.Errorf("unmarshal users file: %w", err)
	}

	team, err := c.GetTeam(ctx, "Administrators")
	if err != nil {
		return fmt.Errorf("get team uuid: %w", err)
	}

	if len(team.ApiKeys) == 0 {
		_, err = c.GenerateApiKey(ctx, team.Uuid)
		if err != nil {
			return fmt.Errorf("generate api key: %w", err)
		}
	}

	// remove users before adding to ensure passwords in sync
	if err := c.RemoveAdminUsers(ctx, users.Users); err != nil {
		return fmt.Errorf("remove users: %w", err)
	}

	if err := c.CreateAdminUsers(ctx, users.Users, team.Uuid); err != nil {
		return fmt.Errorf("create users: %w", err)
	}

	log.Info("created: users and added to Administrators team")
	return nil
}

func bootstrapTeams(ctx context.Context, c dependencytrack.ManagementClient, teamsFilePath string, log *logrus.Logger) error {
	teamsFile, err := os.ReadFile(teamsFilePath)
	if err != nil {
		return fmt.Errorf("read teams file: %w", err)
	}

	type TeamConfig struct {
		Name        string                       `yaml:"name"`
		Permissions []dependencytrack.Permission `yaml:"permissions"`
	}

	type Teams struct {
		Teams []*TeamConfig `yaml:"teams"`
	}

	teams := &Teams{}
	if err := yaml.Unmarshal(teamsFile, teams); err != nil {
		return fmt.Errorf("unmarshal teams file: %w", err)
	}

	// Get existing teams to avoid duplicates
	existingTeams, err := c.GetTeams(ctx)
	if err != nil {
		return fmt.Errorf("get existing teams: %w", err)
	}

	existingTeamMap := make(map[string]string)
	for _, t := range existingTeams {
		existingTeamMap[t.Name] = t.Uuid
	}

	// Create teams that don't exist
	for _, teamConfig := range teams.Teams {
		if teamConfig.Name == "" {
			return fmt.Errorf("team name cannot be empty")
		}

		if _, exists := existingTeamMap[teamConfig.Name]; exists {
			log.Infof("team %s already exists", teamConfig.Name)
		} else {
			_, err := c.CreateTeam(ctx, teamConfig.Name, teamConfig.Permissions)
			if err != nil {
				return fmt.Errorf("create team %s: %w", teamConfig.Name, err)
			}
		}
	}

	log.Info("done: teams created")
	return nil
}

func bootstrapOidcGroups(ctx context.Context, c dependencytrack.ManagementClient, groupsFilePath string, log *logrus.Logger) error {
	groupsFile, err := os.ReadFile(groupsFilePath)
	if err != nil {
		return fmt.Errorf("read groups file: %w", err)
	}

	type OidcGroupConfig struct {
		Name  string   `yaml:"name"`
		Teams []string `yaml:"teams"`
	}

	type OidcGroups struct {
		Groups []*OidcGroupConfig `yaml:"groups"`
	}

	oidcGroups := &OidcGroups{}
	if err := yaml.Unmarshal(groupsFile, oidcGroups); err != nil {
		return fmt.Errorf("unmarshal groups file: %w", err)
	}

	// Get existing OIDC groups
	existingGroups, err := c.GetOidcGroups(ctx)
	if err != nil {
		return fmt.Errorf("get existing OIDC groups: %w", err)
	}

	existingGroupMap := make(map[string]string)
	for _, g := range existingGroups {
		existingGroupMap[g.Name] = g.Uuid
	}

	// Build map of groups from config file
	configGroupMap := make(map[string]bool)
	for _, groupConfig := range oidcGroups.Groups {
		configGroupMap[groupConfig.Name] = true
	}

	// Delete OIDC groups that are not in the config file
	for _, existingGroup := range existingGroups {
		if !configGroupMap[existingGroup.Name] {
			if err := c.DeleteOidcGroup(ctx, existingGroup.Uuid); err != nil {
				return fmt.Errorf("delete OIDC group %s: %w", existingGroup.Name, err)
			}
			log.Infof("deleted OIDC group %s (not in config)", existingGroup.Name)
		}
	}

	// Create OIDC groups and map to teams
	for _, groupConfig := range oidcGroups.Groups {
		if groupConfig.Name == "" {
			return fmt.Errorf("OIDC group name cannot be empty")
		}

		var groupUuid string
		if uuid, exists := existingGroupMap[groupConfig.Name]; exists {
			log.Infof("OIDC group %s already exists with UUID %s", groupConfig.Name, uuid)
			groupUuid = uuid
		} else {
			// Create the OIDC group
			group, err := c.CreateOidcGroup(ctx, groupConfig.Name)
			if err != nil {
				return fmt.Errorf("create OIDC group %s: %w", groupConfig.Name, err)
			}
			groupUuid = group.Uuid
		}

		for _, teamName := range groupConfig.Teams {
			team, err := c.GetTeam(ctx, teamName)
			if err != nil {
				return fmt.Errorf("get team %s for OIDC group mapping: %w", teamName, err)
			}

			if err := c.MapOidcGroupToTeam(ctx, groupUuid, team.Uuid); err != nil {
				return fmt.Errorf("map OIDC group %s to team %s: %w", groupConfig.Name, teamName, err)
			}
			log.Infof("mapped OIDC group %s to team %s", groupConfig.Name, teamName)
		}
	}

	log.Info("done: OIDC groups created and mapped to teams")
	return nil
}

func isAlreadySet(config *string, inputValue string) bool {
	if config == nil {
		return false
	}
	return strings.EqualFold(*config, inputValue)
}
