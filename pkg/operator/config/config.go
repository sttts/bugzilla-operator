package config

import (
	"encoding/base64"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
)

type Credentials struct {
	Username               string `yaml:"username"`
	Password               string `yaml:"password"`
	APIKey                 string `yaml:"apiKey"`
	SlackToken             string `yaml:"slackToken"`
	SlackVerificationToken string `yaml:"slackVerificationToken"`
}

type BugzillaList struct {
	Name     string    `yaml:"name"`
	SharerID string    `yaml:"sharerID"`
	Action   BugAction `yaml:"action"`
}

type BugAction struct {
	AddComment           string       `yaml:"addComment"`
	SetState             string       `yaml:"setState"`
	SetResolution        string       `yaml:"setResolution"`
	AddKeyword           string       `yaml:"addKeyword"`
	PriorityTransitions  []Transition `yaml:"priorityTransitions"`
	SeverityTransitions  []Transition `yaml:"severityTransitions"`
	NeedInfoFromCreator  bool         `yaml:"needInfoFromCreator"`
	NeedInfoFromAssignee bool         `yaml:"needInfoFromAssignee"`
}

type BugzillaLists struct {
	// Stale list represents a list with bugs that are not changes for 30d
	Stale BugzillaList `yaml:"stale"`

	// StaleClose represents a list with bugs we tagged as LifecycleStale and they were not changed 7d after that.
	StaleClose BugzillaList `yaml:"staleClose"`

	// Blockers represents a list with bugs considered release blockers
	Blockers BugzillaList `yaml:"blockers"`

	// Closed represents a list with bugs we closed in last 24h
	Closed BugzillaList `yaml:"closed"`
}

type Transition struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

type BugzillaRelease struct {
	CurrentTargetRelease string `yaml:"currentTargetRelease"`
}

type Group []string

type Component struct {
	// lead should match the bugzilla default assignee the component and will get notifications of new BZs by default.
	Lead string `yaml:"lead"`
	// developers are not assigned by default, but might be on first comment if autoCommentAssign is true.
	// This can have group:<group-name> references.
	Developers []string `yaml:"developers"`
	// watchers get notified about new bugzillas. If this is empty, the lead is notified.
	// This can have group:<group-name> references.
	Watchers []string `yaml:"watchers"`
	// the first commentor from the developers is auto-assigned if the default
	// assignee hasn't commented yet.
	AssignFirstDeveloperCommentor bool `yaml:"autoCommentAssign"`
}

type OperatorConfig struct {
	Credentials Credentials   `yaml:"credentials"`
	Lists       BugzillaLists `yaml:"lists"`

	Release BugzillaRelease `yaml:"release"`

	// groups are list of emails or references to other groups with the syntax group:<other-group>.
	Groups     map[string]Group     `yaml:"groups"`
	Components map[string]Component `yaml:"components"`

	// SlackChannel is a channel where the operator will post reports/etc.
	SlackChannel      string `yaml:"slackChannel"`
	SlackAdminChannel string `yaml:"slackAdminChannel"`

	CachePath string `yaml:"cachePath"`
}

// Anonymize makes a shallow copy of the config, suitable for dumping in logs (no sensitive data)
func (c *OperatorConfig) Anonymize() OperatorConfig {
	a := *c
	if user := a.Credentials.Username; len(user) > 0 {
		a.Credentials.Username = strings.Repeat("x", len(a.Credentials.DecodedUsername()))
	}
	if password := a.Credentials.Password; len(password) > 0 {
		a.Credentials.Password = strings.Repeat("x", len(a.Credentials.DecodedPassword()))
	}
	if key := a.Credentials.APIKey; len(key) > 0 {
		a.Credentials.APIKey = strings.Repeat("x", len(a.Credentials.DecodedAPIKey()))
	}
	if key := a.Credentials.SlackToken; len(key) > 0 {
		a.Credentials.SlackToken = strings.Repeat("x", len(a.Credentials.DecodedSlackToken()))
	}
	if key := a.Credentials.SlackVerificationToken; len(key) > 0 {
		a.Credentials.SlackVerificationToken = strings.Repeat("x", len(a.Credentials.DecodedSlackVerificationToken()))
	}
	return a
}

func decode(s string) string {
	if strings.HasPrefix(s, "base64:") {
		data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "base64:"))
		if err != nil {
			return s
		}
		return string(data)
	}
	return s
}

// DecodedAPIKey return decoded APIKey (in case it was base64 encoded)
func (b Credentials) DecodedAPIKey() string {
	return decode(b.APIKey)
}

// DecodedAPIKey return decoded Password (in case it was base64 encoded)
func (b Credentials) DecodedPassword() string {
	return decode(b.Password)
}

// DecodedAPIKey return decoded Username (in case it was base64 encoded)
func (b Credentials) DecodedUsername() string {
	return decode(b.Username)
}

func (b Credentials) DecodedSlackToken() string {
	return decode(b.SlackToken)
}

func (b Credentials) DecodedSlackVerificationToken() string {
	return decode(b.SlackVerificationToken)
}

func ExpandGroups(cfg map[string]Group, roots ...string) sets.String {
	users := sets.String{}
	for _, r := range roots {
		users, _ = expandGroup(cfg, r, users, nil)
	}
	return users
}

func expandGroup(cfg map[string]Group, x string, expanded sets.String, seen sets.String) (sets.String, sets.String) {
	if strings.HasPrefix(x, "group:") {
		group := x[6:]
		if seen.Has(group) {
			return expanded, seen
		}
		if seen == nil {
			seen = sets.String{}
		}
		seen = seen.Insert(group)
		for _, y := range cfg[group] {
			expanded, seen = expandGroup(cfg, y, expanded, seen)
		}
		return expanded, seen
	}

	return expanded.Insert(x), seen
}
