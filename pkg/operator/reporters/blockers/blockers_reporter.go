package blockers

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/eparis/bugzilla"

	"github.com/mfojtik/bugzilla-operator/pkg/operator/bugutil"
	"github.com/mfojtik/bugzilla-operator/pkg/operator/config"
	"github.com/mfojtik/bugzilla-operator/pkg/slack"
)

const bugzillaEndpoint = "https://bugzilla.redhat.com"

type BlockersReporter struct {
	config      config.OperatorConfig
	slackClient slack.Client
}

const (
	blockerIntro = "Hi there!\nIt appears you have %d bugs assigned to you and these bugs are _%s_ *release blockers*:\n\n"
	blockerOutro = "\n\nPlease keep eyes on these today!"

	triageIntro = "Hi there!\nI found %d untriaged bugs assigned to you:\n\n"
	triageOutro = "\n\nPlease make sure all these have the _Severity_ field set and the _Target Release_ set, so I can stop bothering you :-)\n\n"
)

func NewBlockersReporter(operatorConfig config.OperatorConfig, scheduleInformer factory.Informer, slackClient slack.Client, recorder events.Recorder) factory.Controller {
	c := &BlockersReporter{
		config:      operatorConfig,
		slackClient: slackClient,
	}
	return factory.New().WithSync(c.sync).WithInformers(scheduleInformer).ToController("BlockersReporter", recorder)
}

func (c *BlockersReporter) newClient() bugzilla.Client {
	return bugzilla.NewClient(func() []byte {
		return []byte(c.config.Credentials.DecodedAPIKey())
	}, bugzillaEndpoint).WithCGIClient(c.config.Credentials.DecodedUsername(), c.config.Credentials.DecodedPassword())
}

func (c *BlockersReporter) triageBug(client bugzilla.Client, bugIDs ...int) (blockers []string, needTriage []string) {
	currentTargetRelease := c.config.Release.CurrentTargetRelease
	for _, id := range bugIDs {
		bug, err := client.GetBug(id)
		if err != nil {
			continue
		}
		if len(bug.TargetRelease) == 0 {
			needTriage = append(needTriage, bugutil.FormatBugMessage(*bug))
			continue
		}

		if bug.Severity == "unspecified" || bug.TargetRelease[0] == "---" {
			needTriage = append(needTriage, bugutil.FormatBugMessage(*bug))
		}

		if bug.TargetRelease[0] == currentTargetRelease {
			blockers = append(blockers, bugutil.FormatBugMessage(*bug))
		}
	}

	return
}

func (c *BlockersReporter) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	client := c.newClient()
	blockerBugs, err := client.BugList(c.config.Lists.Blockers.Name, c.config.Lists.Blockers.SharerID)
	if err != nil {
		syncCtx.Recorder().Warningf("BuglistFailed", err.Error())
		return err
	}

	interestingStatus := sets.NewString("NEW", "ASSIGNED")
	peopleBugsMap := map[string][]int{}
	for _, b := range blockerBugs {
		if !interestingStatus.Has(b.Status) {
			continue
		}
		peopleBugsMap[b.AssignedTo] = append(peopleBugsMap[b.AssignedTo], b.ID)
	}

	peopleBlockerNotificationMap := map[string][]string{}
	peopleTriageNotificationMap := map[string][]string{}
	var wg sync.WaitGroup
	for person, bugIDs := range peopleBugsMap {
		wg.Add(1)
		go func(person string, ids []int) {
			defer wg.Done()
			blocker, triage := c.triageBug(client, ids...)
			peopleBlockerNotificationMap[person] = blocker
			peopleTriageNotificationMap[person] = triage
		}(person, bugIDs)
	}
	wg.Wait()

	for person, notifications := range peopleBlockerNotificationMap {
		if len(notifications) == 0 {
			continue
		}
		message := fmt.Sprintf("%s%s%s", fmt.Sprintf(blockerIntro, len(notifications), c.config.Release.CurrentTargetRelease), strings.Join(notifications, "\n"), fmt.Sprintf(blockerOutro))
		if err := c.slackClient.MessageEmail(person, message); err != nil {
			syncCtx.Recorder().Warningf("DeliveryFailed", "Failed to deliver:\n\n%s\n\n to %q: %v", message, person, err)
		}
	}

	for person, notifications := range peopleTriageNotificationMap {
		if len(notifications) == 0 {
			continue
		}
		message := fmt.Sprintf("%s%s%s", fmt.Sprintf(triageIntro, len(notifications)), strings.Join(notifications, "\n"), fmt.Sprintf(triageOutro))
		if err := c.slackClient.MessageEmail(person, message); err != nil {
			syncCtx.Recorder().Warningf("DeliveryFailed", "Failed to deliver:\n\n%s\n\n to %q: %v", message, person, err)
		}
	}

	channelStats := getStatsForChannel(c.config.Release.CurrentTargetRelease, len(blockerBugs), peopleBlockerNotificationMap, peopleTriageNotificationMap)
	if err := c.slackClient.MessageChannel(fmt.Sprintf("*Current Blocker Stats:*\n%s\n", strings.Join(channelStats, "\n"))); err != nil {
		syncCtx.Recorder().Warningf("DeliveryFailed", "Failed to deliver stats to channel: %v", err)
	}

	// send debug stats
	c.sendStatsForPeople(peopleBlockerNotificationMap, peopleTriageNotificationMap)

	return nil
}

func (c *BlockersReporter) sendStatsForPeople(blockers, triage map[string][]string) {
	messages := []string{}
	for person, b := range blockers {
		if len(b) > 0 {
			messages = append(messages, fmt.Sprintf("> %s: %d blockers", person, len(b)))
		}
	}
	for person, b := range triage {
		if len(b) > 0 {
			messages = append(messages, fmt.Sprintf("> %s: %d to triage", person, len(b)))
		}
	}
	c.slackClient.MessageEmail(c.config.SlackUserEmail, strings.Join(messages, "\n"))
}

func getStatsForChannel(target string, totalCount int, blockers, triage map[string][]string) []string {
	totalTriageCount := 0
	for p := range triage {
		totalTriageCount += len(triage[p])
	}
	totalTargetBlockerCount := 0
	for p := range blockers {
		totalTargetBlockerCount += len(blockers[p])
	}
	return []string{
		fmt.Sprintf("> <https://bugzilla.redhat.com/buglist.cgi?cmdtype=dorem&remaction=run&namedcmd=openshift-group-b-blockers&sharer_id=290313|Total Blocker Bug Count>: *%d*", totalCount),
		fmt.Sprintf("> %s Blocker Count: *%d*", target, totalTargetBlockerCount),
		fmt.Sprintf("> <https://bugzilla.redhat.com/buglist.cgi?cmdtype=dorem&remaction=run&namedcmd=openshift-group-b-triage&sharer_id=290313|Bugs Need Triage>:    *%d*", totalTriageCount),
	}
}
