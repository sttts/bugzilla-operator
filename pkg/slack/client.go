package slack

import (
	"github.com/slack-go/slack"
)

var peopleWithWrongSlackEmail = map[string]string{
	"sttts@redhat.com":     "sschiman@redhat.com",
	"rphillips@redhat.com": "rphillip@redhat.com",
}

type Client interface {
	MessageChannel(message string) error
	MessageEmail(email, message string) error
}

type slackClient struct {
	client  *slack.Client
	channel string
}

func getEmail(originalEmail string) string {
	realEmail, ok := peopleWithWrongSlackEmail[originalEmail]
	if ok {
		return realEmail
	}
	return originalEmail
}

func (c *slackClient) MessageChannel(message string) error {
	_, _, err := c.client.PostMessage(c.channel, slack.MsgOptionText(message, false))
	return err
}

func (c *slackClient) MessageEmail(email, message string) error {
	user, err := c.client.GetUserByEmail(getEmail(email))
	if err != nil {
		return err
	}
	_, _, chanID, err := c.client.OpenIMChannel(user.ID)
	if err != nil {
		return err
	}
	_, _, err = c.client.PostMessage(chanID, slack.MsgOptionText(message, false))
	return err
}

func NewClient(channel, token string) Client {
	c := &slackClient{
		channel: channel,
		client:  slack.New(token, slack.OptionDebug(true)),
	}
	return c
}
