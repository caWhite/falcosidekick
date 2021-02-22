package outputs

import (
	"github.com/PagerDuty/go-pagerduty"
	"github.com/falcosecurity/falcosidekick/types"
	"log"
	"strings"
	"time"
)

// PagerdutyPost posts alert event to Pagerduty
func (c *Client) PagerdutyPost(falcopayload types.FalcoPayload) {
	c.Stats.Pagerduty.Add(Total, 1)

	event := createPagerdutyEvent(falcopayload, c.Config.Pagerduty.IntegrationKey)

	_, err := pagerduty.ManageEvent(event)

	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:error"})
		c.Stats.Pagerduty.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": Error}).Inc()
		log.Printf("[ERROR] : PagerDuty - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:ok"})
	c.Stats.Pagerduty.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": OK}).Inc()
	log.Printf("[INFO] : Pagerduty - Create Incident OK\n")
}

func createPagerdutyEvent(falcopayload types.FalcoPayload, routingKey string) pagerduty.V2Event {
	event := pagerduty.V2Event{
		RoutingKey: routingKey,
		Action:     "trigger",
		Payload: &pagerduty.V2Payload{
			Source:    "falco",
			Summary:   falcopayload.Output,
			Severity:  strings.ToLower(falcopayload.Priority.String()),
			Timestamp: falcopayload.Time.Format(time.RFC3339),
			Details:   falcopayload.OutputFields,
		},
	}
	return event
}
