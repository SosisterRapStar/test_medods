package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type IpWebhook struct {
	Endpoint string
	*http.Client
	logger *slog.Logger
}

func NewIpWebhook(endppoint string, client *http.Client, logger *slog.Logger) *IpWebhook {
	return &IpWebhook{
		Endpoint: endppoint,
		Client:   client,
		logger:   logger,
	}
}

type IpUpdateEvent struct {
	Timestamp time.Time `json:"time"`
	UserId    string    `json:"user_id"`
	PrevIp    string    `json:"prev_ip"`
	NewIp     string    `json:"new_ip"`
}

func (iw *IpWebhook) SendEvent(event IpUpdateEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		iw.logger.Debug("Error occured during marshaling json for webhook notifiction")
		return err
	}
	req, err := http.NewRequest("POST", iw.Endpoint, bytes.NewBuffer(body))
	if err != nil {
		iw.logger.Debug("Error occured creating request for webhook service")
		return err
	}
	resp, err := iw.Do(req)
	if err != nil {
		iw.logger.Debug("Error occured during request to webhook")
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	return nil
}
