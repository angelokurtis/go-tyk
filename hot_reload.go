package tyk

// HotReloadService handles communication with the hot reload command.
type HotReloadService struct {
	client *Client
}

type ReloadStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// ReloadGroup restarts a Tyk Gateway Process.
func (s *HotReloadService) ReloadGroup() (*ReloadStatus, error) {
	var p *ReloadStatus
	err := s.client.GET("/reload/group", &p)
	if err != nil {
		return nil, err
	}

	return p, nil
}
