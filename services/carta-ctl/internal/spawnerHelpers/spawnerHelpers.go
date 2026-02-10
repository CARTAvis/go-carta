package spawnerHelpers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/CARTAvis/go-carta/pkg/shared"
)

type ErrorResponse struct {
	ErrorMessage string `json:"msg"`
}

type WorkerInfo struct {
	Port     int    `json:"port"`
	Address  string `json:"address"`
	WorkerId string `json:"workerId"`
}

type WorkerStatus struct {
	WorkerInfo
	Pid           int  `json:"pid"`
	Alive         bool `json:"alive"`
	IsReachable   bool `json:"isReachable"`
	ExitedCleanly bool `json:"exitedCleanly"`
}

func CountWorkers(spawnerAddress string) (int, error) {
	url := fmt.Sprintf("%s/workers", spawnerAddress)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return -1, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, err
	}
	defer helpers.CloseOrLog(resp.Body)

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return -1, err
		}

		var workers []string
		err = json.Unmarshal(body, &workers)
		if err != nil {
			return -1, err
		}

		for _, id := range workers {
			status, err := GetWorkerStatus(id, spawnerAddress)
			if err != nil {
				fmt.Print(err)
			}
			fmt.Print(status)
		}

		return len(workers), nil

	}
	return -1, errors.New("failed to get workers")
}

func GetWorkerStatus(workerId string, spawnerAddress string) (WorkerStatus, error) {
	url := fmt.Sprintf("%s/worker/%s", spawnerAddress, workerId)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return WorkerStatus{}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return WorkerStatus{}, err
	}
	defer helpers.CloseOrLog(resp.Body)

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return WorkerStatus{}, err
		}

		var status WorkerStatus
		err = json.Unmarshal(body, &status)
		if err != nil {
			return WorkerStatus{}, err
		}

		return status, nil
	}
	return WorkerStatus{}, errors.New("failed to get worker status")
}

func RequestWorkerStartup(spawnerAddress string, username string) (WorkerInfo, error) {
	// create a request body with the username
	requestBody, err := json.Marshal(map[string]string{"username": username})
	if err != nil {
		return WorkerInfo{}, err
	}

	req, err := http.NewRequest(http.MethodPost, spawnerAddress, bytes.NewBuffer(requestBody))
	if err != nil {
		return WorkerInfo{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return WorkerInfo{}, err
	}
	defer helpers.CloseOrLog(resp.Body)
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return WorkerInfo{}, err
	}

	if resp.StatusCode == http.StatusOK {
		var info WorkerInfo
		err = json.Unmarshal(responseBody, &info)
		if err != nil {
			fmt.Printf("Failed to unmarshal worker info: %v\n", err)
			return WorkerInfo{}, err
		}
		return info, nil
	} else {
		var errorResponse ErrorResponse
		err = json.Unmarshal(responseBody, &errorResponse)
		if err != nil {
			fmt.Printf("Failed to unmarshal error response: %v\n", err)
			return WorkerInfo{}, err
		}
		return WorkerInfo{}, fmt.Errorf("failed to start worker: %s", errorResponse.ErrorMessage)
	}
}

func RequestWorkerShutdown(workerId string, spawnerAddress string) error {
	url := fmt.Sprintf("%s/worker/%s", spawnerAddress, workerId)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer helpers.CloseOrLog(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to shutdown worker")
	}

	return nil
}
