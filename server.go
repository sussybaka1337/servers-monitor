package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type ClientSSH struct {
	Address    string
	Username   string
	Password   string
	Connection *ssh.Client
}

type ServerStatus struct {
	CPU float64 `json:"used_cpu"`
	RAM struct {
		Used  float64 `json:"used_ram"`
		Total float64 `json:"total_ram"`
	} `json:"ram"`
}

var servers []string = []string{
	"IP:PORT:USER:PASS",
}

func ParseFloat(value string) float64 {
	output, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return -1
	}
	return output
}

func (client *ClientSSH) ExecBash(bash string, background bool) (string, error) {
	session, err := client.Connection.NewSession()
	if err != nil {
		client.Connection.Close()
		return "", err
	}
	defer session.Close()
	if background {
		bash += "screen -dm " + bash
	}
	buffer, err := session.CombinedOutput(bash)
	if err != nil {
		return "", err
	}
	return string(buffer), nil
}

func (client *ClientSSH) GetServerStatus() (*ServerStatus, error) {
	response, err := client.ExecBash("top -b -n 1", false)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(response, "\n")
	cpuParts := parts[2]
	memParts := parts[3]
	compiledCPU, err := regexp.Compile(`(\d+\.\d+) us`)
	if err != nil {
		return nil, err
	}
	if found := compiledCPU.MatchString(cpuParts); !found {
		return nil, fmt.Errorf("error: could not parse CPU percentage")
	}
	compiledTotalMem, err := regexp.Compile(`(\d+\.\d+) total`)
	if err != nil {
		return nil, err
	}
	if found := compiledTotalMem.MatchString(memParts); !found {
		return nil, fmt.Errorf("error: could not parse total memory")
	}
	compiledUsedMem, err := regexp.Compile(`(\d+\.\d+) used`)
	if err != nil {
		return nil, err
	}
	if found := compiledUsedMem.MatchString(memParts); !found {
		return nil, fmt.Errorf("error: could not parse used memory")
	}
	serverStatus := &ServerStatus{}
	cpu := compiledCPU.FindStringSubmatch(cpuParts)[1]
	totalRAM := compiledTotalMem.FindStringSubmatch(memParts)[1]
	usedRAM := compiledUsedMem.FindStringSubmatch(memParts)[1]
	serverStatus.CPU = ParseFloat(cpu)
	serverStatus.RAM.Total = ParseFloat(totalRAM)
	serverStatus.RAM.Used = ParseFloat(usedRAM)
	return serverStatus, nil
}

func ConnectSSH(address string, username string, password string) (*ClientSSH, error) {
	client := &ClientSSH{}
	client.Address = address
	client.Username = username
	client.Password = password
	config := &ssh.ClientConfig{
		User: client.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(client.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	connection, err := ssh.Dial("tcp", client.Address, config)
	if err != nil {
		return nil, err
	}
	client.Connection = connection
	return client, nil
}

type DetailsResponse struct {
	Address string        `json:"address"`
	Status  *ServerStatus `json:"status"`
}

func details(response http.ResponseWriter, request *http.Request) {
	mutex := new(sync.Mutex)
	wait := new(sync.WaitGroup)
	var detailsResponseList []*DetailsResponse
	for key := range servers {
		wait.Add(1)
		server := strings.Split(servers[key], ":")
		address := server[0]
		port := server[1]
		username := server[2]
		password := server[3]
		go func() {
			defer wait.Done()
			client, err := ConnectSSH(net.JoinHostPort(address, port), username, password)
			if err != nil {
				return
			}
			status, err := client.getServerStatus()
			if err != nil {
				return
			}
			detailsResponse := &DetailsResponse{
				Address: client.Address,
				Status:  status,
			}
			mutex.Lock()
			detailsResponseList = append(detailsResponseList, detailsResponse)
			mutex.Unlock()
			client.Connection.Close()
		}()
	}
	wait.Wait()
	response.Header().Set("Content-Type", "application/json")
	json.NewEncoder(response).Encode(&detailsResponseList)
}

func main() {
	http.HandleFunc("/details", details)
	http.ListenAndServe(":1337", nil)
}
