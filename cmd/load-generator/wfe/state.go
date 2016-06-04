package wfe

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/square/go-jose"

	"github.com/letsencrypt/boulder/cmd/load-generator/latency"
)

// RatePeriod describes how long a certain throughput should be maintained
type RatePeriod struct {
	For  time.Duration
	Rate int64
}

type registration struct {
	key    *rsa.PrivateKey
	signer jose.Signer
	iMu    *sync.RWMutex
	auths  []string
	certs  []string
}

// State holds *all* the stuff
type State struct {
	rMu      *sync.RWMutex
	regs     []*registration
	maxRegs  int
	client   *http.Client
	apiBase  string
	termsURL string

	warmupRegs    int
	warmupWorkers int

	realIP string

	nMu       *sync.RWMutex
	noncePool []string

	throughput int64

	challRPCAddr string

	certKey    *rsa.PrivateKey
	domainBase string

	callLatency *latency.Map

	runtime time.Duration

	challSrvProc *os.Process

	wg *sync.WaitGroup

	runPlan []RatePeriod
}

type rawRegistration struct {
	Certs []string `json:"certs"`
	//	Auths  []string `json:"auths"`
	RawKey []byte `json:"rawKey"`
}

type snapshot struct {
	Registrations []rawRegistration
}

// Snapshot will save out generated registrations and certs (ignoring authorizations)
func (s *State) Snapshot(filename string) error {
	s.rMu.Lock()
	defer s.rMu.Unlock()
	snap := snapshot{}
	for _, r := range s.regs {
		snap.Registrations = append(snap.Registrations, rawRegistration{
			Certs: r.certs,
			//			Auths:  r.auths,
			RawKey: x509.MarshalPKCS1PrivateKey(r.key),
		})
	}
	cont, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, cont, os.ModePerm)
}

// Restore previously generated registrations and certs
func (s *State) Restore(filename string) error {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	s.rMu.Lock()
	defer s.rMu.Unlock()
	snap := snapshot{}
	err = json.Unmarshal(content, &snap)
	if err != nil {
		return err
	}
	for _, r := range snap.Registrations {
		key, err := x509.ParsePKCS1PrivateKey(r.RawKey)
		if err != nil {
			continue
		}
		key.Precompute()
		signer, err := jose.NewSigner(jose.RS256, key)
		if err != nil {
			continue
		}
		signer.SetNonceSource(s)
		s.regs = append(s.regs, &registration{
			key:    key,
			signer: signer,
			certs:  r.Certs,
			//			auths:  r.Auths,
			iMu: new(sync.RWMutex),
		})
	}
	return nil
}

// New returns a pointer to a new State struct, or an error
func New(rpcAddr string, apiBase string, rate int, keySize int, domainBase string, runtime time.Duration, termsURL string, realIP string, runPlan []RatePeriod, maxRegs, warmupRegs, warmupWorkers int) (*State, error) {
	certKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	return &State{
		rMu:           new(sync.RWMutex),
		nMu:           new(sync.RWMutex),
		challRPCAddr:  rpcAddr,
		client:        client,
		apiBase:       apiBase,
		throughput:    int64(rate),
		certKey:       certKey,
		domainBase:    domainBase,
		callLatency:   latency.New(fmt.Sprintf("WFE -- %s test at %d base actions / second", runtime, rate)),
		runtime:       runtime,
		termsURL:      termsURL,
		wg:            new(sync.WaitGroup),
		realIP:        realIP,
		runPlan:       runPlan,
		maxRegs:       maxRegs,
		warmupWorkers: warmupWorkers,
		warmupRegs:    warmupRegs,
	}, nil
}

func (s *State) executePlan() {
	for _, p := range s.runPlan {
		atomic.StoreInt64(&s.throughput, p.Rate)
		fmt.Printf("Set base action rate to %d/s for %s\n", p.Rate, p.For)
		time.Sleep(p.For)
	}
}

func (s *State) warmup() {
	fmt.Printf("Beginning warmup, generating ~%d registrations with %d workers\n", s.warmupRegs, s.warmupWorkers)
	wg := new(sync.WaitGroup)
	for i := 0; i < s.warmupWorkers; i++ {
		wg.Add(1)
		go func() {
			for {
				s.rMu.RLock()
				if len(s.regs) >= s.warmupRegs {
					s.rMu.RUnlock()
					break
				}
				s.rMu.RUnlock()

				s.newRegistration(nil)
			}
			wg.Done()
		}()
	}
	stopProg := make(chan bool, 1)
	go func() {
		var last string
		for _ = range time.Tick(1 * time.Second) {
			select {
			case <-stopProg:
				return
			default:
				if last != "" {
					fmt.Fprintf(os.Stdout, strings.Repeat("\b", len(last)))
				}
				s.rMu.RLock()
				last = fmt.Sprintf("%d/%d registrations generated", len(s.regs), s.warmupRegs)
				fmt.Fprint(os.Stdout, last)
				s.rMu.RUnlock()
			}
		}
	}()
	wg.Wait()
	stopProg <- true
	fmt.Println("\nFinished warming up")
}

// Run runs the WFE load-generator for either the specified runtime/rate or the execution plan
func (s *State) Run(binName string, dontRunChallSrv bool, httpOneAddr string) error {
	s.callLatency.Started = time.Now()
	// If warmup, warmup
	if s.warmupRegs > len(s.regs) {
		s.warmup()
	}

	// Start chall server process
	if !dontRunChallSrv {
		cmd := exec.Command(binName, "chall-srv", "--rpcAddr="+s.challRPCAddr, "--httpOneAddr="+httpOneAddr)
		err := cmd.Start()
		if err != nil {
			return err
		}
		s.challSrvProc = cmd.Process
	}

	// If there is a run plan execute it
	if len(s.runPlan) > 0 {
		go s.executePlan()
	}

	// Run sending loop
	stop := make(chan bool, 1)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				s.wg.Add(1)
				go s.sendCall()
				time.Sleep(time.Duration(time.Second.Nanoseconds() / atomic.LoadInt64(&s.throughput)))
			}
		}
	}()

	time.Sleep(s.runtime)
	fmt.Println("SLEEP END")
	stop <- true
	fmt.Println("SENT STOP")
	s.wg.Wait()
	fmt.Println("KILLING CHALL SERVER")
	err := s.challSrvProc.Kill()
	if err != nil {
		fmt.Printf("Error killing challenge server: %s\n", err)
	}
	fmt.Println("ALL DONE")
	s.callLatency.Stopped = time.Now()
	return nil
}

// Dump saves the latency data out as a JSON file to be processed by latency-charter.py
func (s *State) Dump(jsonPath string) error {
	if jsonPath != "" {
		data, err := json.Marshal(s.callLatency)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(jsonPath, data, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}

// HTTP utils

func (s *State) post(endpoint string, payload []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Add("X-Real-IP", s.realIP)
	req.Header.Add("User-Agent", "load-generator -- heyo")
	resp, err := s.client.Do(req)
	if resp != nil {
		if newNonce := resp.Header.Get("Replay-Nonce"); newNonce != "" {
			s.addNonce(newNonce)
		}
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Nonce utils, these methods are used to generate/store/retrieve the nonces
// required for JWS

func (s *State) signWithNonce(endpoint string, alwaysNew bool, payload []byte, signer jose.Signer) ([]byte, error) {
	// nonce, err := s.getNonce(endpoint, alwaysNew)
	// if err != nil {
	// 	return nil, err
	// }
	jws, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}
	return []byte(jws.FullSerialize()), nil
}

func (s *State) Nonce() (string, error) {
	s.nMu.RLock()
	if len(s.noncePool) == 0 {
		s.nMu.RUnlock()
		started := time.Now()
		resp, err := s.client.Head(fmt.Sprintf("%s/directory", s.apiBase))
		finished := time.Now()
		state := "good"
		defer func() { s.callLatency.Add("HEAD /directory", started, finished, state) }()
		if err != nil {
			state = "error"
			return "", err
		}
		defer resp.Body.Close()
		if nonce := resp.Header.Get("Replay-Nonce"); nonce != "" {
			return nonce, nil
		}
		state = "error"
		return "", fmt.Errorf("Nonce header not supplied!")
	}
	s.nMu.RUnlock()
	s.nMu.Lock()
	defer s.nMu.Unlock()
	nonce := s.noncePool[0]
	s.noncePool = s.noncePool[1:]
	return nonce, nil
}

func (s *State) addNonce(nonce string) {
	s.nMu.Lock()
	defer s.nMu.Unlock()
	s.noncePool = append(s.noncePool, nonce)
}

// Reg object utils, used to add and retrieve registration objects

func (s *State) addReg(reg *registration) {
	s.rMu.Lock()
	defer s.rMu.Unlock()
	s.regs = append(s.regs, reg)
}

func (s *State) getReg() (*registration, bool) {
	s.rMu.RLock()
	defer s.rMu.RUnlock()
	regsLength := len(s.regs)
	if regsLength == 0 {
		return nil, false
	}
	return s.regs[mrand.Intn(regsLength)], true
}

// Call sender, it sends the calls!

type probabilityProfile struct {
	prob   int
	action func(*registration)
}

// this is pretty silly but idk...
func weightedCall(setup []probabilityProfile) func(*registration) {
	choices := make(map[int]func(*registration))
	n := 0
	for _, pp := range setup {
		for i := 0; i < pp.prob; i++ {
			choices[i+n] = pp.action
		}
		n += pp.prob
	}
	if len(choices) == 0 {
		return nil
	}

	return choices[mrand.Intn(n)]
}

func (s *State) sendCall() {
	actionList := []probabilityProfile{}
	s.rMu.RLock()
	if s.maxRegs == 0 || len(s.regs) < s.maxRegs {
		actionList = append(actionList, probabilityProfile{1, s.newRegistration})
	}
	s.rMu.RUnlock()

	reg, found := s.getReg()
	if found {
		actionList = append(actionList, probabilityProfile{3, s.newAuthorization})
		reg.iMu.RLock()
		if len(reg.auths) > 0 {
			actionList = append(actionList, probabilityProfile{4, s.newCertificate})
		}
		if len(reg.certs) > 0 {
			actionList = append(actionList, probabilityProfile{2, s.revokeCertificate})
		}
		reg.iMu.RUnlock()
	}

	weightedCall(actionList)(reg)
	s.wg.Done()
}