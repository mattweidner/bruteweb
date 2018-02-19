package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"os"
	"strings"
	"time"
)

type extensions []string

var fileExt extensions
var httpClient *http.Client
var cookies []*http.Cookie
var cookieJar *cookiejar.Jar
var version int = 50
var maxThreads int = 1
var dictionary string = ""
var fileMode int = 0
var followRedirects bool = false
var baseURL string = ""
var proxy string = ""
var count int = 0
var done chan int
var workQueue chan string

func main() {
	log.SetOutput(os.Stdout)
	flags()
	if baseURL == "" || dictionary == "" {
		flag.Usage()
		return
	}
	if !strings.Contains(baseURL, "http") {
		log.Printf("[!] Must include http:// or https:// in URL argument.")
		return
	}

	banner()
	fmt.Println("DATE | TIME | [RESPONSE CODE] | URL (=> REDIRECT) | (RESPONSE LENGTH)")
	// Add a trailing slash to the base URL if it's missing.
	if baseURL[len(baseURL)-1] != '/' {
		baseURL = strings.Join([]string{baseURL, "/"}, "")
	}
	// Open the wordlist file
	f, e := os.Open(dictionary)
	if e != nil {
		log.Fatal(e)
	}
	defer f.Close()
	// Init the web client
	webInit()
	// Initialize the wordlist scanner
	rdr := bufio.NewReader(f)
	scnr := bufio.NewScanner(rdr)
	scnr.Split(bufio.ScanLines)
	// Initialize the IPC channels.
	done = make(chan int)
	workQueue = make(chan string, 1000)
	// Start the worker http client threads.
	for count < maxThreads {
		go webReq(count, workQueue, done)
		count++
	}
	// Start stuffing the work queue with urls.
	for scnr.Scan() {
		w := scnr.Text()
		if w != "" {
			if w[0] != '#' {
				s := scnr.Text()
				workQueue <- s
				if len(fileExt) > 0 {
					for _, x := range fileExt {
						if x[0] != '.' {
							workQueue <- strings.Join([]string{s, ".", x}, "")
						} else {
							workQueue <- strings.Join([]string{s, x}, "")
						}
					}
				}
			}
		}
	}
	// Signal the threads the wordlist queue is empty.
	for i := 0; i < maxThreads; i++ {
		workQueue <- "!!EOF!!"
	}
	// Wait for child thread ack of EOF signal.
	for count > 0 {
		_ = <-done // discard EOF signals
		count--
		// fmt.Println(tid, "DONE")
	}
}

func webReq(tid int, workQueue chan string, done chan int) {
	for {
		relativeURL := <-workQueue
		if relativeURL == "!!EOF!!" {
			done <- tid
			return
		}
		if len(relativeURL) == 0 {
			return
		}
		// Strip leading slashes from wordlist entry because
		// the base URL ends with a slash.
		if relativeURL[0] == '/' {
			relativeURL = relativeURL[1:]
		}
		// Join the baseURL with the wordlist entry.
		url := strings.Join([]string{baseURL, relativeURL}, "")
		// Send the request
		req, e := http.NewRequest("GET", url, nil)
		if e != nil {
			log.Printf("[!] %v %s", tid, e)
			continue
		}
		r, e := httpClient.Do(req)
		if e != nil {
			// There was an error accessing this URL
			// Notify and resubmit it to the work queue
			// for a retry. Could cause DOS condition.
			//
			// TODO: ADD A RETRY COUNTER AND TERMINATE IF EXCEEDED.
			log.Printf("[!] %v %s", tid, e)
			workQueue <- relativeURL
			continue
		}
		// ALWAYS read the entire response body and close it
		// to ensure open TCP connections are re-used for
		// subsequent requests.
		// https://golang.org/src/net/http/response.go
		// https://stackoverflow.com/questions/17948827/reusing-http-connections-in-golang
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode >= 300 && r.StatusCode != 404 {
			// Handle printing redirect info.
			loc := r.Header.Get("Location")
			// Raw DumpResponse() output is used for length
			// calculation since redirects have no body.
			// This is an estimation, caveats from DumpRequest apply.
			// https://golang.org/pkg/net/http/httputil/#DumpRequest
			raw, _ := httputil.DumpResponse(r, false)
			log.Printf("[%v] %s => %s (%v)", r.StatusCode, relativeURL, loc, len(raw))
		}
		if r.StatusCode < 300 {
			// Handle printing successes
			log.Printf("[%v] %s (%v)", r.StatusCode, relativeURL, r.ContentLength)
		}
	}
}

func webInit() {
	// Initialize http client.
	if proxy != "" {
		os.Setenv("HTTP_PROXY", proxy)
	}
	cookieJar, _ = cookiejar.New(nil)
	cookies = nil
	httpClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if followRedirects == false {
				return http.ErrUseLastResponse
			}
			return error(nil)
		},
		Jar:     cookieJar,
		Timeout: time.Duration(15 * time.Second),
		Transport: &http.Transport{
			MaxIdleConnsPerHost: maxThreads,
			MaxIdleConns:        100,
			IdleConnTimeout:     10 * time.Second,
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func flags() {
	flag.StringVar(&baseURL, "u", "", "Base url. REQUIRED.")
	flag.StringVar(&dictionary, "w", "", "Word list dictionary. REQUIRED.")
	flag.BoolVar(&followRedirects, "f", false, "Follow Redirects")
	flag.IntVar(&maxThreads, "t", 4, "Maximum number of scanning threads, default 4.")
	flag.StringVar(&proxy, "p", "", "Proxy url (-p http://127.0.0.1:8080).")
	flag.Var(&fileExt, "x", "Add file extension to each wordlist entry. (-x .php).")
	flag.Parse()
}

func (i *extensions) String() string {
	// fileExt flag handler, prints flag state.
	s := ""
	a := *i
	for _, x := range a {
		s = strings.Join([]string{s, x}, ", ")
	}
	return s
}

func (i *extensions) Set(value string) error {
	// fileExt flag handler, appends multiple "-x"
	// instances to the fileExt array.
	*i = append(*i, value)
	return nil
}

func banner() {
	fmt.Println("bruteweb build", version, "\t https://github.com/mattweidner")
	fmt.Println("Config:")
	fmt.Println("U:", baseURL)
	fmt.Println("W:", dictionary)
	if followRedirects == true {
		fmt.Println("F: ON")
	} else {
		fmt.Println("F: OFF")
	}
	if proxy != "" {
		fmt.Println("P:", proxy)
	}
	fmt.Println("T:", maxThreads)
	if fileMode == 1 {
		fmt.Println("X:", fileExt)
	}
	fmt.Println("")
}
