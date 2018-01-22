package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"
)

var httpClient *http.Client
var cookies []*http.Cookie
var cookieJar *cookiejar.Jar
var version int = 36
var maxThreads int = 1
var dictionary string = "dictionary.txt"
var fileExt string = ".php"
var fileMode int = 0
var followRedirects = 0
var host string = "http://testfire.net"
var proxy string = ""
var count int = 0
var done chan int
var workQueue chan string

func main() {
	if len(os.Args) < 5 {
		usage()
		os.Exit(1)
	}
	processArgs()
	banner()
	fmt.Println("DATE | TIME | [RESPONSE CODE] | URL (=> REDIRECT) | (SIZE)")
	if host[len(host)-1] != '/' {
		host = strings.Join([]string{host, "/"}, "")
	}
	f, e := os.Open(dictionary)
	if e != nil {
		log.Fatal(e)
	}
	defer f.Close()
	webInit()
	rdr := bufio.NewReader(f)
	scnr := bufio.NewScanner(rdr)
	scnr.Split(bufio.ScanLines)
	done = make(chan int)
	workQueue = make(chan string, 1000)
	for count < maxThreads {
		go webReq(count, workQueue, done)
		count++
	}
	for scnr.Scan() {
		w := scnr.Text()
		if w != "" {
			if w[0] != '#' {
				workQueue <- scnr.Text()
			}
		}
	}
	for i := 0; i < maxThreads; i++ {
		workQueue <- "!!EOF!!"
	}
	for count > 0 {
		_ = <-done // discard EOF signals
		count--
		// fmt.Println(tid, "DONE")
	}
}

func banner() {
	fmt.Println("bruteweb build", version, "\t https://github.com/mattweidner")
	fmt.Println("Config:")
	fmt.Println("U:", host)
	fmt.Println("W:", dictionary)
	if followRedirects == 1 {
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

func usage() {
	fmt.Println("brutewebdir build", version, "\t https://github.com/mattweidner")
	fmt.Println(os.Args[0], "-u <http[s]://baseurl> -w <wordlist> [-t <maxThreads>] [-p <http://proxy:port>] [-x <file extension>]")
	fmt.Println("   -f : Follow redirects.")
	fmt.Println("   -u : Base url to scan.")
	fmt.Println("   -w : Word list dictionary.")
	fmt.Println("   -t : Maximum number of scanning threads (Default 4).")
	fmt.Println("   -p : Use this proxy (http://127.0.0.1:8080)")
	fmt.Println("   -x : Add this file extension to each ditionary entry (php)")
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
		if relativeURL[0] == '/' {
			relativeURL = relativeURL[1:]
		}
		url := strings.Join([]string{host, relativeURL}, "")
		if fileMode == 1 {
			url = strings.Join([]string{url, fileExt}, "")
		}
		req, e := http.NewRequest("GET", url, nil)
		if e != nil {
			log.Printf("[!] %v %s", tid, e)
			continue
		}
		r, e := httpClient.Do(req)
		if e != nil {
			log.Printf("[!] %v %s", tid, e)
			workQueue <- relativeURL
			continue
		}
		r.Body.Close()
		if r.StatusCode >= 300 && r.StatusCode < 400 {
			loc := r.Header.Get("Location")
			raw, _ := httputil.DumpResponse(r, false)
			log.Printf("[%v] %s => %s (%v)", r.StatusCode, relativeURL, loc, len(raw))
		}
		if r.StatusCode < 300 {
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
			if followRedirects == 0 {
				return http.ErrUseLastResponse
			}
			return error(nil)
		},
		Jar:     cookieJar,
		Timeout: time.Duration(15 * time.Second),
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func processArgs() {
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-f":
			followRedirects = 1
		case "-w":
			i++
			dictionary = os.Args[i]
		case "-p":
			i++
			proxy = os.Args[i]
		case "-u":
			i++
			host = os.Args[i]
		case "-t":
			i++
			x, e := strconv.Atoi(os.Args[i])
			if e != nil {
				maxThreads = 1
			} else {
				maxThreads = x
			}
		case "-x":
			fileMode = 1
			i++
			fileExt = os.Args[i]
			if fileExt[0] != '.' {
				fileExt = strings.Join([]string{".", fileExt}, "")
			}
		default:
			banner()
			os.Exit(1)
			i++
		}
	}
}
