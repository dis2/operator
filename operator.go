package main
//import "bytes"
import "encoding/base64"
import "strings"
import "bufio"
import "golang.org/x/net/proxy"
import "crypto/rand"
import "fmt"
import "net"
import "crypto/sha1"
import "bytes"
import "io"
import "net/url"
import "io/ioutil"
import "net/http/cookiejar"
import "net/http"
import "encoding/json"
import "log"
import "os"
import "crypto/tls"
import dac "github.com/dis2/go-http-digest-auth-client"

const API_BASE = "https://api.surfeasy.com/v4/"
const TOR_URL = "socks5://127.0.0.1:9150"
const api_key = "94938A583190AF928BC4FA2279DC10AE8FABB5E9E21826C9092B404D24B949A0"
const client_type = "se0316"

type KV map[string]string
type Client struct {
	dac.DigestTransport // http request via tor for vpn auth
	http.Client // http request via tor
	DialProxy func() (net.Conn, error) // dials Tor
	Proxies []string
	User string
	Pass string
	Proxy string
}

func (c *Client) API(name string, kv KV) []byte {
	uv := url.Values{}
	for k,v := range kv {
		uv.Add(k,v)
	}
	req, _ := http.NewRequest("POST", API_BASE + name, bytes.NewBuffer([]byte(uv.Encode())))
	req.Header.Set("Content-Type","application/x-www-form-urlencoded")
	req.Header.Set("SE-Client-Type", client_type)
	req.Header.Set("SE-API-Key", api_key)
	req.Header.Set("SE-Operating-System", "Windows")

	resp, _ := c.DigestTransport.RoundTrip(req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return body
}

// make up vpn credentials
func (c *Client) authVPN() []byte {
	var rbuf [40]byte
	rand.Read(rbuf[:])
	c.DigestTransport = dac.NewTransport(client_type, api_key)
	c.DigestTransport.Client = &c.Client
	c.Jar, _ = cookiejar.New(nil)
	c.API("register_subscriber", KV{
		"email":fmt.Sprintf("%x@%s.surfeasy.vpn",rbuf[0:20], client_type),
		"password":fmt.Sprintf("%040x",rbuf[20:40]),
	})
	js := c.API("register_device", KV{
		"client_type":client_type,
		"device_hash":"4BE7D6F1BD040DE45A371FD831167BC108554111",
		"device_name":"Opera-Browser-Client",
	})
	ioutil.WriteFile("operator.auth", js, 0644)
	return js
}

func copyHeader(dst, src http.Header) {
    for k, vv := range src {
        for _, v := range vv {
            dst.Add(k, v)
        }
    }
}

func (c *Client) ProxyHTTP(w http.ResponseWriter, req *http.Request) {
	// Here, we do things a bit differently. Simply round-trip the request.
	resp, err := c.Client.Transport.RoundTrip(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (c *Client) ProxyCONNECT(w http.ResponseWriter, r *http.Request) {
	preq := &http.Request {
		Method: "CONNECT",
		URL: &url.URL{Opaque:r.Host},
		Host: r.Host,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	// Except this one
	auth := base64.StdEncoding.EncodeToString([]byte(c.User + ":" + c.Pass))
	preq.Header = make(http.Header)
	preq.Header.Set("Proxy-Authorization", "Basic " + auth)
	pconn, _ := c.DialProxy()
	wconn := bufio.NewWriter(pconn)
	preq.Write(wconn)
	wconn.Flush()
	br := bufio.NewReader(pconn)
	http.ReadResponse(br, preq) // TODO check response

	// tell client we're ready to talk
	w.WriteHeader(http.StatusOK)

	hijacker := w.(http.Hijacker)
	client, _, _ := hijacker.Hijack()
	go transfer(client, pconn)
	go transfer(pconn, client)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
    defer destination.Close()
    defer source.Close()
    io.Copy(destination, source)
}


func main() {
	// set up Tor proxy stuff
	torProxyURL, _ := url.Parse(TOR_URL)
	torDialer, _ := proxy.FromURL(torProxyURL, proxy.Direct)
	//tbTransport := &http.Transport{Dial: torDialer.Dial}

	// All http from c will go through Tor
	trans := http.Transport {}
	c := &Client{}

	c.Client.Transport = &trans
	//c.Transport = tbTransport
	trans.Dial = func(net,addr string) (net.Conn, error) {
		return torDialer.Dial("tcp", addr)
	}
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	trans.TLSClientConfig = conf

	// The actual proxy selecting dialer
	c.DialProxy = func() (net.Conn, error) {
		conn, err := torDialer.Dial("tcp", c.Proxy) // PROXY-GETTER
		tlsconn := tls.Client(conn, conf)
		return tlsconn, err
	}


	// parse auth data
	auth, err := ioutil.ReadFile("operator.auth")
	if err != nil {
		log.Println("Retrieving new auth data")
		auth = c.authVPN()
	} else {
		log.Println("Reusing old auth data")
	}
	obj := struct {
		Data struct {
			User string `json:"device_id"`
			Pass string `json:"device_password"`
		} `json:"data"`
	}{}
	json.Unmarshal(auth, &obj)
	user := fmt.Sprintf("%X", sha1.Sum([]byte(obj.Data.User)))
	pass := obj.Data.Pass
	log.Println("Using creds "+user+":"+pass)
	proxylist, err := ioutil.ReadFile(os.Args[1])
	proxyaddrs := []string{}
	for _, v := range strings.Split(string(proxylist), "\n") {
		addrs, err := net.LookupIP(v)
		if err != nil { continue}
		for _, addr := range addrs {
			proxyaddrs = append(proxyaddrs, addr.String() + ":443")
		}
	}
	log.Printf("Found %d proxies\n",len(proxyaddrs))
	server := &http.Server{
		Addr: "127.0.0.1:8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				c.ProxyCONNECT(w, r)
			} else {
				c.ProxyHTTP(w, r)
			}
		}),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	c.Proxies = proxyaddrs
	c.Proxy = c.Proxies[0]
	c.User = user
	c.Pass = pass
	// We do this only after talking to the VPN APIs
	trans.Proxy = func(req *http.Request) (*url.URL, error) {
		return url.Parse("https://"+c.User+":"+c.Pass+"@"+c.Proxy)
	}
	log.Fatal(server.ListenAndServe())
}
