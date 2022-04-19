package main

import (
	"GOscan/module/POC"
	"GOscan/module/finger"
	"GOscan/module/queue"
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/gookit/color"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
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

func request(target string, client *http.Client, resultnumber *int, Task_id string, path string) {
	req, err := http.NewRequest("GET", target, nil)
	req.Header.Add("Cache-Control", "max-age=0")
	req.Header.Add("Upgrade-Insecure-Requests", "1")
	req.Header.Add("User-Agent", rndua())
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	resp, err := client.Do(req)
	if err != nil {
		//fmt.Println("[-]: ", err)
		return
	}
	defer resp.Body.Close()
	errs := finger.LoadWebfingerprint(path)
	if errs != nil {
		color.RGBStyleFromString("237,64,35").Println("[-] Webfingerprint file error!!!")
		os.Exit(1)
	}
	Finpx := finger.GetWebfingerprint()
	out := finger.Checkbanner(target, resp, Finpx, Task_id)
	if out.Cms != "" {
		*resultnumber = *resultnumber + 1
		POC.Attackmatch(target, out.Cms)
	}
	if len(out.Jsurl) > 0 {
		request(out.Jsurl[0], client, resultnumber, Task_id, path)
	}
}

func main() {
	//指纹文件路径
	fingerpath := "file/finger.json"
	//目标文件路径
	targetpath := "file/test.txt"
	//可设置代理
	proxy, _ := url.Parse("http://127.0.0.1:8080")

	start := time.Now()
	var resultnumber int //检测成功banner数量
	var slice1 []string  //存取 从url文档中读到的URL

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
		Transport: tr,
	}
	inputFile, inputError := os.Open(targetpath)
	if inputError != nil {
		fmt.Printf("An error occurred on opening the inputfile\n" +
			"Does the file exist?\n" +
			"Have you got acces to it?\n")
		return
	}
	defer inputFile.Close()
	inputReader := bufio.NewReader(inputFile)
	for {
		inputString, readerError := inputReader.ReadString('\n')
		inputString = strings.Replace(inputString, "\r\n", "", -1)
		slice1 = append(slice1, inputString)
		if readerError == io.EOF {
			break
		}
	}

	//时间戳定义Task_id
	Task_id := time.Now().Unix()
	//定义协程池，设置最大数量
	pool := queue.New(100)
	for i := 0; i < len(slice1); i++ {
		pool.Add(1)
		go func(i int) {
			//要修改函数外的变量需要引用传递
			request(slice1[i], client, &resultnumber, strconv.FormatInt(Task_id, 10), fingerpath)
			pool.Done()
		}(i)
	}

	pool.Wait()

	fmt.Println("[+] success check banner&Send Paylaod ", resultnumber)
	elapsed := time.Since(start)
	fmt.Println("Take ", elapsed)
}
