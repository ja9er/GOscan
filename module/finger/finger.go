package finger

import (
	"GOscan/module/queue"
	"encoding/json"
	"github.com/PuerkitoBio/goquery"
	"github.com/yinheli/mahonia"
	"golang.org/x/net/html/charset"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

//收集HTTP信息的结构体
type Resps struct {
	Url        string
	Body       string
	Header     map[string][]string
	Server     string
	Statuscode int
	Length     int
	Title      string
	jsurl      []string
	favhash    string
}

//输出结果的结构体
type Outrestul struct {
	Url        string   `json:"url"`
	Cms        string   `json:"cms"`
	Server     string   `json:"server"`
	Statuscode int      `json:"statuscode"`
	Length     int      `json:"length"`
	Title      string   `json:"title"`
	Jsurl      []string `json:"jsurl"`
}

//下发匹配指纹的结构体
type bannerjob struct {
	finp    Fingerprint
	data    Resps
	headers string
	cms     *[]string
}

func MapToJson(param map[string][]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType)
	return dataString
}

func RemoveDuplicatesAndEmpty(a []string) (ret []string) {
	a_len := len(a)
	for i := 0; i < a_len; i++ {
		if (i > 0 && a[i-1] == a[i]) || len(a[i]) == 0 {
			continue
		}
		ret = append(ret, a[i])
	}
	return
}

func Convert(src string, srcCode string, tagCode string) string {
	if srcCode == tagCode {
		return src
	}
	srcCoder := mahonia.NewDecoder(srcCode)
	srcResult := srcCoder.ConvertString(src)
	tagCoder := mahonia.NewDecoder(tagCode)
	_, cdata, _ := tagCoder.Translate([]byte(srcResult), true)
	result := string(cdata)
	return result
}

func toUtf8(content string, contentType string) string {
	var htmlEncode string
	var htmlEncode2 string
	var htmlEncode3 string
	htmlEncode = "gb18030"
	if strings.Contains(contentType, "gbk") || strings.Contains(contentType, "gb2312") || strings.Contains(contentType, "gb18030") || strings.Contains(contentType, "windows-1252") {
		htmlEncode = "gb18030"
	} else if strings.Contains(contentType, "big5") {
		htmlEncode = "big5"
	} else if strings.Contains(contentType, "utf-8") {
		//实际上，这里获取的编码未必是正确的，在下面还要做比对
		htmlEncode = "utf-8"
	}
	reg := regexp.MustCompile(`(?is)<meta[^>]*charset\s*=["']?\s*([A-Za-z0-9\-]+)`)
	match := reg.FindStringSubmatch(content)
	if len(match) > 1 {
		contentType = strings.ToLower(match[1])
		if strings.Contains(contentType, "gbk") || strings.Contains(contentType, "gb2312") || strings.Contains(contentType, "gb18030") || strings.Contains(contentType, "windows-1252") {
			htmlEncode2 = "gb18030"
		} else if strings.Contains(contentType, "big5") {
			htmlEncode2 = "big5"
		} else if strings.Contains(contentType, "utf-8") {
			htmlEncode2 = "utf-8"
		}
	}
	reg = regexp.MustCompile(`(?is)<title[^>]*>(.*?)<\/title>`)
	match = reg.FindStringSubmatch(content)
	if len(match) > 1 {
		aa := match[1]
		_, contentType, _ = charset.DetermineEncoding([]byte(aa), "")
		contentType = strings.ToLower(contentType)
		if strings.Contains(contentType, "gbk") || strings.Contains(contentType, "gb2312") || strings.Contains(contentType, "gb18030") || strings.Contains(contentType, "windows-1252") {
			htmlEncode3 = "gb18030"
		} else if strings.Contains(contentType, "big5") {
			htmlEncode3 = "big5"
		} else if strings.Contains(contentType, "utf-8") {
			htmlEncode3 = "utf-8"
		}
	}
	if htmlEncode != "" && htmlEncode2 != "" && htmlEncode != htmlEncode2 {
		htmlEncode = htmlEncode2
	}
	if htmlEncode == "utf-8" && htmlEncode != htmlEncode3 {
		htmlEncode = htmlEncode3
	}
	if htmlEncode != "" && htmlEncode != "utf-8" {
		content = Convert(content, htmlEncode, "utf-8")
	}
	return content
}

func gettitle(httpbody string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(httpbody))
	if err != nil {
		return "Not found"
	}
	title := doc.Find("title").Text()
	title = strings.Replace(title, "\n", "", -1)
	title = strings.Trim(title, " ")
	return title
}

//计算ICO HASH
func getfavicon(httpbody string, turl string) string {
	faviconpaths := xegexpjs(`href="(.*?favicon....)"`, httpbody)
	var faviconpath string
	u, err := url.Parse(turl)
	if err != nil {
		panic(err)
	}
	turl = u.Scheme + "://" + u.Host
	if len(faviconpaths) > 0 {
		fav := faviconpaths[0][1]
		if fav[:2] == "//" {
			faviconpath = "http:" + fav
		} else {
			if fav[:4] == "http" {
				faviconpath = fav
			} else {
				faviconpath = turl + "/" + fav
			}

		}
	} else {
		faviconpath = turl + "/favicon.ico"
	}
	return favicohash(faviconpath)
}

/*
指纹匹配函数
*/
func lookforbanner(job bannerjob) {
	if job.finp.Location == "body" {
		if job.finp.Method == "keyword" {
			if iskeyword(job.data.Body, job.finp.Keyword) {
				(*job.cms) = append((*job.cms), job.finp.Cms)
			}
		}
		if job.finp.Method == "faviconhash" {
			if job.data.favhash == job.finp.Keyword[0] {
				(*job.cms) = append((*job.cms), job.finp.Cms)
			}
		}
		if job.finp.Method == "regular" {
			if isregular(job.data.Body, job.finp.Keyword) {
				(*job.cms) = append((*job.cms), job.finp.Cms)
			}
		}
	}
	if job.finp.Location == "header" {
		if job.finp.Method == "keyword" {
			if iskeyword(job.headers, job.finp.Keyword) {
				(*job.cms) = append((*job.cms), job.finp.Cms)
			}
		}
		if job.finp.Method == "regular" {
			if isregular(job.headers, job.finp.Keyword) {
				(*job.cms) = append((*job.cms), job.finp.Cms)
			}
		}
	}
	if job.finp.Location == "title" {
		if job.finp.Method == "keyword" {
			if iskeyword(job.data.Title, job.finp.Keyword) {
				(*job.cms) = append((*job.cms), job.finp.Cms)
			}
		}
		if job.finp.Method == "regular" {
			if isregular(job.data.Title, job.finp.Keyword) {
				(*job.cms) = append((*job.cms), job.finp.Cms)
			}
		}
	}
}

//检查指纹
func Checkbanner(target string, resp *http.Response, Finpx *Packjson, Task_id string) Outrestul {
	result, _ := ioutil.ReadAll(resp.Body)
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	httpbody := string(result)
	httpbody = toUtf8(httpbody, contentType)
	title := gettitle(httpbody)
	httpheader := resp.Header
	var server string
	capital, ok := httpheader["Server"]
	if ok {
		server = capital[0]
	} else {
		Powered, ok := httpheader["X-Powered-By"]
		if ok {
			server = Powered[0]
		} else {
			server = "None"
		}
	}
	var jsurl []string
	jsurl = Jsjump(httpbody, target)
	favhash := getfavicon(httpbody, target)
	data := Resps{target, httpbody, resp.Header, server, resp.StatusCode, len(httpbody), title, jsurl, favhash}
	headers := MapToJson(data.Header)
	var cms []string
	//协程并发匹配
	pool := queue.New(100)
	for _, finp := range Finpx.Fingerprint {
		pool.Add(1)
		job := bannerjob{finp, data, headers, &cms}
		go func(job bannerjob) {
			lookforbanner(job)
			pool.Done()
		}(job)
	}
	pool.Wait()
	cms = RemoveDuplicatesAndEmpty(cms)
	cmss := strings.Join(cms, ",")
	out := Outrestul{data.Url, cmss, data.Server, data.Statuscode, data.Length, data.Title, jsurl}
	return out
}
