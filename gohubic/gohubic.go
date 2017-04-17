// hubic (ovh) client
// TODO: implement metadata update 

package gohubic

import (
  "fmt"
	"log"
	pth "path"
	ospath "path/filepath"
	"io"
	"io/ioutil"
	"bytes"
	"net/http"
	uri "net/url"
	"encoding/json"
	"encoding/base64"
  "os"
	"os/exec"
	"sort"
	"strings"
	"strconv"
	"time"
	"menteslibres.net/gosexy/yaml"
	"menteslibres.net/gosexy/to"
	"github.com/dustin/go-humanize"
	"github.com/cheggaaa/pb"
	"runtime"
	urlut "github.com/opennota/url"
	fd "github.com/xiconet/godownload"
)

func b64encode(s string) string {
	data := []byte(s)
	str := base64.StdEncoding.EncodeToString(data)
	return str
}

const(
	api_url = "https://api.hubic.com"
)

var(
	home = os.Getenv("USERPROFILE")
	cfg_file = ospath.Join(home, ".config", "hubic.yml")
	uids = map[string]string{}
	Verbose bool
)

type Client struct {
		BaseUrl string
		CfgFile string
		User string
		Auth Auth
		Endpoints map[string]string		
}

type Auth struct {
		TokenType string
		Token string			
}

func NewClient(baseUrl, cfgFile, user string, auth Auth, endpoints map[string]string) (c *Client){
	return &Client{baseUrl, cfgFile, user, Auth{}, map[string]string{}}
}

type Item struct {
		Name			string		`json:"name"`
		Bytes			uint64		`json:"bytes"`
		Hash			string		`json:"hash"`
		ContentType		string		`json:"content_type"`
		User            string		`json:"user"`
		Children        []Item	    `json:"children"`	
}

type ItemSet []Item
func (s ItemSet) setUser(i int, user string) {
	s[i].User = user 
}

type ByName []Item 

func (a ByName) Len() int           { return len(a) }
func (a ByName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByName) Less(i, j int) bool { return a[i].Name < a[j].Name }


type OToken struct {
		AccessToken		string 	`json:"access_token"`
		RefreshToken	string	`json:"refresh_token"`
		ExpiresIn		int64 	`json:"expires_in"`
}

type SToken struct {
		Token       string 	`json:"token"`
		Expires     string	`json:"expires"`
		Endpoint    string 	`json:"endpoint"`
}

func StringInSlice(s string, x []string) bool {
	for _, i := range x {
		if i == s {	
			return true
		}
	}
	return false
}

func SetUser(user string) {
	cfg, err := yaml.Open(cfg_file)
	if err != nil {panic(err)}
	cfg.Set("users", "current_user", user)
	err = cfg.Save()
	if err != nil { panic(err) }
}

func (c *Client) tokenRequest(config *yaml.Yaml, user string, params map[string]string) string {
	client_id := to.String(config.Get(user, "oauth", "client_id"))
	client_secret := to.String(config.Get(user, "oauth", "client_secret"))	
	credentials := b64encode(client_id+":"+client_secret)	

	data := params
	auth := map[string]string{"Authorization": "Basic " + credentials}
	status, body := c.apiReq("POST", api_url + "/oauth/token/", auth, nil, data)
	if status[:3] != "200" {
		fmt.Println("[tokenRequest] error: bad server status:", status, "\n"+string(body))
		os.Exit(2)
    }
	
    token := OToken{}
	err := json.Unmarshal(body, &token)
	if err != nil {panic(err)}
    config.Set(user, "oauth", "access_token", token.AccessToken)
	if token.RefreshToken != "" {
		config.Set(user, "oauth", "refresh_token", token.RefreshToken)
	}
	expat := time.Now().Unix() + token.ExpiresIn	
    config.Set(user, "oauth", "expires_at", float64(expat))	
	config.Save()
	return token.AccessToken
}

func AuthCodeUrl(config *yaml.Yaml, user string) string {
    client_id := to.String(config.Get(user, "oauth", "client_id"))
    redirect_uri := to.String(config.Get("misc", "redirect_uri")) 
	buf := bytes.Buffer{}
	buf.WriteString(api_url + "/oauth/auth/")
	scope := "usage.r,account.r,getAllLinks.r,credentials.r,sponsorCode.r,activate.w,sponsored.r,links.drw"
	v := uri.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", client_id)
	v.Set("redirect_uri", redirect_uri)
	v.Set("scope", scope)	
	buf.WriteByte('?')
	buf.WriteString(v.Encode())
	return buf.String()
}


func (c *Client) Authorize(user string) string {
	config, err := yaml.Open(cfg_file)
    if err != nil {
        panic(err)
    }
	if user == "current_user" {
		user = to.String(config.Get("users", user))
	} 
	auth_url := AuthCodeUrl(config, user)
	fmt.Printf("Go to the following url and authorize access:\n %s", auth_url)
	fmt.Println("enter the returned url: ")   
	var input string
	fmt.Scanln(&input)  
	p, err := uri.Parse(input)
	if err != nil {panic(err)}
	code := p.Query()["code"][0]
	redirect_uri := to.String(config.Get("misc", "redirect_uri"))	
	params := map[string]string{
		"code": code, 
		"redirect_uri": redirect_uri, 
		"grant_type": "authorization_code",
	}
	return c.tokenRequest(config, user, params)
}

	
func (c *Client) refreshToken(config *yaml.Yaml, user string) string {
	refresh_token := to.String(config.Get(user, "oauth", "refresh_token"))	
	params := map[string]string{
		"grant_type": "refresh_token",
		"refresh_token": refresh_token,
	}
	return c.tokenRequest(config, user, params)
}

func (c *Client) getCredentials(config *yaml.Yaml, user string) (token, endpoint string) {
	var stoken SToken
    access_token := to.String(config.Get(user, "oauth", "access_token"))	
    expat := to.Int64(config.Get(user, "oauth", "expires_at"))	
	if access_token == "" || expat - time.Now().Unix() < 60 {
		access_token = c.refreshToken(config, user)	
	}       	
	url := api_url + "/1.0/account/credentials"
	auth := map[string]string{"Authorization": "Bearer " + access_token}
	status, body := c.apiReq("GET", url, auth, nil, nil)
	
    if status[:3] != "200" {
		fmt.Println("[getCredentials] error: bad server status:", status, "\n" + string(body))
		os.Exit(1)
	}	
    err := json.Unmarshal(body, &stoken)
	if err != nil {panic(err)}	 
    config.Set(user, "storage", "token", stoken.Token)
    config.Set(user, "storage", "expires", stoken.Expires)    
    endpoint = stoken.Endpoint	
    if endpoint[len(endpoint) -1:] != "/" {
        endpoint += "/"
	}	
	ep := to.String(config.Get(user, "storage", "endpoint"))	
	if ep != endpoint {
        fmt.Println("endpoint has changed, storing to config file")
		fmt.Println("old endpoint:", ep, "new:", endpoint)
        config.Set(user, "storage", "endpoint", endpoint)
	}	
	config.Save()	
    return stoken.Token, endpoint
}


func (c *Client) SetConfig(user string) (endpoint, token string) {
	config, err := yaml.Open(cfg_file)
    if err != nil {
        panic(err)
    }
	if user == "current_user" {
		user = to.String(config.Get("users", "current_user"))	
	}	
	endpoint = to.String(config.Get(user, "storage", "endpoint"))	
	token = to.String(config.Get(user, "storage", "token"))
	expires := to.String(config.Get(user, "storage", "expires"))	
	x, _ := time.Parse(time.RFC3339, expires)
	
	if x.Unix() - time.Now().Unix() < 600 {
        token, endpoint = c.getCredentials(config, user)
    }
	c.User = user
	c.BaseUrl = endpoint
	c.Auth.TokenType = "X-Auth-Token"
	c.Auth.Token = token
	return endpoint, token
}

func (c *Client) apiReq(method, u string, headers, params, data interface{}) (string, []byte) {
	url, err := uri.Parse(u)
	if err != nil {panic(err)}
	//fmt.Println("final url:", url.String()) // DEBUG
	var req *http.Request
	if params != nil {
		q := uri.Values{}
		for k, v := range params.(map[string]string) {
			q.Set(k,v)
		}
		url.RawQuery = q.Encode()
		req, err = http.NewRequest(method, url.String(), nil)
		if err != nil {panic(err)}
	}
	if data != nil {
		form := uri.Values{}
		for k, v := range data.(map[string]string) {
			form.Set(k,v)
		}
		req, err = http.NewRequest(method, url.String(), strings.NewReader(form.Encode()))
		if err != nil {panic(err)}
	}
	// let's not forget the case where params and data and both nil:
	if req == nil {
		req, err = http.NewRequest(method, url.String(), nil)
	}
	
	if !strings.HasPrefix(url.String(), api_url) {
		req.Header.Set("X-Auth-Token", c.Auth.Token)
	}
	
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if headers != nil {
		for k, v := range headers.(map[string]string) {
			req.Header.Set(k, v)
		}
	}
	
	if Verbose {
		fmt.Printf("request: %+v\n", req) // DEBUG
	}
	
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println(err)
		fmt.Println("req: %v\n", req)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {panic(err)}
	return resp.Status, body 	
}

func (c *Client) Info(user string){
	config, err := yaml.Open(cfg_file)
    if err != nil {
        panic(err)
    }
	if user == "current_user" {
		user = to.String(config.Get("users", user))	
	}
	access_token := to.String(config.Get(user, "oauth", "access_token"))		
    exp_at := to.Int64(config.Get(user, "oauth", "expires_at"))
		
	if exp_at - time.Now().Unix() < 60 {		
		access_token = c.refreshToken(config, user)
	}
	
	var account string
	
	url := api_url + "/1.0/account"
	auth := map[string]string{"Authorization": "Bearer " + access_token}
	params := map[string]string{"format":"json"}
	status, body := c.apiReq("GET", url, auth, params, nil)
	if status[:3] != "200" {
		fmt.Println("error: bad status:", status, "\n"+string(body))
	} else {
		account = string(body)
	}
	// simply changing path triggers a server error, complainig about the format param
	//url, err = uri.Parse(api_url + "/1.0/account/usage")
	url = api_url + "/1.0/account/usage"
	status, body = c.apiReq("GET", url, auth, nil, nil)
	if status[:3] != "200" {
		fmt.Println("server status:", status, "\n"+string(body))
	} else {
		usage := map[string]uint64{}
		err := json.Unmarshal(body, &usage)
		if err != nil {panic(err)}
		quota := usage["quota"]
		used := usage["used"]
		left := quota - used
		
		fmt.Println(account)
		fmt.Printf(" Quota: %d bytes [%s]\n", quota, humanize.IBytes(quota)) 
		fmt.Printf(" Used: %d bytes [%s]\n", used, humanize.IBytes(used))
		fmt.Printf(" Left: %d bytes [%s]\n", left, humanize.IBytes(left))
	}
}
			

func (c *Client) getResource() (data ItemSet) {
	p := map[string]string{"format":"json"}
	status, body := c.apiReq("GET", c.BaseUrl + "default", nil, p, nil)
	if status != "200 OK" {
		fmt.Println("error: bad server status:", status, "\n"+string(body))
	} else {
		err := json.Unmarshal(body, &data)
		if err != nil {panic(err)}
	}
	return
}

func (c *Client) GetMeta(path string) (bool, Item){
	data := c.getResource()
	for _, i := range data {
		if strings.TrimRight(i.Name, "/") == path {
			fmt.Printf("%+v\n", i)
			return true, i
		}
	}
	return false, Item{}
}

func (s ItemSet) getMeta(path string) (bool, Item){
	for _, i := range s {
		if strings.TrimRight(i.Name, "/") == path {
			fmt.Printf("%+v\n", i)
			return true, i
		}
	}
	return false, Item{}
}

func getTreeRoots(root string, data []Item) []Item {
	var roots []Item	
    if root == "/" {
		for _, i := range data {
			s := strings.TrimRight(i.Name, "/")
			f := strings.Split(s, "/")
			if len(f) == 1 {
				roots = append(roots, i)
			}
		}
    }  else {
		for _, i := range data {
			s := strings.TrimRight(i.Name, "/")
			if s == root {
				roots = append(roots, i)
				break
			}
		}
	}	
    return roots
}
	
func makeLeaves(roots []Item, data []Item, depth, p int) []Item {	
    for k, i := range roots {       
        if i.Bytes == 0 {
			s := strings.TrimRight(i.Name, "/")
			for _, j := range data {
				if s == pth.Dir(strings.TrimRight(j.Name, "/")) {
					i.Children = append(i.Children, j)
				}
			}
		}
		roots[k] = i
		if (depth == 0) || (p < depth) {
            if len(i.Children) > 0 {
                makeLeaves(i.Children, data, depth, p+1)
			}
		}
	}
	return roots 
}

func rightPad(s string, padStr string, pLen int) string {
	return s + strings.Repeat(padStr, pLen);
}

func shorten(s string, maxlen int) string {	
	f := strings.Fields(s)
	if strings.Join(f, "") == s {
		return s	// shorten would fail if name has no whitespace 
	}
	u := len(s)	
	for u >= maxlen - 4 {
		f = strings.Fields(s)
		f = append(f[:len(f) - 2], f[len(f) - 1:]...)
		s = strings.Join(f, " ")
		u = len(s)
	}
	fs := strings.Fields(s)
	lastword := fs[len(fs) - 1]
	fa := append(fs[:len(fs) - 1], "... "+lastword)
	return strings.Join(fa, " ")
}

func printTree(tree []Item, c int, allUsers bool, uids map[string]string){
    i := strings.Repeat("  ", c)	
	sort.Sort(ByName(tree))
	mx := 70	
	for _, t := range tree {	
		name := pth.Base(t.Name)		
		if t.Bytes == 0 {
			if allUsers && c == 0 {
				fmt.Printf("[%s] %s%s\n", uids[t.User], i, name)
			} else {
				fmt.Printf("%s%s\n", i, name)
			}
		} else {
			size := humanize.IBytes(uint64(t.Bytes))
			if len(name) + len(i) > mx {
				name = shorten(name, mx - len(i))
			}
			if len(name) + len(i) < mx {				
				name = rightPad(name, " ", mx - (len(name) + len(i)))
			}
			fmt.Printf("%s%s %s\n", i, name, size)
		}
        printTree(t.Children, c+1, allUsers, uids)
	}			
}	

func (c *Client) makeTree(root string, depth int)[]Item {
	// a more robust listing method with a cleaner code	
	var tree []Item	
	data := c.getResource()
	roots := getTreeRoots(root, data)
	switch {
	case root == "/":
		if depth == 1 {
			tree = roots
		} else {
			tree = makeLeaves(roots, data, depth, 2)
		}
	default:
		tree = makeLeaves(roots, data, depth, 1)
	}
	return tree	
}

func (c *Client) TreeList(root string, depth int) {
	tree := c.makeTree(root, depth)
	printTree(tree, 0, false, uids)
}
	
func (c *Client) ListAll(path string, depth int) {
	var compiled []Item
	config, err := yaml.Open(cfg_file)
    if err != nil {
        panic(err)
    }
	s := config.Get("users", "users")
	users, _ := s.([]interface{})		
	for n, u := range users {		
		user, _ := u.(string)
		c.SetConfig(user)
		uids[user] = fmt.Sprintf("%d", n)
		udata := c.getResource()
		for i, _ := range udata {
			udata.setUser(i, user)
		}		
		var tree []Item
		roots := getTreeRoots(path, udata)
		if path == "/" {
			tree = roots
			compiled = append(tree, compiled...) 
		} else {
			tree = makeLeaves(roots, udata, depth, 1)
			compiled = append(compiled, tree[0].Children...)
		}   
	}
	printTree(compiled, 0, true, uids)	
	legend := []string{}
	for k, v := range uids {
		legend = append(legend, fmt.Printf("%s=%s " , v, k))
	}
	fmt.Println("\n[" + strings.Join(legend, " ") + "]")
}
	
func (c *Client) MkFolder(foldername, parent string) (string){ 
	url := c.BaseUrl + pth.Join("default", parent, foldername) + "/"
	headers := map[string]string{"Content-Type": "application/directory"}
	status, body := c.apiReq("PUT", url, headers, nil, nil)
	fmt.Println("server status:", status)
	fmt.Println(string(body))
	return status
}
    
func (c *Client) uploadFile(filepath, parent string) int { 	
    filename := ospath.Base(filepath) 
	path := pth.Join("default", parent, filename)
	url := c.BaseUrl + path	
	data, err := os.Open(filepath)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer data.Close()	
	req, err := http.NewRequest("PUT", url, data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Auth-Token", c.Auth.Token)	
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}	
	defer res.Body.Close()	
	fmt.Println(res.Status)
	if res.StatusCode != 201 {
		fmt.Println("error: upload failed")
		return 1
	}	
	return 0
}

func (c *Client) pipedUpload(filepath, parent string) { 	
    filename := ospath.Base(filepath) 
	path := pth.Join("default", parent, filename)
	url := c.BaseUrl + path	
	input, err := os.Open(filepath)
	check(err)
	defer input.Close()
	stat, err := input.Stat()
	check(err)
	pipeOut, pipeIn := io.Pipe()
	fsize := stat.Size()
	bar := pb.New(int(fsize)).SetUnits(pb.U_BYTES)
	bar.ShowSpeed = true
	writer := io.Writer(pipeIn)
	var resp *http.Response
	done := make(chan error)	
	go func() {
		req, err := http.NewRequest("PUT", url, pipeOut)
		if err != nil {
			done <- err
			return
		}
		req.ContentLength = fsize 
		req.Header.Set("X-Auth-Token", c.Auth.Token)
		log.Println("Created Request")
		bar.Start()

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			done <- err
			return
		}
		done <- nil
	}()	
	out := io.MultiWriter(writer, bar)
	_, err = io.Copy(out, input)
	check(err)
	check(pipeIn.Close())
	check(<-done)
	bar.FinishPrint("Upload done!")
}

func check(err error) {
	_, file, line, _ := runtime.Caller(1)
	if err != nil {
		log.Fatalf("Fatal from <%s:%d>\nError:%s", file, line, err)
	}
}

func (c *Client) upsync(localPath, parent string){
	fmt.Printf("creating folder %q in %q\n", ospath.Base(localPath), parent)
	c.MkFolder(ospath.Base(localPath), parent)
	dirlist, err := ioutil.ReadDir(localPath)
	if err != nil {panic(err)}
	for _, i := range dirlist {
		if !i.IsDir() && strings.ToLower(i.Name()) != "thumbs.db" {
			filepath := ospath.Join(localPath, i.Name())
			parent := pth.Join(parent, ospath.Base(localPath))
			fmt.Printf("uploading %q to %q\n", filepath, parent)
			c.pipedUpload(filepath, parent)
		}
		if i.IsDir(){
			c.upsync(ospath.Join(localPath, i.Name()), pth.Join(parent, ospath.Base(localPath)))
		}
	}
}

func (c *Client) Upload(localPath, parent string) {		
	inf, er := os.Stat(localPath)
	if er != nil { panic(er) }		
	if inf.IsDir() {
		c.upsync(localPath, parent)		
	} else {
		fmt.Printf("uploading %q to %q\n" , localPath, parent)
		c.pipedUpload(localPath, parent)
	}
}

func (c *Client) downloadFile(path, filepath string, aria, fast bool) int64 {		
	url := c.BaseUrl + "default/" + path
	switch {
	case aria:
		cmd := exec.Command("aria2c" , "--continue", "--file-allocation=falloc", "--max-connection-per-server=5" , "--min-split-size=1M", "--remote-time=true", "--header=X-Auth-Token: "+c.Auth.Token, url, "-o "+filepath)		
		cmd.Stdout = os.Stdout		
		cmd.Stderr = os.Stderr				
		err := cmd.Run()
		if err != nil {fmt.Println(err)}		
		return 0
	case fast:
		c.FastFileDownload(url, filepath, 5)
		return 0
	default:		
		client := &http.Client{}		
		req, err := http.NewRequest("GET", url, nil)
		req.Header.Add("X-Auth-Token", c.Auth.Token)		
		resp, err := client.Do(req)	
		if err != nil { 
			panic(err) 
		}		
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Error: server returned non-200 status: %v\n", resp.Status)
			return 0
		}		
		i, _ := strconv.Atoi(resp.Header.Get("Content-Length"))
		sourceSize := int64(i)
		defer resp.Body.Close()			
		out, err := os.Create(filepath)
		if err != nil {panic(err)}
		defer out.Close()		
		bar := pb.New(int(sourceSize)).SetUnits(pb.U_BYTES).SetRefreshRate(time.Millisecond * 10)
		bar.ShowSpeed = false
		if i >= 1024 * 1024 {
			bar.ShowSpeed = true
		}
		bar.Start()
		writer := io.MultiWriter(out, bar)
		n, err := io.Copy(writer, resp.Body)
		if err != nil {
			fmt.Println("Error while downloading", url, "-", err)
			return 0
		}	
		bar.Finish()
		return n
	}
}	
	
func (c *Client) downsync(folderpath string, tree []Item, depth, r int, aria, fast bool, exclude string) {
	err := os.MkdirAll(folderpath, 0777)
	if err != nil { panic(err) }	
	for _, i := range tree {
		path := i.Name
		name := pth.Base(path)
		if i.Bytes != 0 && pth.Ext(name) != exclude {
			filepath := folderpath + "/" + name
			var dlfast bool
			if fast && i.Bytes >= 1024*1024 {dlfast=true}
			fmt.Println("downloading", filepath)			
			c.downloadFile(path, filepath, aria, dlfast)
		}
		if (depth == 0 || r < depth) && i.Bytes == 0 {
			c.downsync(folderpath + "/" + name, i.Children, depth, r+1, aria, fast, exclude)
		}
	}
}

func (c *Client) Download(path string, depth int, aria, fast bool, exclude string) {	
	data := c.getResource()
	ok, meta := data.getMeta(path)
	if !ok {
		fmt.Println("error: path not found")
		os.Exit(2)
	}
	if meta.ContentType == "application/directory" || meta.Bytes == 0 {
		roots := getTreeRoots(path, data)
		tree := makeLeaves(roots, data, depth, 1)	
		if path != "/" {
			folderpath := pth.Base(path)
			c.downsync(folderpath, tree[0].Children, depth, 1, aria, fast, exclude)
		}
	} else {
		var dlfast bool
		if fast && meta.Bytes >= 1024*1024 {dlfast=true}
		c.downloadFile(path, pth.Base(path), aria, dlfast)
	}	
}

func DisplayProgress(dl *fd.Downloader) {
	barWidth := float64(40)
	for {
		status, total, downloaded, elapsed := dl.GetProgress()
		frac := float64(downloaded)/float64(total)
		bps := humanize.IBytes(uint64(float64(downloaded)/elapsed.Seconds()))
		fmt.Fprintf(os.Stdout, "\r[%-41s] %5.2f%% of %s %5s/s %.fs ", strings.Repeat("=", int(frac*barWidth))+">", frac*100, humanize.IBytes(uint64(total)), bps, elapsed.Seconds())
		switch {
		case status == fd.Completed:
			fmt.Println("\nSuccessfully completed download in", elapsed)
			return
		case status == fd.OnProgress:
		case status == fd.NotStarted:
		default:
			fmt.Printf("\nFailed: %s\n", status)
			os.Exit(1)
		}
		time.Sleep(time.Second)
	}
}

func (c *Client) FastFileDownload(url, filePath string, conns int) {
	d := fd.New()
	d.SetHeaders(map[string]string{"X-Auth-Token":c.Auth.Token})
	size, _, err := d.Init(url, conns, filePath)	
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("File size is %s\n", humanize.IBytes(size))
	d.StartDownload()
	go d.Wait()
	DisplayProgress(&d)
}

func (c *Client) CopyFile(src, dest string) (string, string) {
    url := c.BaseUrl + "default/" + src
    d := urlut.Encode("default/" + dest)
    req, err := http.NewRequest("COPY", url, nil)
	if err != nil {fmt.Println(err); os.Exit(2)}
	req.Header.Add("X-Auth-Token", c.Auth.Token)
	req.Header.Add("Destination", d)	
	resp, err := http.DefaultClient.Do(req)
    if err != nil {
		fmt.Println(err); 
		os.Exit(2)
	}
	defer resp.Body.Close()
	body := &bytes.Buffer{}
	body.ReadFrom(resp.Body)
	fmt.Println(body.String())
	return resp.Status, body.String()
}

func (c *Client) MoveTree(tree []Item, dest string, srcFiles, destFiles []string) ([]string, []string) {
    fmt.Printf("destination path: %q\n", dest)
    folderName := pth.Base(dest)
	parent := pth.Dir(dest)
    fmt.Printf( "creating destination folder %q in %q\n" , folderName, parent)
    mkf := c.MkFolder(folderName, parent)
    if mkf == "201 Created" {
        fmt.Printf("copying files to %q\n", dest)
        for _, i := range tree {
            if i.ContentType != "application/directory" {
                filename := pth.Base(strings.TrimRight(i.Name, ("/")))
                srcFiles = append(srcFiles, filename)
                src := strings.TrimRight(i.Name, ("/"))
                fileDest := pth.Join(dest, filename)
                fmt.Printf("copying %q to %q\n", src, fileDest)
                mvf := c.MoveFile(src, fileDest)
                if mvf {
                    destFiles = append(destFiles, filename)
				}
			} else {
                itemName := pth.Base(strings.TrimRight(i.Name, ("/")))
                folderPath := pth.Join(dest, itemName)
                srcFiles, destFiles = c.MoveTree(i.Children, folderPath, srcFiles, destFiles)
			}
		}
	}	
    return srcFiles, destFiles
}

func (c *Client) MoveFile(src, target string) (success bool) {
	status, body := c.CopyFile(src, target)
    if status != "201 Created" {
        fmt.Println("error bad status:", status + "\n" + body)
        fmt.Printf("could not copy %q to %q\n", src, target)
		return false
    } else {
        fmt.Printf("%s => \"%s\"\n", status, target)
        s, b := c.DeleteObj(src)		
        if s[:3] == "204" {
            fmt.Printf("%s => %q deleted\n", s, src)
            success = true
		} else {
			fmt.Println(s + "\n" + b)
			fmt.Printf("failed to delete %q\n", src)
			success = false 
		}
	}
	return success		
}

func (c *Client) MoveObj(src, dest string) {
	
	data := c.getResource()
	ok, meta := data.getMeta(src)
	if !ok {
		fmt.Println("[getMeta] error: path not found")
		os.Exit(2)
	}
	if meta.ContentType == "application/directory" || meta.Bytes == 0 {
		roots := getTreeRoots(src, data)
		tree := makeLeaves(roots, data, 0, 1)	
		srcFiles, destFiles := c.MoveTree(tree, dest, []string{}, []string{})		
		fmt.Printf("copied %d of %d files\n", len(destFiles), len(srcFiles) )
			if len(srcFiles) == len(destFiles) {
			c.deleteFolder(src)
		}
	} else {
		c.MoveFile(src, dest)
	}	
}

func (c *Client) RenameObj(src, dest string) {	
	data := c.getResource()
	ok, meta := data.getMeta(src)
	if !ok {
		fmt.Println("[getMeta] error: path not found")
		os.Exit(2)
	}
	if meta.ContentType == "application/directory" || meta.Bytes == 0 {
		roots := getTreeRoots(src, data)
		tree := makeLeaves(roots, data, 0, 1)	
		srcFiles, destFiles := c.MoveTree(tree[0].Children, dest, []string{}, []string{})
		fmt.Printf("copied %d of %d files\n", len(destFiles), len(srcFiles) )
			if len(srcFiles) == len(destFiles) {
			c.deleteFolder(src)
		}
	} else {
		c.MoveFile(src, dest)
	}	
}
	
func (c *Client) DeleteObj(path string) (string, string){
	url := c.BaseUrl + fmt.Sprintf("default/%s", path)
	status, body := c.apiReq("DELETE", url, nil, nil, nil)
	if status[:3] == "204" {
		fmt.Printf("%s - %q successfully deleted\n", status, path)
	} else {
        fmt.Println("error: bad status:", status, "(expected: 204)")
		fmt.Println(body)
	}
	return status, string(body)
}

func (c *Client) delTree(tree []Item) {
   for _, i := range tree {
        if i.ContentType != "application/directory" {
            fmt.Printf("deleting file %s\n", i.Name)
            c.DeleteObj(strings.TrimRight(i.Name, "/")) 
        } else {
            fmt.Printf("deleting %s\n" , i.Name)
            c.DeleteObj(i.Name)
            c.delTree(i.Children)
		}
	}
}

func (c *Client) deleteFolder(path string) {
	depth := 3
	tree := c.makeTree(path, depth)
	c.delTree(tree)
}

func (c *Client) Delete(path string) {
	if path == "/" {
		fmt.Println("error: we're not going to delete the entire tree, are we?")
		os.Exit(0)
	}
	data := c.getResource()
	ok, meta := data.getMeta(path)
	if !ok {
		fmt.Println("error: path not found")
		os.Exit(2)
	}
	if meta.ContentType == "application/directory" || meta.Bytes == 0 {
		roots := getTreeRoots(path, data)
		tree := makeLeaves(roots, data, 0, 1)
		c.delTree(tree)	
	} else {
		c.DeleteObj(path)
	}	
}

