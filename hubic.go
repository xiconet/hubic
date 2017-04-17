// cli interface for gohubic
package main 

import (
	"fmt"
	"os"
	"strings"
	"strconv"
	"github.com/codegangsta/cli"
	"github.com/xiconet/hubic/gohubic"
)

const(
	api_url = "https://api.hubic.com"
	cfg_file = "C:/Documents and Settings/arc/.config/hubic.yml"
)

func main() {
	app := cli.NewApp()
	app.Name = "hubic"
	app.Version = "0.1"
	app.Usage = "A client for the hubiC 'rest' api. Lists the specified path if no option is provided. The path may begin by the user's name or id, e.g. user1/path/to/folder"
	
	users := map[string]string{} 	// FIXME
	userlist := []string{} 			// FIXME
	uids := []string{} 				// FIXME
	app.Flags = []cli.Flag {
	cli.BoolFlag{
		Name: "verbose, V",
		Usage: "switch verbose/debug mode on",
		},
	cli.StringFlag{
		Name: "user, u",
		Value: "current_user",
		Usage: fmt.Sprintf("user name (one of %s)", strings.Join(userlist, ", "))
		},
	cli.StringFlag{
		Name: "setuser, su",
		Value: "",
		Usage: "set current user name in config file",
		},
	cli.BoolFlag{
		Name: "authorize, auth",
		Usage: "(re-)authorize this program for the specified user",
		},
	cli.BoolFlag{
		Name: "info, i",
		Usage: "get account info for the specified user",
		},
	cli.BoolFlag{
		Name: "all, a",
		Usage: "list the specified path for all users",
		},
	cli.BoolFlag{
		Name: "meta, me",
		Usage: "get metainfo for the specified path",
		},
	cli.StringFlag{
		Name: "mkfolder, m",
		Value: "",
		Usage: "create a new folder in the specified parent folder (root if unspecified)",
		},
	cli.StringFlag{
		Name: "upload, p",
		Value: "",
		Usage: "upload (file) or upsync (folder) to the specified parent folder path",
		},
	cli.StringFlag{
		Name: "rename, ren",
		Value: "",
		Usage: "rename a file or a folder to the specified full destination path",
		},
	cli.StringFlag{
		Name: "move, mv",
		Value: "",
		Usage: "Move a file or folder to the specified full destination path",
		},
	cli.StringFlag{
		Name: "copy, cp",
		Value: "",
		Usage: "copy a file to the specified full destination path",
		},
	cli.BoolFlag{
		Name: "download, d",
		Usage: "download items(s) under the specified path",
		},
	cli.StringFlag{
		Name: "exclude, no",
		Value: "",
		Usage: "exclude the specified file extension from downloading",
		},
	cli.IntFlag{
		Name: "depth, r",
		Value: 1,
		Usage: "recursion depth, default is 1 for immediate children",
		},
	cli.BoolFlag{
		Name: "fast, f",
		Usage: "download faster with parallel connections (internal code)",
		},
	cli.BoolFlag{
		Name: "aria, x",
		Usage: "use aria2c external downloader",
		},
	cli.BoolFlag{
		Name: "delete, rm",
		Usage: "delete the specified path",
		},
	}
	app.Action = func(c *cli.Context) {
		path := "/"
		if len(c.Args()) > 0 {
			path = c.Args()[0]
		}
		if c.Bool("verbose") {gohubic.Verbose = true}
		var user string
		switch {
		case c.String("setuser") != "":
			user = c.String("setuser")
			if _, ok := users[user]; !ok {
				fmt.Printf("error:%q is not a registered user\n", user)
				os.Exit(2)
			}
			gohubic.SetUser(user)
		default:
			user = c.String("user")
			if user != "current_user" {
				if _, ok := users[user]; !ok {
					fmt.Printf("error:%q is not a registered user\n", user)
					os.Exit(2)
				}
			}
		}
		if gohubic.StringInSlice(strings.Split(path, "/")[0], userlist) {
			user = strings.Split(path, "/")[0]
			path = strings.Join(strings.Split(path, "/")[1:], "/")
		} else if gohubic.StringInSlice(strings.Split(path, "/")[0], uids) {
			i, _ := strconv.Atoi(strings.Split(path, "/")[0])
			path = strings.Join(strings.Split(path, "/")[1:], "/")
			user = userlist[i]
		}
		if path == "" {path = "/"}
		h := gohubic.NewClient(api_url, cfg_file, user, gohubic.Auth{}, map[string]string{})
		if !c.Bool("all") {
			h.SetConfig(user)
		}
		switch {
		case c.Bool("authorize"):
			h.Authorize(user)
		case c.Bool("info"):
			h.Info(user)
		case c.String("mkfolder") != "":
			h.MkFolder(c.String("mkfolder"), path)
		case c.String("upload") != "":
			h.Upload(c.String("upload"), path)
		case c.Bool("download"):
			h.Download(path, c.Int("depth"), c.Bool("aria"), c.Bool("fast"), c.String("exclude"))
		case c.Bool("delete"):			
			h.Delete(path)
		case c.Bool("all"):
			h.ListAll(path, c.Int("depth"))	
		case c.Bool("meta"):
			h.GetMeta(path)
		case c.String("copy") != "":
			h.CopyFile(c.String("copy"), path)
		case c.String("move") != "":
			h.MoveObj(c.String("move"), path)
		case c.String("rename") != "":
			h.RenameObj(c.String("rename"), path)
		default:
			h.TreeList(path, c.Int("depth"))
		}
	}
  app.Run(os.Args)
}		