/*
 *  fvserver - Filevault server.
 *
 *  Copyright (c) 2019  Priceboro Newport, Inc.  All Rights Reserved.
 *
 *  6/13/2019 - Version 2.0 - Added Authentication & https
 *  6/17/2019 - Version 2.1 - Added Roles & Permissions
 *
 */

package main

import (
	"../cola/filestore"
	"../cola/filevault"
	"../cola/webapp"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const version = "2.1"

var fv *filevault.FileVault
var root_path string
var temp_path string
var data_path string
var passwords *filestore.FileStore
var user_roles *filestore.FileStore
var permissions *filestore.FileStore

func main() {
	var config_path string
	args := os.Args
	if len(args) > 1 {
		config_path = args[1]
	}
	webapp.Register("", "/", Handler, false)
	webapp.ListenAndServe(config_path)
}

func Handler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	if fv == nil {
		temp_path = webapp.Config.Read("temp_path", "/tmp/")
		data_path = webapp.Config.Read("data_path", "./data/")
		root_path = webapp.Config.Read("root_path")
		fv = filevault.New(webapp.DB, root_path)
	}
	auth := r.URL.Query().Get("auth")
	if auth != "" {
		command := webapp.UrlPath(r, 0)
		if command == "check" {
			CheckHandler(w, r, p)
			return
		} else if command == "exist" {
			ExistsHandler(w, r, p)
			return
		} else if command == "extract" {
			ExtractHandler(w, r, p)
			return
		} else if command == "hash" {
			HashHandler(w, r, p)
			return
		} else if command == "import" {
			ImportHandler(w, r, p)
			return
		} else if command == "info" {
			InfoHandler(w, r, p)
			return
		} else if command == "list" {
			ListHandler(w, r, p)
			return
		} else if command == "query" {
			QueryHandler(w, r, p)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized\n")
	}

}

func CheckHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	root_directory, _ := ValidateAuth(r.URL.Query().Get("auth"), "check")
	if root_directory != "/" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized")
		return
	}
	results, err := fv.Check()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, err.Error())
	}
	if len(results) > 0 {
		for _, v := range results {
			fmt.Fprintf(w, "%s\n", v)
		}
	}
}

func ExistsHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	filename := r.URL.Query().Get("fn")
	root_directory, _ := ValidateAuth(r.URL.Query().Get("auth"), "exist "+filename)
	if root_directory != "" && strings.Index(filename, root_directory) != 0 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized")
		return
	}
	if filename == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No filename specified.")
		return
	}
	file_ids, err := fv.QueryFilename(filename)
	for i := 0; i < len(file_ids); i++ {
		fmt.Fprintf(w, "%10d\n", file_ids[i])
	}
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, err.Error())
	}
}

func ExtractHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	auth := r.URL.Query().Get("auth")
	fid := r.URL.Query().Get("f")
	root_directory, _ := ValidateAuth(auth, "extract "+fid)
	if root_directory == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized")
		return
	}
	if fid == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No file_id specified.")
		return
	}
	file_id, _ := strconv.Atoi(fid)
	if file_id == 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Invalid file_id.")
		return
	}
	fi, err := fv.Info(file_id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Not Found")
		return
	}
	if strings.Index(fi.Path, root_directory) != 0 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized")
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		name = fi.Name
	}
	if webapp.UrlPath(r, 1) != name {
		webapp.Redirect(w, r, "/extract/"+name+"?auth="+auth+"&f="+fid+"&name="+url.QueryEscape(name))
		return
	}
	temp_filename := temp_path + p.Session + filepath.Ext(name)
	_, err = fv.Extract(file_id, temp_filename)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Not Found")
		return
	}
	mime_type := webapp.ContentType(temp_filename)
	f, err := ioutil.ReadFile(temp_filename)
	if (err != nil) || (mime_type == "") {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Not Found")
		return
	}
	b := bytes.NewBuffer(f)
	w.Header().Set("Content-type", mime_type)
	b.WriteTo(w)
	os.Remove(temp_filename)
	return
}

func HashHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	hash := r.URL.Query().Get("h")
	root_directory, _ := ValidateAuth(r.URL.Query().Get("auth"), "hash "+hash)
	if root_directory == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized")
		return
	}
	if hash == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No hash specified.")
		return
	}
	file_ids, filenames, err := fv.ListHash(hash)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Not Found")
		return
	}
	for i := 0; i < len(file_ids); i++ {
		if strings.Index(filenames[i], root_directory) == 0 {
			fmt.Fprintf(w, "%10d: %s\n", file_ids[i], filenames[i])
		}
	}
}

func ImportHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	if r.Method == "POST" {
		r.ParseMultipartForm(32 << 20)
		file, _, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, err.Error())
			return
		} else {
			defer file.Close()
			filename := r.Form.Get("fn")
			root_directory, write_permission := ValidateAuth(r.URL.Query().Get("auth"), "import "+filename)
			if !write_permission || strings.Index(filename, root_directory) < 0 {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, "Unauthorized")
				return
			}
			temp_filename := temp_path + p.Session + "_import"
			f, err := os.OpenFile(temp_filename, os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, err.Error())
				return
			}
			io.Copy(f, file)
			if filename == "" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "No filename specified.")
				return
			}
			timestamp := time.Now()
			if r.Form.Get("ts") != "" {
				timestamp, err = time.Parse("2006-01-02 15:04:05", r.Form.Get("ts"))
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, "Invalid timestamp: Format must be YYYY-MM-DD HH:MM:SS")
					return
				}
			}
			f.Close()
			file_id, err := fv.Import(temp_filename, filename, timestamp)
			if err == nil {
				fmt.Fprintf(w, "%10d: %s\n", file_id, filename)
			} else if err.Error() == "Exists" {
				fmt.Fprintf(w, "%10d+ %s\n", file_id, filename)
			} else {
				fmt.Fprintf(w, err.Error())
			}
			os.Remove(temp_filename)
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No file uploaded.")
	}
}

func InfoHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	fid := r.URL.Query().Get("f")
	var root_directory string
	if fid == "" {
		root_directory, _ = ValidateAuth(r.URL.Query().Get("auth"), "info")
		if root_directory == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "Unauthorized")
			return
		}
		fmt.Fprintf(w, "Filevault Server v%s\n", version)
		return
	} else {
		root_directory, _ = ValidateAuth(r.URL.Query().Get("auth"), "info "+fid)
		if root_directory == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "Unauthorized")
			return
		}
	}
	file_id, _ := strconv.Atoi(fid)
	if file_id == 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Invalid file_id.")
		return
	}
	fi, err := fv.Info(file_id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Not Found")
		return
	}
	if strings.Index(fi.Path, root_directory) == 0 {
		fmt.Fprintf(w, "File ID: %d\n", fi.FileID)
		fmt.Fprintf(w, "Path: %s\n", fi.Path)
		fmt.Fprintf(w, "Name: %s\n", fi.Name)
		fmt.Fprintf(w, "Date: %s\n", fi.Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(w, "Size: %d\n", fi.Size)
		fmt.Fprintf(w, "Hash: %s\n", fi.Hash)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized")
	}
}

func ListHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	path := r.URL.Query().Get("p")
	root_directory, _ := ValidateAuth(r.URL.Query().Get("auth"), "list "+path)
	if root_directory == "" || strings.Index(path, root_directory) != 0 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized")
		return
	}
	if path == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No path specified.")
		return
	}
	file_ids, names, err := fv.ListPath(path)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Not Found")
		return
	}
	for i := 0; i < len(file_ids); i++ {
		fmt.Fprintf(w, "%10d: %s\n", file_ids[i], names[i])
	}
}

func QueryHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	terms := r.URL.Query().Get("t")
	root_directory, _ := ValidateAuth(r.URL.Query().Get("auth"), "query "+terms)
	if root_directory == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Unauthorized")
		return
	}
	if len(terms) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "No query terms specified.")
		return
	}
	file_ids, filenames, err := fv.Query(terms)
	for i := 0; i < len(file_ids); i++ {
		if strings.Index(filenames[i], root_directory) == 0 {
			fmt.Fprintf(w, "%10d: %s\n", file_ids[i], filenames[i])
		}
	}
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, err.Error())
	}
}

func SHA256(str string) string {
	h := sha256.New()
	h.Write([]byte(str))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func ValidateAuth(auth string, id string) (root_directory string, write_permission bool) {
	components := strings.Split(auth, "/")
	if len(components) != 3 {
		return "", false
	}
	if passwords == nil {
		passwords = filestore.New(data_path + "passwords.fs")
	}
	if user_roles == nil {
		user_roles = filestore.New(data_path + "user_roles.fs")
	}
	if permissions == nil {
		permissions = filestore.New(data_path + "permissions.fs")
	}
	if SHA256(id+components[1]+passwords.Read(components[0])) == components[2] {
		permission_components := strings.Split(permissions.Read(user_roles.Read(components[0])), ",")
		if len(permission_components) > 0 {
			root_directory = permission_components[0]
			if len(permission_components) > 1 {
				write_permission = strings.Contains(strings.ToLower(permission_components[1]), "w")
			}
		}
	}
	return
}
