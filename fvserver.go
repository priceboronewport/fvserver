package main

import (
	"../cola/filevault"
	"../cola/webapp"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

var fv *filevault.FileVault
var root_path string
var temp_path string

func main() {
	webapp.Register("", "/", Handler, false)
	webapp.ListenAndServe("")
}

func Handler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	if fv == nil {
		temp_path = webapp.Config.Read("temp_path", "/tmp/")
		root_path = webapp.Config.Read("root_path")
		fv = filevault.New(webapp.DB, root_path)
	}
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
	} else if command == "import" {
		ImportHandler(w, r, p)
		return
	} else if command == "info" {
		InfoHandler(w, r, p)
		return
	} else if command == "query" {
		QueryHandler(w, r, p)
		return
	}
	w.WriteHeader(http.StatusBadRequest)
}

func CheckHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	results, err := fv.Check()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, " ** ERROR: check: %s\n", err.Error())
	}
	if len(results) > 0 {
		for _, v := range results {
			fmt.Fprintf(w, "%s\n", v)
		}
	}
}

func ExistsHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	filename := r.URL.Query().Get("fn")
	if filename == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, " ** ERROR: exist: No filename specified.\n")
		return
	}
	file_ids, err := fv.QueryFilename(filename)
	for i := 0; i < len(file_ids); i++ {
		fmt.Fprintf(w, "%10d\n", file_ids[i])
	}
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, " ** ERROR: %s\n", err.Error())
	}
}

func ExtractHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	fid := r.URL.Query().Get("f")
	if fid == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, " ** ERROR: extract: No file_id specified.\n")
		return
	}
	file_id, _ := strconv.Atoi(fid)
	if file_id == 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, " ** ERROR: extract: Invalid file_id.\n")
		return
	}
	fi, err := fv.Info(file_id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, " ** ERROR: info: Not Found")
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		name = fi.Name
	}
	if webapp.UrlPath(r, 1) != name {
		webapp.Redirect(w, r, "/extract/"+name+"?f="+fid+"&name="+url.QueryEscape(name))
		return
	}
	temp_filename := temp_path + p.Session + filepath.Ext(name)
	_, err = fv.Extract(file_id, temp_filename)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, " ** ERROR: extract: Not Found")
		return
	}
	mime_type := webapp.ContentType(temp_filename)
	f, err := ioutil.ReadFile(temp_filename)
	if (err != nil) || (mime_type == "") {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, " ** ERROR: extract: Not Found")
		return
	}
	b := bytes.NewBuffer(f)
	w.Header().Set("Content-type", mime_type)
	b.WriteTo(w)
	os.Remove(temp_filename)
	return
}

func ImportHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	if r.Method == "POST" {
		r.ParseMultipartForm(32 << 20)
		file, _, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, " ** ERROR: %s\n", err.Error())
			return
		} else {
			defer file.Close()
			temp_filename := temp_path + p.Session + "_import"
			f, err := os.OpenFile(temp_filename, os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, " ** ERROR: import: %s\n", err.Error())
				return
			}
			io.Copy(f, file)
			filename := r.Form.Get("fn")
			if filename == "" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, " ** ERROR: import: No filename specified.\n")
				return
			}
			timestamp := time.Now()
			if r.Form.Get("ts") != "" {
				timestamp, err = time.Parse("2006-01-02 15:04:05", r.Form.Get("ts"))
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, " ** ERROR: import: Invalid timestamp: Format must be YYYY-MM-DD HH:MM:SS\n")
					return
				}
			}
			f.Close()
			file_id, err := fv.Import(temp_filename, filename, timestamp)
			if err == nil {
				fmt.Fprintf(w, "%10d: %s\n", file_id, filename)
			} else {
				fmt.Fprintf(w, " ** ERROR: import: %s\n", err.Error())
			}
			os.Remove(temp_filename)
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, " ** ERROR: import: No file uploaded.\n")
	}
}

func InfoHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	fid := r.URL.Query().Get("f")
	if fid == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, " ** ERROR: info: No file_id specified.\n")
		return
	}
	file_id, _ := strconv.Atoi(fid)
	if file_id == 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, " ** ERROR: info: Invalid file_id.\n")
		return
	}
	fi, err := fv.Info(file_id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, " ** ERROR: info: Not Found\n")
		return
	}
	fmt.Fprintf(w, "File ID: %d\n", fi.FileID)
	fmt.Fprintf(w, "Path: %s\n", fi.Path)
	fmt.Fprintf(w, "Name: %s\n", fi.Name)
	fmt.Fprintf(w, "Date: %s\n", fi.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Size: %d\n", fi.Size)
	fmt.Fprintf(w, "Hash: %s\n", fi.Hash)
}

func QueryHandler(w http.ResponseWriter, r *http.Request, p webapp.HandlerParams) {
	terms := r.URL.Query().Get("t")
	if len(terms) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, " ** ERROR: query: No query terms specified.\n")
		return
	}
	file_ids, filenames, err := fv.Query(terms)
	for i := 0; i < len(file_ids); i++ {
		fmt.Fprintf(w, "%10d: %s\n", file_ids[i], filenames[i])
	}
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, " ** ERROR: %s\n", err.Error())
	}
}
