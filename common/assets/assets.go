/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package assets

import (
	"errors"
	"fmt"
	"github.com/adrg/xdg"
	"github.com/sirupsen/logrus"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func GetLocationAsset(log *logrus.Logger, filename string) (path string, err error) {
	folder := "dae"
	location := os.Getenv("DAE_LOCATION_ASSET")
	// check if DAE_LOCATION_ASSET is set
	if location != "" {
		// add DAE_LOCATION_ASSET to search path
		searchPaths := []string{
			filepath.Join(location, filename),
		}
		// additional paths for non windows platforms
		if runtime.GOOS != "windows" {
			searchPaths = append(
				searchPaths,
				filepath.Join("/usr/local/share", folder, filename),
				filepath.Join("/usr/share", folder, filename),
			)
		}
		searchDirs := make([]string, len(searchPaths))
		for i := range searchDirs {
			searchDirs[i] = filepath.Dir(searchPaths[i])
		}
		log.Debugf(`Search "%v" in [%v]`, filename, strings.Join(searchDirs, ", "))
		for _, searchPath := range searchPaths {
			if _, err = os.Stat(searchPath); err != nil && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			log.Debugf(`Found "%v" at %v`, filename, searchPath)
			// return the first path that exists
			return searchPath, nil
		}
		return "", fmt.Errorf("%v: %w in [%v]", filename, os.ErrNotExist, strings.Join(searchDirs, ", "))
	} else {
		if runtime.GOOS != "windows" {
			// search XDG data directories on non windows platform
			searchDirs := append([]string{xdg.DataHome}, xdg.DataDirs...)
			for i := range searchDirs {
				searchDirs[i] = filepath.Join(searchDirs[i], folder)
			}
			log.Debugf(`Search "%v" in [%v]`, filename, strings.Join(searchDirs, ", "))
			relpath := filepath.Join(folder, filename)
			fullpath, err := xdg.SearchDataFile(relpath)
			if err != nil {
				return "", fmt.Errorf("%v: %w in [%v]", filename, os.ErrNotExist, strings.Join(searchDirs, ", "))
			}
			log.Debugf(`Found "%v" at %v`, filename, fullpath)
			return fullpath, nil
		} else {
			// fallback to the old behavior of using only current dir on Windows
			path := filepath.Join("./", filename)
			if absPath, e := filepath.Abs(path); e == nil {
				path = absPath
			}
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("%v: %w in %v", filename, os.ErrNotExist, path)
			}
			return path, nil
		}
	}
}
