/*
Copyright 2025 jmh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package siteconfig adapts the user-provided site configuration portion of
// the historical zeek-operator/pkg/zeek/config/generator.go at p6m commit
// fc517c9869e937962693d9639b73228fac8f15c8.
package siteconfig

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// AppendPolicy preserves the base policy and appends user-provided Zeek code.
func AppendPolicy(base, policy string) string {
	var builder strings.Builder
	builder.WriteString(base)
	// Add user-provided site config (adapted from the historical generator).
	if policy != "" {
		builder.WriteString("\n# User-provided site configuration\n")
		builder.WriteString(policy)
		builder.WriteString("\n")
	}
	return builder.String()
}

// ScriptFiles adapts the inline-script ConfigMap behavior from the historical
// zeek-operator/pkg/zeek/scripts/manager.go (same p6m commit as above).
func ScriptFiles(scripts map[string]string) (map[string]string, []string, error) {
	valid := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	data := make(map[string]string, len(scripts))
	names := make([]string, 0, len(scripts))
	for name, body := range scripts {
		if len(name) > 240 || !valid.MatchString(name) {
			return nil, nil, fmt.Errorf("invalid Zeek script name %q: use letters, numbers, underscores or hyphens", name)
		}
		filename := name + ".zeek"
		data[filename] = body
		names = append(names, filename)
	}
	sort.Strings(names)
	return data, names, nil
}
