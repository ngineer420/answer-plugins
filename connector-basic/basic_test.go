/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package basic

import (
	"strings"
	"testing"

	"github.com/apache/answer/plugin"
)

// The regression being guarded: an unmapped username used to fall through to
// the length padding and become "____", so every privacy-preserving signup
// collided on one handle. An unmapped display name stayed empty, which renders
// a blank byline and emits "author":{"name":""} in the QAPage markup.
func TestFormatUserInfoPseudonymises(t *testing.T) {
	tests := []struct {
		name        string
		prefix      string
		in          plugin.ExternalLoginUserInfo
		wantPrefix  string
		wantDisplay string // exact match when set
		keepsGiven  bool   // provider values must survive untouched
	}{
		{
			name:       "both unmapped generates a prefixed handle",
			prefix:     "grower",
			in:         plugin.ExternalLoginUserInfo{ExternalID: "1"},
			wantPrefix: "grower-",
		},
		{
			name:       "no prefix configured falls back to the default",
			prefix:     "",
			in:         plugin.ExternalLoginUserInfo{ExternalID: "1"},
			wantPrefix: "user-",
		},
		{
			name:        "display name follows a mapped username",
			prefix:      "grower",
			in:          plugin.ExternalLoginUserInfo{ExternalID: "1", Username: "mapped_name"},
			wantDisplay: "mapped_name",
			keepsGiven:  true,
		},
		{
			name:        "provider values are left alone",
			prefix:      "grower",
			in:          plugin.ExternalLoginUserInfo{ExternalID: "1", Username: "someuser", DisplayName: "Some User"},
			wantDisplay: "Some User",
			keepsGiven:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connector{Config: &ConnectorConfig{PseudonymPrefix: tt.prefix}}
			got := c.formatUserInfo(tt.in)

			if got.Username == "____" || strings.Trim(got.Username, "_") == "" {
				t.Fatalf("username collapsed to padding: %q", got.Username)
			}
			if got.DisplayName == "" {
				t.Error("display name is empty; would render a blank author byline")
			}
			if tt.wantPrefix != "" && !strings.HasPrefix(got.Username, tt.wantPrefix) {
				t.Errorf("username = %q, want prefix %q", got.Username, tt.wantPrefix)
			}
			if tt.wantDisplay != "" && got.DisplayName != tt.wantDisplay {
				t.Errorf("display name = %q, want %q", got.DisplayName, tt.wantDisplay)
			}
			if tt.keepsGiven && got.Username != tt.in.Username {
				t.Errorf("provider username was rewritten: %q -> %q", tt.in.Username, got.Username)
			}
		})
	}
}

// Generated handles must not collide, or the second member to sign up fails.
func TestGeneratedHandlesAreUnique(t *testing.T) {
	c := &Connector{Config: &ConnectorConfig{PseudonymPrefix: "grower"}}
	seen := make(map[string]bool, 500)
	for i := 0; i < 500; i++ {
		u := c.formatUserInfo(plugin.ExternalLoginUserInfo{ExternalID: "1"}).Username
		if seen[u] {
			t.Fatalf("duplicate handle generated: %s", u)
		}
		seen[u] = true
	}
}
