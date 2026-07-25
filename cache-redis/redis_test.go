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

package redis

import "testing"

// The whole point of the change is that a rediss:// endpoint produces a client
// with TLS actually enabled, so that is asserted directly rather than inferred
// from "it connected". A silent fallback to plaintext is the failure mode worth
// guarding against: it would still work against a permissive server while
// sending session tokens in the clear.
func TestBuildRedisOptions(t *testing.T) {
	tests := []struct {
		name     string
		conf     CacheConfig
		wantAddr string
		wantTLS  bool
		wantUser string
		wantPass string
		wantErr  bool
	}{
		{
			name:     "rediss URL enables TLS",
			conf:     CacheConfig{Endpoint: "rediss://default:secret@my-db.upstash.io:6379"},
			wantAddr: "my-db.upstash.io:6379",
			wantTLS:  true,
			wantUser: "default",
			wantPass: "secret",
		},
		{
			name:     "redis URL stays plaintext",
			conf:     CacheConfig{Endpoint: "redis://localhost:6379"},
			wantAddr: "localhost:6379",
			wantTLS:  false,
		},
		{
			name:     "bare host:port keeps the original behaviour",
			conf:     CacheConfig{Endpoint: "localhost:6379", Username: "u", Password: "p"},
			wantAddr: "localhost:6379",
			wantTLS:  false,
			wantUser: "u",
			wantPass: "p",
		},
		{
			name:     "explicit credentials override those in the URL",
			conf:     CacheConfig{Endpoint: "rediss://default:fromurl@host:6379", Username: "override", Password: "alsooverride"},
			wantAddr: "host:6379",
			wantTLS:  true,
			wantUser: "override",
			wantPass: "alsooverride",
		},
		{
			name:     "surrounding whitespace is tolerated",
			conf:     CacheConfig{Endpoint: "  rediss://host:6379  "},
			wantAddr: "host:6379",
			wantTLS:  true,
		},
		{
			name:    "malformed URL is reported, not silently downgraded",
			conf:    CacheConfig{Endpoint: "rediss://host:not-a-port"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := buildRedisOptions(&tt.conf)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opts.Addr != tt.wantAddr {
				t.Errorf("Addr = %q, want %q", opts.Addr, tt.wantAddr)
			}
			if gotTLS := opts.TLSConfig != nil; gotTLS != tt.wantTLS {
				t.Errorf("TLS enabled = %v, want %v", gotTLS, tt.wantTLS)
			}
			if tt.wantUser != "" && opts.Username != tt.wantUser {
				t.Errorf("Username = %q, want %q", opts.Username, tt.wantUser)
			}
			if tt.wantPass != "" && opts.Password != tt.wantPass {
				t.Errorf("Password = %q, want %q", opts.Password, tt.wantPass)
			}
		})
	}
}
