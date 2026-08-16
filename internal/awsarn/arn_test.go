package awsarn

import "testing"

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{
			name: "iam role passes through",
			in:   "arn:aws:iam::123456789012:role/S3Access",
			want: "arn:aws:iam::123456789012:role/S3Access",
		},
		{
			name: "iam user passes through",
			in:   "arn:aws:iam::123456789012:user/Bob",
			want: "arn:aws:iam::123456789012:user/Bob",
		},
		{
			name: "account root passes through",
			in:   "arn:aws:iam::123456789012:root",
			want: "arn:aws:iam::123456789012:root",
		},
		{
			// The case that matters most: kubectl callers almost always arrive as
			// an assumed-role session, but access entries are written against the
			// role. Without this collapse every mapping misses.
			name: "assumed role collapses to the underlying role",
			in:   "arn:aws:sts::123456789012:assumed-role/Accounting-Role/Mary",
			want: "arn:aws:iam::123456789012:role/Accounting-Role",
		},
		{
			name: "assumed role preserves an embedded role path",
			in:   "arn:aws:sts::123456789012:assumed-role/some/deep/path/Admin/session-name",
			want: "arn:aws:iam::123456789012:role/some/deep/path/Admin",
		},
		{
			name: "federated user passes through",
			in:   "arn:aws:sts::123456789012:federated-user/Bob",
			want: "arn:aws:sts::123456789012:federated-user/Bob",
		},
		{
			name: "non-default partition is preserved",
			in:   "arn:aws-us-gov:sts::123456789012:assumed-role/Admin/session",
			want: "arn:aws-us-gov:iam::123456789012:role/Admin",
		},
		{
			name:    "assumed role without a session is rejected",
			in:      "arn:aws:sts::123456789012:assumed-role/Admin",
			wantErr: true,
		},
		{
			name:    "unknown sts resource is rejected",
			in:      "arn:aws:sts::123456789012:something-else/Bob",
			wantErr: true,
		},
		{
			name:    "unknown iam resource is rejected",
			in:      "arn:aws:iam::123456789012:group/Admins",
			wantErr: true,
		},
		{
			// A non-principal ARN must not be silently accepted: treating an S3
			// bucket as a cluster principal would be a genuine security bug.
			name:    "non-IAM service is rejected",
			in:      "arn:aws:s3:::my-bucket",
			wantErr: true,
		},
		{
			name:    "garbage is rejected",
			in:      "not-an-arn",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Canonicalize(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Canonicalize(%q) returned unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Canonicalize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSessionName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"arn:aws:sts::123456789012:assumed-role/Accounting-Role/Mary", "Mary"},
		{"arn:aws:sts::123456789012:assumed-role/path/Role/i-0abc123", "i-0abc123"},
		{"arn:aws:iam::123456789012:role/S3Access", ""},
		{"arn:aws:iam::123456789012:user/Bob", ""},
		{"nonsense", ""},
	}
	for _, tt := range tests {
		if got := SessionName(tt.in); got != tt.want {
			t.Errorf("SessionName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestStripPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"arn:aws:iam::123456789012:role/some/path/Admin", "arn:aws:iam::123456789012:role/Admin"},
		{"arn:aws:iam::123456789012:role/Admin", "arn:aws:iam::123456789012:role/Admin"},
		{"arn:aws:iam::123456789012:root", "arn:aws:iam::123456789012:root"},
		{"not-an-arn", "not-an-arn"},
	}
	for _, tt := range tests {
		if got := StripPath(tt.in); got != tt.want {
			t.Errorf("StripPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseRoundTrip(t *testing.T) {
	const in = "arn:aws:sts::123456789012:assumed-role/Role/session"
	parsed, err := Parse(in)
	if err != nil {
		t.Fatalf("Parse returned unexpected error: %v", err)
	}
	if parsed.Service != "sts" {
		t.Errorf("Service = %q, want sts", parsed.Service)
	}
	if parsed.AccountID != "123456789012" {
		t.Errorf("AccountID = %q, want 123456789012", parsed.AccountID)
	}
	// The resource keeps its slashes, so re-rendering must reproduce the input.
	if got := parsed.String(); got != in {
		t.Errorf("String() = %q, want %q", got, in)
	}
}
