package feishu

import (
	"testing"

	"github.com/mojoreviewer/mojoreviewer/internal/github"
)

func TestParseCommand(t *testing.T) {
	cases := []struct {
		in          string
		kind        CommandKind
		repo        string
		number      int
		intent      github.Intent
		instruction string
	}{
		{"帮助", KindHelp, "", 0, "", ""},
		{"状态", KindStatus, "", 0, "", ""},
		{"审查 fullac/MojoReviewer#23", KindEnqueue, "fullac/MojoReviewer", 23, github.IntentReview, ""},
		{"重审 yurika0211/lucky-agent#286 看下错误处理", KindEnqueue, "yurika0211/lucky-agent", 286, github.IntentReview, "看下错误处理"},
		{"修复 owner/repo#9 补上空指针", KindEnqueue, "owner/repo", 9, github.IntentFix, "补上空指针"},
		{"记住 owner/repo#9 禁用 terminal", KindEnqueue, "owner/repo", 9, github.IntentRemember, "禁用 terminal"},
		{"https://github.com/fullac/MojoReviewer/pull/20", KindEnqueue, "fullac/MojoReviewer", 20, github.IntentReview, ""},
		{"看看 https://github.com/acme/app/pull/4 只看鉴权", KindEnqueue, "acme/app", 4, github.IntentReview, "只看鉴权"},
	}
	for _, tc := range cases {
		got, err := ParseCommand(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if got.Kind != tc.kind || got.Repo != tc.repo || got.Number != tc.number || got.Intent != tc.intent || got.Instruction != tc.instruction {
			t.Fatalf("%q: got %+v", tc.in, got)
		}
	}
}

func TestParseCommandRejectsUnknown(t *testing.T) {
	for _, in := range []string{"", "你好", "审查一下", "owner/repo"} {
		if _, err := ParseCommand(in); err == nil {
			t.Fatalf("%q 应被拒绝", in)
		}
	}
}
