package feishu

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/mojoreviewer/mojoreviewer/internal/github"
)

// CommandKind 是飞书消息能表达的操作。help/status 只在通道内回复，
// 不进入审查 runtime。
type CommandKind string

const (
	KindHelp    CommandKind = "help"
	KindStatus  CommandKind = "status"
	KindEnqueue CommandKind = "enqueue"
)

// Command 是解析后的飞书指令。
type Command struct {
	Kind        CommandKind
	Repo        string
	Number      int
	Intent      github.Intent
	Instruction string
}

var prURLPattern = regexp.MustCompile(`(?i)https?://[^/\s]+/([^/\s]+)/([^/\s]+)/pull/(\d+)`)
var shortPRPattern = regexp.MustCompile(`(?i)^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#(\d+)$`)

// ParseCommand 把一条飞书文本解析成通道命令。
// 空文本、无法识别的文本返回错误，调用方应回复用法而不是入队。
func ParseCommand(text string) (Command, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Command{}, fmt.Errorf("空消息")
	}
	fields := strings.Fields(text)
	head := normalizeWord(fields[0])
	switch head {
	case "help", "帮助", "?", "？":
		return Command{Kind: KindHelp}, nil
	case "status", "状态", "健康":
		return Command{Kind: KindStatus}, nil
	}

	repo, number, rest, err := extractTarget(text)
	if err != nil {
		return Command{}, err
	}
	intent, instruction := github.ParseIntent(rest, "")
	// ParseIntent 在没有命令词时把整段当 review 说明。
	// 飞书里如果首词不是已知命令，且没有 PR 目标，上面已经失败。
	// 这里如果 rest 本身就是 PR 引用，instruction 可能仍含引用，清掉。
	instruction = stripTarget(instruction, repo, number)
	return Command{
		Kind:        KindEnqueue,
		Repo:        repo,
		Number:      number,
		Intent:      intent,
		Instruction: strings.TrimSpace(instruction),
	}, nil
}

func extractTarget(text string) (repo string, number int, rest string, err error) {
	if loc := prURLPattern.FindStringSubmatchIndex(text); loc != nil {
		match := prURLPattern.FindStringSubmatch(text)
		n, convErr := strconv.Atoi(match[3])
		if convErr != nil || n < 1 {
			return "", 0, "", fmt.Errorf("PR 编号无效")
		}
		rest = strings.TrimSpace(text[:loc[0]] + " " + text[loc[1]:])
		return match[1] + "/" + match[2], n, rest, nil
	}

	fields := strings.Fields(text)
	for i, field := range fields {
		clean := strings.Trim(field, "<>()[]【】,，。")
		m := shortPRPattern.FindStringSubmatch(clean)
		if m == nil {
			continue
		}
		n, convErr := strconv.Atoi(m[2])
		if convErr != nil || n < 1 {
			return "", 0, "", fmt.Errorf("PR 编号无效")
		}
		var kept []string
		kept = append(kept, fields[:i]...)
		kept = append(kept, fields[i+1:]...)
		return m[1], n, strings.Join(kept, " "), nil
	}
	return "", 0, "", fmt.Errorf("没有识别到 PR，格式：审查 owner/repo#123")
}

func stripTarget(text, repo string, number int) string {
	needle := fmt.Sprintf("%s#%d", repo, number)
	text = strings.ReplaceAll(text, needle, " ")
	text = prURLPattern.ReplaceAllString(text, " ")
	return strings.Join(strings.Fields(text), " ")
}

func normalizeWord(word string) string {
	word = strings.TrimSpace(word)
	word = strings.Trim(word, ":：,，?/？")
	// 保留中文，英文小写。
	var b strings.Builder
	for _, r := range word {
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// HelpText 是通道内的用法说明，不依赖 runtime。
func HelpText() string {
	return strings.TrimSpace(`
MojoReviewer 飞书通道

审查 owner/repo#123
重审 owner/repo#123 请看错误处理
修复 owner/repo#123 补上空指针判断
记住 owner/repo#123 这个仓库禁用 terminal
https://github.com/owner/repo/pull/123
状态
帮助

审查任务仍由 reviewer 执行，飞书只负责收发和入队。
`)
}
