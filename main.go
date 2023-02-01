package main

import (
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/spf13/cobra"
)

var (
	LogLines       []LogLine
	TemplateEngine *template.Template
)

type LogLine struct {
	IP    netip.Addr
	BadIP bool
}

func Hosts(cidr string, numOfBadIps int, numOfClients int) ([]LogLine, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return []LogLine{}, err
	}

	var ips []LogLine
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, LogLine{
			IP: addr,
		})
	}
	rand.Seed(time.Now().UnixNano())
	randInt := rand.Intn(len(ips) - numOfClients)
	ips = ips[randInt : randInt+numOfClients]
	for i := 0; i < numOfBadIps; i++ {
		ips[rand.Intn(len(ips))].BadIP = true
	}

	return ips, nil
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "gologspoof",
		Short: "gologspoof allows you to generate log files",
		Long: `gologspoof allows you to generate log files for various applications.
It is meant to be used within CTF's, games and training`,
		ValidArgs:         []string{"generate", "validate"},
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		SilenceUsage:      true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			flags := cmd.Flags()
			r, err := flags.GetString("range")
			if err != nil {
				return err
			}
			i, err := flags.GetInt("num-of-bad-ips")
			if err != nil {
				return err
			}
			LogLines, err = Hosts(r, i, 30)
			if err != nil {
				return err
			}
			TemplateEngine, err = template.New("base").Funcs(sprig.FuncMap()).ParseGlob("format/*")
			if err != nil {
				return err
			}
			return nil
		},
	}

	rootCmd.PersistentFlags().StringP("range", "r", "192.168.0.1/24", "defines ip range must be CIDR format")
	rootCmd.PersistentFlags().Int("num-of-bad-ips", 1, "defines how many bad IP's reside in range")

	rootCmd.AddCommand(GenerateCmd())
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func GenerateCmd() *cobra.Command {
	generateCmd := &cobra.Command{
		Use:   "generate [application]",
		Short: "generate application logs",
		Long:  "generate will create a log file with the specific [application] type",
		Args:  cobra.MatchAll(cobra.MinimumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := cmd.Flags()
			attackType, err := flags.GetString("attack")
			if err != nil {
				return err
			}
			for _, val := range args {
				f, _ := os.CreateTemp("./tmp", fmt.Sprintf("%s_*.log", val))
				defer f.Close()
				rand.Shuffle(len(LogLines), func(i, j int) { LogLines[i], LogLines[j] = LogLines[j], LogLines[i] })
				TemplateEngine.ExecuteTemplate(f, fmt.Sprintf("%s_%s", val, attackType), LogLines)
			}
			return nil
		},
	}

	flags := generateCmd.Flags()
	flags.StringP("attack", "a", "bruteforce", "defines attack type bruteforce, sqli")

	return generateCmd
}

// func GenerateLogs(t string) ([]string, error) {

// }
