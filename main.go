package main

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	config := FirewallConfig{}

	rootCmd := &cobra.Command{
		Use:   "hpc-firewall",
		Short: "HPC firewall runs a web server to add client ips to consul",
		Long: `HPC firewall is a web server with oauth for client authentication,
		  which stores client ips of authenticated users in a consul kv store.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			// Do Stuff Here
			f, err := NewFirewall(config)
			if err != nil {
				log.Fatal(err)
			}

			err = f.LogAdminPass()
			if err != nil {
				log.Fatal(err)
			}

			err = f.Run()
			if err != nil {
				log.Fatal(err)
			}
		},
	}

	rootCmd.Flags().StringVar(&config.OauthClientID, "oauth-client-id", os.Getenv("OAUTH_CLIENT_ID"), "Oauth Client ID")
	rootCmd.Flags().StringVar(&config.OauthClientSecret, "oauth-client-secret", os.Getenv("OAUTH_CLIENT_SECRET"), "Oauth Client secret")
	rootCmd.Flags().StringVar(&config.ConsulURL, "consul-addr", "", "Consul address")
	rootCmd.Flags().StringVar(&config.ConsulToken, "consul-token", "", "Consul token")
	rootCmd.Flags().StringVarP(&config.ConsulPath, "consul-path", "p", os.Getenv("CONSUL_PATH"), "Consul path")
	rootCmd.Flags().StringVar(&config.HashKey, "hash-key", os.Getenv("HASH_KEY"), "Hash key for securecookie. Should be at least 32 bytes long")
	rootCmd.Flags().StringVar(&config.BlockKey, "block-key", os.Getenv("BLOCK_KEY"), "Block key for securecookie. Should be 16 (AES-128) or 32 bytes (AES-256) long")
	rootCmd.Flags().StringVarP(&config.Domain, "domain", "d", os.Getenv("DOMAIN"), "Domain to host the website")
	rootCmd.Flags().StringSliceVar(&config.Endpoints, "endpoints", nil, "Endpoints for ip detection")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
