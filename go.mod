module "https://gitea.icts.kuleuven.be/hpc/hpc-firewall"

go 1.12

require (
	gitea.icts.kuleuven.be/ceif-lnx/go/webapp v0.0.0-20200427102449-ebc8e5ee9a1d
	github.com/GeertJohan/go.rice v1.0.0
	github.com/gorilla/securecookie v1.1.1
	github.com/hashicorp/consul/api v1.4.0
	github.com/labstack/echo v3.3.10+incompatible // indirect
	github.com/labstack/echo/v4 v4.1.15
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/spf13/cobra v1.0.0
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
)
