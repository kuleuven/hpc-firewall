package framework

import (
	"html/template"
	"io"
	"log"
	"os"

	rice "github.com/GeertJohan/go.rice"
	"github.com/Masterminds/sprig"
	"github.com/hashicorp/go-hclog"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"gitea.icts.kuleuven.be/ceif-lnx/go/webapp/framework/templice"
)

const (
	defaultTemplatesDir = "templates"
	defaultGlob         = defaultTemplatesDir + "/" + "*.html"
	csrfTokenLength     = 32
	csrfCookieMaxAge    = 86400
)

// Echo contains the embedded echo configuration and echo client
type Echo struct {
	*Config
	Echo *echo.Echo
}

// Config contains the configuration
type Config struct {
	Insecure      bool                    // If enabled the CSRF and Secure middleware will be disabled. Useful for testing/debugging
	LoggerConfig  middleware.LoggerConfig // The Logger middleware configuration
	CSRFConfig    middleware.CSRFConfig   // The CSRF middleware configuration
	SecureConfig  middleware.SecureConfig // The Secure middleware configuration
	ShowPort      bool                    // If enabled will print out the listening port on startup
	TemplatesGlob string                  // Globbing pattern to use for the templates, if not specified "templates/*.html" will be used
	TemplatesBox  *rice.Box               // A ricebox containing embedded templates
	Logger        hclog.Logger            // The hclog logger interface
	Renderer      echo.Renderer           // A echo Renderer interface
}

// New returns a new Echo client.
// This function can do a fatal if the specified TemplatesGlob isn't valid.
// It will call the Recover, Logger and Gzip middleware by default.
// The secure and CSRF middleware can be disabled by using the Insecure parameter.
func New(cfg *Config) *echo.Echo {
	e := echo.New()

	cfg.Logger = cfg.Logger.Named("framework")

	if cfg.TemplatesGlob == "" {
		cfg.TemplatesGlob = defaultGlob
	}

	var err error

	if cfg.TemplatesBox == nil && cfg.Renderer == nil {
		_, err = template.New("base").ParseGlob(cfg.TemplatesGlob) //nolint:errcheck
		if err != nil {
			if _, inerr := os.Stat(defaultTemplatesDir); !os.IsNotExist(inerr) {
				cfg.Logger.Error("using templates", "error", err)
			}
		}
	}

	if err == nil && cfg.Renderer == nil {
		// do we have embedded templates
		if cfg.TemplatesBox != nil {
			tplice := templice.New(cfg.TemplatesBox)

			tplice.SetPrep(func(templ *template.Template) *template.Template {
				return templ.Funcs(sprig.FuncMap())
			})

			err := tplice.Load()
			if err != nil {
				log.Fatalf("embedded templates failed: %s", err)
			}

			t := &tpl{
				rtemplates: tplice,
			}
			cfg.Renderer = t

			cfg.Logger.Debug("using box templates", "glob", cfg.TemplatesGlob)
		} else {
			t := &tpl{
				templates: template.Must(template.New("base").Funcs(sprig.FuncMap()).ParseGlob(cfg.TemplatesGlob)),
			}
			cfg.Renderer = t

			cfg.Logger.Debug("using templates", "glob", cfg.TemplatesGlob)
		}
	} else if cfg.TemplatesGlob != defaultGlob && cfg.Renderer == nil {
		log.Fatal("incorrect TemplatesGlob", cfg.TemplatesGlob)
	}

	e.Renderer = cfg.Renderer
	e.HideBanner = true
	e.HidePort = !cfg.ShowPort
	e.Use(middleware.Recover())
	e.Use(middleware.LoggerWithConfig(cfg.LoggerConfig))
	e.Use(middleware.Gzip())

	if cfg.CSRFConfig.TokenLookup == "" {
		cfg.CSRFConfig = middleware.CSRFConfig{
			TokenLength:  csrfTokenLength,
			TokenLookup:  "form:csrf",
			ContextKey:   "csrf",
			CookieName:   "_csrf",
			CookieMaxAge: csrfCookieMaxAge,
		}
	}

	if !cfg.Insecure {
		e.Use(middleware.SecureWithConfig(cfg.SecureConfig))
		e.Use(middleware.CSRFWithConfig(cfg.CSRFConfig))
	}

	return e
}

type tpl struct {
	templates  *template.Template
	rtemplates *templice.Template
}

func (t *tpl) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	if t.rtemplates != nil {
		return t.rtemplates.ExecuteTemplate(w, name, data)
	}

	return t.templates.ExecuteTemplate(w, name, data)
}
