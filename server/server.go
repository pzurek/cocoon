package server

import (
	"context"
	"crypto/ecdsa"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/events"
	"github.com/bluesky-social/indigo/util"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/domodwyer/mailyak/v3"
	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/go-playground/validator"
	"github.com/gorilla/sessions"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/internal/yubicloud"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/oauth/client"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/dpop"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/haileyok/cocoon/oauth/scopes"
	"github.com/haileyok/cocoon/plc"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo-contrib/echoprometheus"
	echo_session "github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwk"
	slogecho "github.com/samber/slog-echo"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	AccountSessionMaxAge = 30 * 24 * time.Hour // one week
)

type S3Config struct {
	BackupsEnabled   bool
	BlobstoreEnabled bool
	Endpoint         string
	Region           string
	Bucket           string
	AccessKey        string
	SecretKey        string
	CDNUrl           string
}

type Server struct {
	http          *http.Client
	httpd         *http.Server
	mail          *mailyak.MailYak
	mailLk        *sync.Mutex
	echo          *echo.Echo
	db            *db.DB
	plcClient     *plc.Client
	logger        *slog.Logger
	config        *config
	privateKey    *ecdsa.PrivateKey
	publicJwk     jwk.Key
	publicKid     string
	repoman       *RepoMan
	oauthProvider *provider.Provider
	evtman        *events.EventManager
	evtpersister  *DbPersister
	passport      *identity.Passport
	scopeResolver scopes.PermissionSetResolver
	// spaceTypes resolves space type declarations; nil uses scopeResolver.
	spaceTypes    scopes.SpaceTypeResolver
	fallbackProxy string

	// yubiCloud checks YubiKey OTPs with Yubico, so factory keys can be
	// registered by tapping them. Nil when no Yubico API key is configured.
	yubiCloud *yubicloud.Client

	repoWriteLocks     sync.Map      // DID -> *sync.Mutex; shared by writes and imports.
	reservationLimiter *rate.Limiter // guarded by the reserved-keys write lock.

	// Set before accepting requests. Background work and hijacked streams are
	// cancelled at shutdown; ordinary request contexts survive the drain.
	workerCtx context.Context
	// Zero uses five minutes, matching the import request timeout.
	shutdownTimeout time.Duration

	// spaceJobs tracks background Spaces work (notification fan-out).
	spaceJobs sync.WaitGroup
	// spaceWorker resends failed write notifications.
	spaceWorker spaceWorker
	// spaceFetchHTTP fetches client metadata and JWKS for client
	// attestations. Nil uses the SSRF-guarded client.
	spaceFetchHTTP *http.Client
	// spaceHTTP sends space requests to endpoints DID documents name
	// (managing apps, notification recipients, space hosts). Nil uses the
	// SSRF-guarded client.
	spaceHTTP     *http.Client
	spaceHTTPOnce sync.Once

	// Proxy and feed-record requests share an SSRF-guarded client unless overridden.
	proxyHTTPClient     *http.Client
	proxyHTTPClientOnce sync.Once

	lastRequestCrawl time.Time
	requestCrawlMu   sync.Mutex

	// Display names of OAuth clients for the account page.
	clientDisplays    cache.Cache[string, clientDisplay]
	clientDisplayOnce sync.Once

	dbName   string
	dbType   string
	s3Config *S3Config
}

type Args struct {
	Logger *slog.Logger

	LogLevel              slog.Level
	Addr                  string
	DbName                string
	DbType                string
	DatabaseURL           string
	Version               string
	Did                   string
	Hostname              string
	RotationKeyPath       string
	JwkPath               string
	ContactEmail          string
	Relays                []string
	AdminPassword         string
	RequireInvite         bool
	DisableSpaces         bool
	KEMBackfillEnabled    bool
	BlobUploadLimit       int64
	BlobAccountQuotaBytes int64
	BlobServerQuotaBytes  int64
	BackupDir             string

	SmtpUser  string
	SmtpPass  string
	SmtpHost  string
	SmtpPort  string
	SmtpEmail string
	SmtpName  string

	S3Config *S3Config

	SessionSecret    string
	SessionCookieKey string

	BlockstoreVariant BlockstoreVariant
	FallbackProxy     string

	// PlcURL is the PLC directory used for creating, updating, and resolving
	// did:plc identities. Empty defaults to identity.DefaultPlcURL.
	PlcURL string

	// YubicoClientID and YubicoAPIKey (base64) let YubiKeys be checked with
	// Yubico's YubiCloud service, so they can be added by tapping them. Get
	// both from https://upgrade.yubico.com/getapikey/. Leave both empty to
	// only accept YubiKeys programmed with a secret this server stores.
	YubicoClientID string
	YubicoAPIKey   string
}

type config struct {
	LogLevel              slog.Level
	Version               string
	Did                   string
	Hostname              string
	ContactEmail          string
	EnforcePeering        bool
	Relays                []string
	AdminPassword         string
	RequireInvite         bool
	DisableSpaces         bool
	KEMBackfillEnabled    bool
	BlobUploadLimit       int64
	BlobAccountQuotaBytes int64
	BlobServerQuotaBytes  int64
	BackupDir             string
	SmtpEmail             string
	SmtpName              string
	SessionCookieKey      string
	BlockstoreVariant     BlockstoreVariant
	FallbackProxy         string
}

type CustomValidator struct {
	validator *validator.Validate
}

type ValidationError struct {
	error
	Field string
	Tag   string
}

func (cv *CustomValidator) Validate(i any) error {
	if err := cv.validator.Struct(i); err != nil {
		var validateErrors validator.ValidationErrors
		if errors.As(err, &validateErrors) && len(validateErrors) > 0 {
			first := validateErrors[0]
			return ValidationError{
				error: err,
				Field: first.Field(),
				Tag:   first.Tag(),
			}
		}

		return err
	}

	return nil
}

//go:embed templates/*
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

type TemplateRenderer struct {
	templates    *template.Template
	isDev        bool
	templatePath string
	hostname     string
}

var templateFuncs = template.FuncMap{
	// initial is the first letter of a name, for avatar placeholders.
	"initial": func(s string) string {
		s = strings.TrimLeft(s, "@ ")
		for _, r := range s {
			return strings.ToUpper(string(r))
		}
		return "?"
	},
}

func (s *Server) loadTemplates() {
	absPath, _ := filepath.Abs("server/templates/*.html")
	if s.config.Version == "dev" {
		tmpl := template.Must(template.New("").Funcs(templateFuncs).ParseGlob(absPath))
		s.echo.Renderer = &TemplateRenderer{
			templates:    tmpl,
			isDev:        true,
			templatePath: absPath,
			hostname:     s.config.Hostname,
		}
	} else {
		tmpl := template.Must(template.New("").Funcs(templateFuncs).ParseFS(templateFS, "templates/*.html"))
		s.echo.Renderer = &TemplateRenderer{
			templates: tmpl,
			isDev:     false,
			hostname:  s.config.Hostname,
		}
	}
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data any, c echo.Context) error {
	if t.isDev {
		tmpl, err := template.New("").Funcs(templateFuncs).ParseGlob(t.templatePath)
		if err != nil {
			return err
		}
		t.templates = tmpl
	}

	if viewContext, isMap := data.(map[string]any); isMap {
		viewContext["reverse"] = c.Echo().Reverse
		if _, ok := viewContext["Hostname"]; !ok {
			viewContext["Hostname"] = t.hostname
		}
	}

	return t.templates.ExecuteTemplate(w, name, data)
}

type filteredHandler struct {
	level   slog.Level
	handler slog.Handler
}

func (h *filteredHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.level && h.handler.Enabled(ctx, level)
}

func (h *filteredHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.handler.Handle(ctx, r)
}

func (h *filteredHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &filteredHandler{level: h.level, handler: h.handler.WithAttrs(attrs)}
}

func (h *filteredHandler) WithGroup(name string) slog.Handler {
	return &filteredHandler{level: h.level, handler: h.handler.WithGroup(name)}
}

func New(args *Args) (*Server, error) {
	if args.Logger == nil {
		args.Logger = slog.Default()
	}

	if args.LogLevel != 0 {
		args.Logger = slog.New(&filteredHandler{
			level:   args.LogLevel,
			handler: args.Logger.Handler(),
		})
	}

	logger := args.Logger.With("name", "New")

	if args.BlobUploadLimit < 0 {
		return nil, fmt.Errorf("blob upload limit must not be negative")
	}
	if args.BlobUploadLimit == 0 {
		args.BlobUploadLimit = DefaultBlobUploadLimit
	}
	if args.BlobAccountQuotaBytes < 0 || args.BlobServerQuotaBytes < 0 {
		return nil, fmt.Errorf("blob quotas must not be negative")
	}
	if args.BlobAccountQuotaBytes == 0 {
		args.BlobAccountQuotaBytes = DefaultBlobAccountQuotaBytes
	}
	if args.BlobServerQuotaBytes == 0 {
		args.BlobServerQuotaBytes = DefaultBlobServerQuotaBytes
	}

	if args.Addr == "" {
		return nil, fmt.Errorf("addr must be set")
	}

	if args.DbName == "" {
		return nil, fmt.Errorf("db name must be set")
	}

	if args.Did == "" {
		return nil, fmt.Errorf("cocoon did must be set")
	}

	if args.ContactEmail == "" {
		return nil, fmt.Errorf("cocoon contact email is required")
	}

	if _, err := syntax.ParseDID(args.Did); err != nil {
		return nil, fmt.Errorf("error parsing cocoon did: %w", err)
	}

	if args.Hostname == "" {
		return nil, fmt.Errorf("cocoon hostname must be set")
	}

	if args.AdminPassword == "" {
		return nil, fmt.Errorf("admin password must be set")
	}

	if args.SessionSecret == "" {
		panic("SESSION SECRET WAS NOT SET. THIS IS REQUIRED. ")
	}

	plcURL, err := identity.NormalizePlcURL(args.PlcURL)
	if err != nil {
		return nil, err
	}
	if plcURL != identity.DefaultPlcURL {
		logger.Warn("using non-default plc directory", "plc_url", plcURL)
	}

	e := echo.New()

	e.Pre(middleware.RemoveTrailingSlash())
	e.Pre(slogecho.New(args.Logger.With("component", "slogecho")))
	store := sessions.NewCookieStore([]byte(args.SessionSecret))
	// Every decoded session inherits these defaults, including flash-only saves.
	store.Options.HttpOnly = true
	store.Options.SameSite = http.SameSiteLaxMode
	store.Options.Secure = args.Version != "dev"
	e.Use(browserSecurityHeaders)
	e.Use(echo_session.Middleware(store))
	e.Use(echoprometheus.NewMiddleware("cocoon"))
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowHeaders:     []string{"*"},
		AllowMethods:     []string{"*"},
		AllowCredentials: true,
		MaxAge:           100_000_000,
	}))

	vdtor := validator.New()
	vdtor.RegisterValidation("atproto-handle", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseHandle(fl.Field().String()); err != nil {
			return false
		}
		return true
	})
	vdtor.RegisterValidation("atproto-did", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseDID(fl.Field().String()); err != nil {
			return false
		}
		return true
	})
	vdtor.RegisterValidation("atproto-rkey", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseRecordKey(fl.Field().String()); err != nil {
			return false
		}
		return true
	})
	vdtor.RegisterValidation("atproto-nsid", func(fl validator.FieldLevel) bool {
		if _, err := syntax.ParseNSID(fl.Field().String()); err != nil {
			return false
		}
		return true
	})

	e.Validator = &CustomValidator{validator: vdtor}

	httpd := &http.Server{
		Addr:    args.Addr,
		Handler: e,
		// shitty defaults but okay for now, needed for import repo
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  5 * time.Minute,
	}

	dbType := args.DbType
	if dbType == "" {
		dbType = "sqlite"
	}

	var gdb *gorm.DB
	constructed := false
	defer func() {
		// GORM may return a non-nil DB together with an initialization/ping
		// error, so also cover errors from Open itself.
		if !constructed && gdb != nil {
			if sqlDB, err := gdb.DB(); err == nil {
				_ = sqlDB.Close()
			}
		}
	}()
	switch dbType {
	case "postgres":
		if args.DatabaseURL == "" {
			return nil, fmt.Errorf("database-url must be set when using postgres")
		}
		gdb, err = gorm.Open(postgres.Open(args.DatabaseURL), &gorm.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to postgres: %w", err)
		}
		logger.Info("connected to PostgreSQL database")
	default:
		gdb, err = gorm.Open(sqlite.Open(args.DbName), &gorm.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to open sqlite database: %w", err)
		}
		gdb.Exec("PRAGMA journal_mode=WAL")
		gdb.Exec("PRAGMA synchronous=NORMAL")

		logger.Info("connected to SQLite database", "path", args.DbName)
	}
	dbw := db.NewDB(gdb)
	if _, err := gdb.DB(); err != nil {
		return nil, err
	}

	rkbytes, err := os.ReadFile(args.RotationKeyPath)
	if err != nil {
		return nil, err
	}

	h := util.RobustHTTPClient()

	plcClient, err := plc.NewClient(&plc.ClientArgs{
		H:           h,
		Service:     plcURL,
		PdsHostname: args.Hostname,
		RotationKey: rkbytes,
	})
	if err != nil {
		return nil, err
	}

	jwkbytes, err := os.ReadFile(args.JwkPath)
	if err != nil {
		return nil, err
	}

	key, err := helpers.ParseJWKFromBytes(jwkbytes)
	if err != nil {
		return nil, err
	}

	var pkey ecdsa.PrivateKey
	if err := key.Raw(&pkey); err != nil {
		return nil, err
	}

	publicJwk, publicKid, err := derivePublicJWK(&pkey, key.KeyID())
	if err != nil {
		return nil, err
	}

	oauthCli := helpers.NewSafeFetchClient()

	var nonceSecret []byte
	maybeSecret, err := os.ReadFile("nonce.secret")
	if err != nil && !os.IsNotExist(err) {
		logger.Error("error attempting to read nonce secret", "error", err)
	} else {
		nonceSecret = maybeSecret
	}

	evtPersister, err := NewDbPersister(gdb, 72*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("failed to create event persister: %w", err)
	}
	defer func() {
		if !constructed {
			_ = evtPersister.Shutdown(context.Background())
		}
	}()

	s := &Server{
		http:       h,
		httpd:      httpd,
		echo:       e,
		logger:     args.Logger,
		db:         dbw,
		plcClient:  plcClient,
		privateKey: &pkey,
		publicJwk:  publicJwk,
		publicKid:  publicKid,
		config: &config{
			LogLevel:              args.LogLevel,
			Version:               args.Version,
			Did:                   args.Did,
			Hostname:              args.Hostname,
			ContactEmail:          args.ContactEmail,
			EnforcePeering:        false,
			Relays:                args.Relays,
			AdminPassword:         args.AdminPassword,
			RequireInvite:         args.RequireInvite,
			DisableSpaces:         args.DisableSpaces,
			KEMBackfillEnabled:    args.KEMBackfillEnabled,
			BlobUploadLimit:       args.BlobUploadLimit,
			BlobAccountQuotaBytes: args.BlobAccountQuotaBytes,
			BlobServerQuotaBytes:  args.BlobServerQuotaBytes,
			BackupDir:             args.BackupDir,
			SmtpName:              args.SmtpName,
			SmtpEmail:             args.SmtpEmail,
			SessionCookieKey:      args.SessionCookieKey,
			BlockstoreVariant:     args.BlockstoreVariant,
			FallbackProxy:         args.FallbackProxy,
		},
		evtman:        events.NewEventManager(evtPersister),
		evtpersister:  evtPersister,
		passport:      identity.NewPassport(nil, identity.NewMemCache(10_000), identity.WithPlcURL(plcURL)),
		scopeResolver: scopes.NewIndigoResolverWithPLCURL(plcURL),

		dbName:   args.DbName,
		dbType:   dbType,
		s3Config: args.S3Config,

		oauthProvider: provider.NewProvider(provider.Args{
			Hostname: args.Hostname,
			ClientManagerArgs: client.ManagerArgs{
				Cli:    oauthCli,
				Logger: args.Logger.With("component", "oauth-client-manager"),
			},
			DpopManagerArgs: dpop.ManagerArgs{
				NonceSecret:           nonceSecret,
				NonceRotationInterval: constants.NonceMaxRotationInterval / 3,
				OnNonceSecretCreated: func(newNonce []byte) {
					if err := os.WriteFile("nonce.secret", newNonce, 0644); err != nil {
						logger.Error("error writing new nonce secret", "error", err)
					}
				},
				Logger:   args.Logger.With("component", "dpop-manager"),
				Hostname: args.Hostname,
			},
		}),
	}

	s.loadTemplates()

	s.repoman = NewRepoMan(s) // TODO: this is way too lazy, stop it
	s.scopeResolver.(*scopes.IndigoResolver).SetLocalLexiconReader(s.readLocalLexicon)

	// TODO: should validate these args
	if args.SmtpUser == "" || args.SmtpPass == "" || args.SmtpHost == "" || args.SmtpPort == "" || args.SmtpEmail == "" || args.SmtpName == "" {
		args.Logger.Warn("not enough smtp args were provided. mailing will not work for your server.")
	} else {
		mail := mailyak.New(args.SmtpHost+":"+args.SmtpPort, smtp.PlainAuth("", args.SmtpUser, args.SmtpPass, args.SmtpHost))
		mail.From(s.config.SmtpEmail)
		mail.FromName(s.config.SmtpName)

		s.mail = mail
		s.mailLk = &sync.Mutex{}
	}

	yc, err := newYubiCloudFromConfig(args.YubicoClientID, args.YubicoAPIKey)
	if err != nil {
		return nil, err
	}
	s.yubiCloud = yc
	if yc == nil {
		args.Logger.Info("no yubico api key configured; yubikeys must be programmed with a secret to be added")
	}

	constructed = true
	return s, nil
}

func (s *Server) addRoutes() {
	// static
	if s.config.Version == "dev" {
		s.echo.Static("/static", "server/static")
	} else {
		s.echo.GET("/static/*", echo.WrapHandler(http.FileServer(http.FS(staticFS))))
	}

	// random stuff
	s.echo.GET("/", s.handleRoot)
	s.echo.GET("/xrpc/_health", s.handleHealth)
	s.echo.GET("/.well-known/did.json", s.handleWellKnown)
	s.echo.GET("/.well-known/atproto-did", s.handleAtprotoDid)
	s.echo.GET("/.well-known/oauth-protected-resource", s.handleOauthProtectedResource)
	s.echo.GET("/.well-known/oauth-authorization-server", s.handleOauthAuthorizationServer)
	s.echo.GET("/robots.txt", s.handleRobots)

	// public
	s.echo.GET("/xrpc/com.atproto.identity.resolveHandle", s.handleResolveHandle)
	s.echo.POST("/xrpc/com.atproto.server.createAccount", s.handleCreateAccount)
	s.echo.POST("/xrpc/com.atproto.server.createSession", s.handleCreateSession)
	s.echo.GET("/xrpc/com.atproto.server.describeServer", s.handleDescribeServer)
	s.echo.POST("/xrpc/com.atproto.server.reserveSigningKey", s.handleServerReserveSigningKey)

	s.echo.GET("/xrpc/com.atproto.repo.describeRepo", s.handleDescribeRepo, s.handleRepoReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.sync.listRepos", s.handleListRepos)
	s.echo.GET("/xrpc/com.atproto.repo.listRecords", s.handleListRecords, s.handleRepoReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.repo.getRecord", s.handleRepoGetRecord, s.handleRepoReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.sync.getRecord", s.handleSyncGetRecord, s.handleRepoReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.sync.getBlocks", s.handleGetBlocks, s.handleRepoReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.sync.getLatestCommit", s.handleSyncGetLatestCommit, s.handleRepoReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.sync.getRepoStatus", s.handleSyncGetRepoStatus)
	s.echo.GET("/xrpc/com.atproto.sync.getRepo", s.handleSyncGetRepo, s.handleRepoReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.sync.subscribeRepos", s.handleSyncSubscribeRepos)
	s.echo.GET("/xrpc/com.atproto.sync.listBlobs", s.handleSyncListBlobs, s.handleRepoReadMiddleware)
	s.echo.GET("/xrpc/com.atproto.sync.getBlob", s.handleSyncGetBlob, s.handleRepoReadMiddleware)

	// labels
	s.echo.GET("/xrpc/com.atproto.label.queryLabels", s.handleLabelQueryLabels)

	// account
	s.echo.GET("/account", s.handleAccount)
	s.echo.POST("/account/revoke", s.handleAccountRevoke)
	s.echo.POST("/account/switch", s.handleAccountSwitchPost)
	s.echo.GET("/account/signin", s.handleAccountSigninGet)
	s.echo.POST("/account/signin", s.handleAccountSigninPost)
	s.echo.GET("/account/signin/verify", s.handleAccountSigninVerifyGet)
	s.echo.POST("/account/signin/verify", s.handleAccountSigninVerifyPost)
	s.echo.GET("/account/signout", s.handleAccountSignout)
	s.echo.GET("/account/2fa", s.handleAccountTwoFactor)
	s.echo.GET("/account/2fa/totp", s.handleAccountTwoFactorTOTPGet)
	s.echo.POST("/account/2fa/totp", s.handleAccountTwoFactorTOTPPost)
	s.echo.GET("/account/2fa/yubikey", s.handleAccountTwoFactorYubiKeyGet)
	s.echo.POST("/account/2fa/yubikey", s.handleAccountTwoFactorYubiKeyPost)
	s.echo.POST("/account/2fa/email-code", s.handleAccountTwoFactorEmailCode)
	s.echo.POST("/account/2fa/remove", s.handleAccountTwoFactorRemove)
	s.echo.POST("/account/2fa/backup-codes", s.handleAccountTwoFactorBackupCodes)

	// oauth account
	s.echo.GET("/oauth/jwks", s.handleOauthJwks)
	s.echo.GET("/oauth/authorize", s.handleOauthAuthorizeGet)
	s.echo.POST("/oauth/authorize", s.handleOauthAuthorizePost)

	// oauth authorization
	s.echo.POST("/oauth/par", s.handleOauthPar, s.oauthProvider.BaseMiddleware)
	s.echo.POST("/oauth/token", s.handleOauthToken, s.oauthProvider.BaseMiddleware)
	s.echo.POST("/oauth/revoke", s.handleOauthRevoke, s.oauthProvider.BaseMiddleware)

	// authed
	s.echo.GET("/xrpc/com.atproto.server.getSession", s.handleGetSession, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.refreshSession", s.handleRefreshSession, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.deleteSession", s.handleDeleteSession, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.GET("/xrpc/com.atproto.identity.getRecommendedDidCredentials", s.handleGetRecommendedDidCredentials, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.identity.updateHandle", s.handleIdentityUpdateHandle, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.identity.requestPlcOperationSignature", s.handleIdentityRequestPlcOperationSignature, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.identity.signPlcOperation", s.handleSignPlcOperation, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.identity.submitPlcOperation", s.handleSubmitPlcOperation, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.confirmEmail", s.handleServerConfirmEmail, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.requestEmailConfirmation", s.handleServerRequestEmailConfirmation, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.requestPasswordReset", s.handleServerRequestPasswordReset) // AUTH NOT REQUIRED FOR THIS ONE
	s.echo.POST("/xrpc/com.atproto.server.requestEmailUpdate", s.handleServerRequestEmailUpdate, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.resetPassword", s.handleServerResetPassword)
	s.echo.POST("/xrpc/com.atproto.server.updateEmail", s.handleServerUpdateEmail, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.GET("/xrpc/com.atproto.server.getServiceAuth", s.handleServerGetServiceAuth, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.GET("/xrpc/com.atproto.server.checkAccountStatus", s.handleServerCheckAccountStatus, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.deactivateAccount", s.handleServerDeactivateAccount, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.activateAccount", s.handleServerActivateAccount, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.requestAccountDelete", s.handleServerRequestAccountDelete, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.deleteAccount", s.handleServerDeleteAccount)

	// repo
	s.echo.GET("/xrpc/com.atproto.repo.listMissingBlobs", s.handleListMissingBlobs, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.repo.createRecord", s.handleCreateRecord, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.repo.putRecord", s.handlePutRecord, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.repo.deleteRecord", s.handleDeleteRecord, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.repo.applyWrites", s.handleApplyWrites, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.repo.uploadBlob", s.handleRepoUploadBlob, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/com.atproto.repo.importRepo", s.handleRepoImportRepo, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)

	// stupid silly endpoints
	s.echo.GET("/xrpc/app.bsky.actor.getPreferences", s.handleActorGetPreferences, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/app.bsky.actor.putPreferences", s.handleActorPutPreferences, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.GET("/xrpc/app.bsky.feed.getFeed", s.handleProxyBskyFeedGetFeed, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.GET("/xrpc/app.bsky.ageassurance.getState", s.handleAgeAssurance, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	// admin routes
	s.echo.POST("/xrpc/com.atproto.server.createInviteCode", s.handleCreateInviteCode, s.handleAdminMiddleware)
	s.echo.POST("/xrpc/com.atproto.server.createInviteCodes", s.handleCreateInviteCodes, s.handleAdminMiddleware)
	s.echo.GET("/xrpc/com.atproto.admin.getSubjectStatus", s.handleAdminGetSubjectStatus, s.handleAdminMiddleware)
	s.echo.POST("/xrpc/com.atproto.admin.updateSubjectStatus", s.handleAdminUpdateSubjectStatus, s.handleAdminMiddleware)

	s.addSpaceRoutes()

	// are there any routes that we should be allowing without auth? i dont think so but idk
	s.echo.GET("/xrpc/*", s.handleProxy, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
	s.echo.POST("/xrpc/*", s.handleProxy, s.handleLegacySessionMiddleware, s.handleOauthSessionMiddleware)
}

// Migrate runs the database migrations Serve applies at startup, so offline
// commands (like create-agent) operate on an up-to-date schema. The space
// tables are migrated even if the main migration fails, as Serve always has.
func (s *Server) Migrate() error {
	var errs []error
	if err := s.db.AutoMigrate(
		&models.Actor{},
		&models.Repo{},
		&models.InviteCode{},
		&models.Token{},
		&models.RefreshToken{},
		&models.Block{},
		&models.Record{},
		&models.PublicBlobRef{},
		&models.PublicBlobIndex{},
		&models.Blob{},
		&models.BlobPart{},
		&models.BlobCharge{},
		&models.BlobQuotaState{},
		&models.ReservedKey{},
		&models.TwoFactorCredential{},
		&models.TwoFactorBackupCode{},
		&provider.OauthToken{},
		&provider.OauthUsedRefreshToken{},
		&provider.OauthAuthorizationRequest{},
	); err != nil {
		errs = append(errs, fmt.Errorf("migration failed: %w", err))
	}
	if err := initBlobQuota(s.db.Client()); err != nil {
		errs = append(errs, fmt.Errorf("blob quota migration failed: %w", err))
	}
	if err := migrateSpaceTables(s.db.Client(), s.logger); err != nil {
		errs = append(errs, fmt.Errorf("space table migration failed; spaces will not work: %w", err))
	}
	return errors.Join(errs...)
}

func (s *Server) Serve(ctx context.Context) error {
	logger := s.logger.With("name", "Serve")
	fail := func(err error) error {
		return errors.Join(err, s.closeResources())
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	logger.Info("migrating...")
	if err := s.Migrate(); err != nil {
		return fail(fmt.Errorf("startup migrations: %w", err))
	}
	// Bind synchronously: a bind failure must be returned to the caller, not
	// panic in an unobserved goroutine or start background jobs.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.httpd.Addr)
	if err != nil {
		return fail(fmt.Errorf("listen: %w", err))
	}
	defer ln.Close()
	s.addRoutes()
	workerCtx, cancelWorkers := context.WithCancel(context.Background())
	s.workerCtx = workerCtx
	defer cancelWorkers()
	requestCtx, cancelRequests := context.WithCancel(context.Background())
	defer cancelRequests()

	// net/http does not wait for hijacked connections, and Close does not wait
	// for handlers either. Count every accepted handler, with an admission gate
	// so no Add can race the shutdown Wait (including late keep-alive requests).
	var handlers sync.WaitGroup
	var admission sync.Mutex
	stopping := false
	handler := s.httpd.Handler
	s.httpd.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admission.Lock()
		if stopping {
			admission.Unlock()
			http.Error(w, "server shutting down", http.StatusServiceUnavailable)
			return
		}
		handlers.Add(1)
		admission.Unlock()
		defer handlers.Done()
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(requestCtx, cancel)
		defer stop()
		defer cancel()
		handler.ServeHTTP(w, r.WithContext(ctx))
	})

	logger.Info("starting cocoon")
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.httpd.Serve(ln) }()
	var workers sync.WaitGroup
	start := func(fn func(context.Context)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			fn(s.workerCtx)
		}()
	}
	start(s.backupRoutine)
	s.startSpaceWorkers()
	start(s.kemKeyBackfillRoutine)
	start(s.oauthTokenCleanupRoutine)
	start(func(ctx context.Context) {
		if err := s.requestCrawl(ctx); err != nil && ctx.Err() == nil {
			logger.Error("error requesting crawls", "err", err)
		}
	})

	var result error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		// Even ErrServerClosed is unexpected unless our shutdown initiated it.
		result = fmt.Errorf("HTTP server stopped unexpectedly: %w", err)
	}
	admission.Lock()
	stopping = true
	admission.Unlock()
	cancelWorkers()
	if s.spaceWorker.cancel != nil {
		s.spaceWorker.cancel()
	}

	timeout := s.shutdownTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), timeout)
	defer cancelDrain()
	// Cleanup continues even if a handler ignores forced cancellation. Never
	// close its database underneath it. Serve still returns a bounded, explicit
	// failure so a supervisor can terminate an uncooperative process.
	drained := make(chan error, 1)
	go func() {
		err := s.httpd.Shutdown(drainCtx)
		handlers.Wait()
		workers.Wait()
		s.stopSpaceWorkers()
		drained <- errors.Join(err, s.closeResources())
	}()
	select {
	case err := <-drained:
		return errors.Join(result, err)
	case <-drainCtx.Done():
		result = errors.Join(result, fmt.Errorf("graceful shutdown deadline exceeded: %w", drainCtx.Err()))
		cancelRequests()
		result = errors.Join(result, s.httpd.Close())
	}
	// Allow cancelled handlers/SQL calls to unwind, but do not hang forever on
	// code that ignores context cancellation.
	forceTimer := time.NewTimer(5 * time.Second)
	defer forceTimer.Stop()
	select {
	case err := <-drained:
		return errors.Join(result, err)
	case <-forceTimer.C:
		return errors.Join(result, errors.New("forced shutdown incomplete; database cleanup deferred until handlers and workers exit"))
	}
}

// Called only after all DB users have exited, or before startup accepts work.
func (s *Server) closeResources() error {
	if s.evtpersister != nil {
		if err := s.evtpersister.Shutdown(context.Background()); err != nil {
			return err
		}
	}
	sqlDB, err := s.db.Client().DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (s *Server) requestCrawl(ctx context.Context) error {
	logger := s.logger.With("component", "request-crawl")
	s.requestCrawlMu.Lock()
	defer s.requestCrawlMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	logger.Info("requesting crawl with configured relays")

	if time.Since(s.lastRequestCrawl) <= 1*time.Minute {
		return fmt.Errorf("a crawl request has already been made within the last minute")
	}

	for _, relay := range s.config.Relays {
		logger := logger.With("relay", relay)
		logger.Info("requesting crawl from relay")
		cli := xrpc.Client{Host: relay}
		if err := atproto.SyncRequestCrawl(ctx, &cli, &atproto.SyncRequestCrawl_Input{
			Hostname: s.config.Hostname,
		}); err != nil {
			logger.Error("error requesting crawl", "err", err)
		} else {
			logger.Info("crawl requested successfully")
		}
	}

	s.lastRequestCrawl = time.Now()

	return nil
}

func (s *Server) doBackup(ctx context.Context) {
	logger := s.logger.With("name", "doBackup")

	if ctx.Err() != nil {
		return
	}
	if s.dbType == "postgres" {
		logger.Info("skipping S3 backup - PostgreSQL backups should be handled externally (pg_dump, managed database backups, etc.)")
		return
	}

	start := time.Now()

	logger.Info("beginning database backup")
	dir := s.config.BackupDir
	// Create an unpredictable, owner-only empty file; VACUUM INTO accepts it.
	// The operator provisions the directory; creating it here without syncing
	// every new ancestor would not make the first backup crash-durable.
	// Local snapshots use the destination filesystem for atomic publication.
	tmp, err := os.CreateTemp(dir, ".cocoon-backup-*.tmp")
	if err != nil {
		logger.Error("error creating backup file", "err", err)
		return
	}
	tmpFile := tmp.Name()
	defer os.Remove(tmpFile)
	if err := tmp.Close(); err != nil {
		logger.Error("error closing empty backup file", "err", err)
		return
	}

	if err := s.db.Client().WithContext(ctx).Exec("VACUUM INTO ?", tmpFile).Error; err != nil {
		logger.Error("error creating tmp backup file", "err", err)
		return
	}

	file, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		logger.Error("error opening backup file", "err", err)
		return
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		logger.Error("error syncing backup file", "err", err)
		return
	}
	if ctx.Err() != nil {
		return
	}
	currTime := time.Now().UTC().Format("2006-01-02_15-04-05.000000000")
	key := "cocoon-backup-" + currTime + ".db"
	if dir != "" {
		if err := os.Rename(tmpFile, filepath.Join(dir, key)); err != nil {
			logger.Error("error publishing local backup", "err", err)
			return
		}
		parent, err := os.Open(dir)
		if err != nil {
			logger.Error("error opening backup directory", "err", err)
			return
		}
		err = parent.Sync()
		_ = parent.Close()
		if err != nil {
			logger.Error("error syncing backup directory", "err", err)
			return
		}
	}
	if s.s3Config != nil && s.s3Config.BackupsEnabled {
		svc, err := s.s3Client()
		if err != nil {
			logger.Error("error creating s3 session", "err", err)
			return
		}
		// *os.File is rewindable for SDK retries, without buffering the snapshot.
		if _, err := svc.PutObjectWithContext(ctx, &s3.PutObjectInput{
			Bucket: aws.String(s.s3Config.Bucket), Key: aws.String(key), Body: file,
		}); err != nil {
			logger.Error("error uploading backup to s3; any local snapshot is retained", "err", err)
			return
		}
	}
	logger.Info("finished database backup", "key", key, "duration", time.Since(start).Seconds())
	if err := os.WriteFile(filepath.Join(dir, "last-backup.txt"), []byte(time.Now().UTC().Format(time.RFC3339Nano)), 0600); err != nil {
		logger.Error("error recording backup completion", "err", err)
	}
}

func (s *Server) backupRoutine(ctx context.Context) {
	logger := s.logger.With("name", "backupRoutine")

	s3Enabled := s.s3Config != nil && s.s3Config.BackupsEnabled
	if s.config.BackupDir == "" && !s3Enabled {
		return
	}
	if s.dbType == "postgres" {
		logger.Warn("built-in snapshots are SQLite-only; configure external PostgreSQL backups")
		return
	}
	if s3Enabled && (s.s3Config.Region == "" || s.s3Config.Bucket == "" || s.s3Config.AccessKey == "" || s.s3Config.SecretKey == "") {
		logger.Warn("incomplete S3 backup configuration; backups will not run")
		return
	}

	shouldBackupNow := false
	lastBackupStr, err := os.ReadFile(filepath.Join(s.config.BackupDir, "last-backup.txt"))
	if err != nil {
		shouldBackupNow = true
	} else {
		lastBackup, err := time.Parse(time.RFC3339Nano, string(lastBackupStr))
		if err != nil {
			shouldBackupNow = true
		} else if time.Since(lastBackup).Seconds() > 3600 {
			shouldBackupNow = true
		}
	}

	if shouldBackupNow {
		s.doBackup(ctx)
	}

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.doBackup(ctx)
		}
	}
}

func (s *Server) UpdateRepo(ctx context.Context, did string, root cid.Cid, rev string) error {
	if err := s.db.Exec(ctx, "UPDATE repos SET root = ?, rev = ? WHERE did = ?", nil, root.Bytes(), rev, did).Error; err != nil {
		return err
	}

	return nil
}
