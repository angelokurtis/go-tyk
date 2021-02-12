package tyk

// APIsService handles communication with the APIs.
type APIsService struct {
	client *Client
}

// API represents an API.
type API struct {
	ID                         string            `json:"api_id"`
	Name                       string            `json:"name"`
	Slug                       string            `json:"slug"`
	ListenPort                 int               `json:"listen_port"`
	Protocol                   string            `json:"protocol"`
	EnableProxyProtocol        bool              `json:"enable_proxy_protocol"`
	OrgID                      string            `json:"org_id"`
	UseKeyless                 bool              `json:"use_keyless"`
	UseOauth2                  bool              `json:"use_oauth2"`
	UseOpenid                  bool              `json:"use_openid"`
	OpenIDOptions              *OpenIDOptions    `json:"openid_options"`
	OauthMeta                  *OAuthMeta        `json:"oauth_meta"`
	Auth                       *Auth             `json:"auth"`
	AuthConfigs                interface{}       `json:"auth_configs"`
	UseBasicAuth               bool              `json:"use_basic_auth"`
	BasicAuth                  *BasicAuth        `json:"basic_auth"`
	UseMutualTLSAuth           bool              `json:"use_mutual_tls_auth"`
	ClientCertificates         interface{}       `json:"client_certificates"`
	UpstreamCertificates       interface{}       `json:"upstream_certificates"`
	PinnedPublicKeys           interface{}       `json:"pinned_public_keys"`
	EnableJwt                  bool              `json:"enable_jwt"`
	UseStandardAuth            bool              `json:"use_standard_auth"`
	UseGoPluginAuth            bool              `json:"use_go_plugin_auth"`
	EnableCoprocessAuth        bool              `json:"enable_coprocess_auth"`
	JwtSigningMethod           string            `json:"jwt_signing_method"`
	JwtSource                  string            `json:"jwt_source"`
	JwtIdentityBaseField       string            `json:"jwt_identity_base_field"`
	JwtClientBaseField         string            `json:"jwt_client_base_field"`
	JwtPolicyFieldName         string            `json:"jwt_policy_field_name"`
	JwtDefaultPolicies         interface{}       `json:"jwt_default_policies"`
	JwtIssuedAtValidationSkew  int               `json:"jwt_issued_at_validation_skew"`
	JwtExpiresAtValidationSkew int               `json:"jwt_expires_at_validation_skew"`
	JwtNotBeforeValidationSkew int               `json:"jwt_not_before_validation_skew"`
	JwtSkipKid                 bool              `json:"jwt_skip_kid"`
	JwtScopeToPolicyMapping    interface{}       `json:"jwt_scope_to_policy_mapping"`
	JwtScopeClaimName          string            `json:"jwt_scope_claim_name"`
	Notifications              *Notifications    `json:"notifications"`
	EnableSignatureChecking    bool              `json:"enable_signature_checking"`
	HmacAllowedClockSkew       int               `json:"hmac_allowed_clock_skew"`
	HmacAllowedAlgorithms      interface{}       `json:"hmac_allowed_algorithms"`
	RequestSigning             *RequestSigning   `json:"request_signing"`
	BaseIdentityProvidedBy     string            `json:"base_identity_provided_by"`
	Definition                 *Definition       `json:"definition"`
	VersionData                *VersionData      `json:"version_data"`
	UptimeTests                *UptimeTests      `json:"uptime_tests"`
	Proxy                      *Proxy            `json:"proxy"`
	DisableRateLimit           bool              `json:"disable_rate_limit"`
	DisableQuota               bool              `json:"disable_quota"`
	CustomMiddleware           *CustomMiddleware `json:"custom_middleware"`
	CustomMiddlewareBundle     string            `json:"custom_middleware_bundle"`
	CacheOptions               *CacheOptions     `json:"cache_options"`
	SessionLifetime            int               `json:"session_lifetime"`
	Active                     bool              `json:"active"`
	Internal                   bool              `json:"internal"`
	AuthProvider               *AuthProvider     `json:"auth_provider"`
	SessionProvider            *SessionProvider  `json:"session_provider"`
	EventHandlers              *EventHandlers    `json:"event_handlers"`
	EnableBatchRequestSupport  bool              `json:"enable_batch_request_support"`
	EnableIPWhitelisting       bool              `json:"enable_ip_whitelisting"`
	AllowedIps                 interface{}       `json:"allowed_ips"`
	EnableIPBlacklisting       bool              `json:"enable_ip_blacklisting"`
	BlacklistedIps             interface{}       `json:"blacklisted_ips"`
	DontSetQuotaOnCreate       bool              `json:"dont_set_quota_on_create"`
	ExpireAnalyticsAfter       int               `json:"expire_analytics_after"`
	ResponseProcessors         interface{}       `json:"response_processors"`
	CORS                       *CORS             `json:"CORS"`
	Domain                     string            `json:"domain"`
	Certificates               interface{}       `json:"certificates"`
	DoNotTrack                 bool              `json:"do_not_track"`
	Tags                       interface{}       `json:"tags"`
	EnableContextVars          bool              `json:"enable_context_vars"`
	ConfigData                 interface{}       `json:"config_data"`
	TagHeaders                 interface{}       `json:"tag_headers"`
	GlobalRateLimit            *GlobalRateLimit  `json:"global_rate_limit"`
	StripAuthData              bool              `json:"strip_auth_data"`
	EnableDetailedRecording    bool              `json:"enable_detailed_recording"`
	GraphQL                    *GraphQL          `json:"graphql"`
}

// OpenIDOptions represents the OpenID options.
type OpenIDOptions struct {
	Providers         interface{} `json:"providers"`
	SegregateByClient bool        `json:"segregate_by_client"`
}

// OAuth represents the OAuth metadata.
type OAuthMeta struct {
	AllowedAccessTypes    interface{} `json:"allowed_access_types"`
	AllowedAuthorizeTypes interface{} `json:"allowed_authorize_types"`
	AuthLoginRedirect     string      `json:"auth_login_redirect"`
}

// Signature represents an Signature.
type Signature struct {
	Algorithm        string `json:"algorithm"`
	Header           string `json:"header"`
	Secret           string `json:"secret"`
	AllowedClockSkew int    `json:"allowed_clock_skew"`
	ErrorCode        int    `json:"error_code"`
	ErrorMessage     string `json:"error_message"`
}

// Auth represents an auth.
type Auth struct {
	UseParam          bool       `json:"use_param"`
	ParamName         string     `json:"param_name"`
	UseCookie         bool       `json:"use_cookie"`
	CookieName        string     `json:"cookie_name"`
	AuthHeaderName    string     `json:"auth_header_name"`
	UseCertificate    bool       `json:"use_certificate"`
	ValidateSignature bool       `json:"validate_signature"`
	Signature         *Signature `json:"signature"`
}

type BasicAuth struct {
	DisableCaching     bool   `json:"disable_caching"`
	CacheTTL           int    `json:"cache_ttl"`
	ExtractFromBody    bool   `json:"extract_from_body"`
	BodyUserRegexp     string `json:"body_user_regexp"`
	BodyPasswordRegexp string `json:"body_password_regexp"`
}

type Notifications struct {
	SharedSecret        string `json:"shared_secret"`
	OauthOnKeychangeURL string `json:"oauth_on_keychange_url"`
}

type RequestSigning struct {
	IsEnabled       bool        `json:"is_enabled"`
	Secret          string      `json:"secret"`
	KeyID           string      `json:"key_id"`
	Algorithm       string      `json:"algorithm"`
	HeaderList      interface{} `json:"header_list"`
	CertificateID   string      `json:"certificate_id"`
	SignatureHeader string      `json:"signature_header"`
}

type Definition struct {
	Location  string `json:"location"`
	Key       string `json:"key"`
	StripPath bool   `json:"strip_path"`
}

type Paths struct {
	Ignored   interface{} `json:"ignored"`
	WhiteList interface{} `json:"white_list"`
	BlackList interface{} `json:"black_list"`
}

type DefaultVersion struct {
	Name                        string      `json:"name"`
	Expires                     string      `json:"expires"`
	Paths                       *Paths      `json:"paths"`
	UseExtendedPaths            bool        `json:"use_extended_paths"`
	ExtendedPaths               interface{} `json:"extended_paths"`
	GlobalHeaders               interface{} `json:"global_headers"`
	GlobalHeadersRemove         interface{} `json:"global_headers_remove"`
	GlobalResponseHeaders       interface{} `json:"global_response_headers"`
	GlobalResponseHeadersRemove interface{} `json:"global_response_headers_remove"`
	IgnoreEndpointCase          bool        `json:"ignore_endpoint_case"`
	GlobalSizeLimit             int         `json:"global_size_limit"`
	OverrideTarget              string      `json:"override_target"`
}

type Versions struct {
	Default *DefaultVersion `json:"Default"`
}

type VersionData struct {
	NotVersioned   bool      `json:"not_versioned"`
	DefaultVersion string    `json:"default_version"`
	Versions       *Versions `json:"versions"`
}

type ServiceDiscovery struct {
	UseDiscoveryService bool   `json:"use_discovery_service"`
	QueryEndpoint       string `json:"query_endpoint"`
	UseNestedQuery      bool   `json:"use_nested_query"`
	ParentDataPath      string `json:"parent_data_path"`
	DataPath            string `json:"data_path"`
	PortDataPath        string `json:"port_data_path"`
	TargetPath          string `json:"target_path"`
	UseTargetList       bool   `json:"use_target_list"`
	CacheTimeout        int    `json:"cache_timeout"`
	EndpointReturnsList bool   `json:"endpoint_returns_list"`
}

type Config struct {
	ExpireAfter      int               `json:"expire_utime_after"`
	ServiceDiscovery *ServiceDiscovery `json:"service_discovery"`
	RecheckWait      int               `json:"recheck_wait"`
}

type UptimeTests struct {
	CheckList interface{} `json:"check_list"`
	Config    *Config     `json:"config"`
}

type Transport struct {
	SSLInsecureSkipVerify   bool        `json:"ssl_insecure_skip_verify"`
	SSLCiphers              interface{} `json:"ssl_ciphers"`
	SSLMinVersion           int         `json:"ssl_min_version"`
	SSLForceCommonNameCheck bool        `json:"ssl_force_common_name_check"`
	ProxyURL                string      `json:"proxy_url"`
}

type Proxy struct {
	PreserveHostHeader          bool              `json:"preserve_host_header"`
	ListenPath                  string            `json:"listen_path"`
	TargetURL                   string            `json:"target_url"`
	DisableStripSlash           bool              `json:"disable_strip_slash"`
	StripListenPath             bool              `json:"strip_listen_path"`
	EnableLoadBalancing         bool              `json:"enable_load_balancing"`
	TargetList                  interface{}       `json:"target_list"`
	CheckHostAgainstUptimeTests bool              `json:"check_host_against_uptime_tests"`
	ServiceDiscovery            *ServiceDiscovery `json:"service_discovery"`
	Transport                   *Transport        `json:"transport"`
}

type AuthCheck struct {
	Name           string `json:"name"`
	Path           string `json:"path"`
	RequireSession bool   `json:"require_session"`
	RawBodyOnly    bool   `json:"raw_body_only"`
}

type IDExtractor struct {
	ExtractFrom     string      `json:"extract_from"`
	ExtractWith     string      `json:"extract_with"`
	ExtractorConfig interface{} `json:"extractor_config"`
}

type CustomMiddleware struct {
	Pre         interface{}  `json:"pre"`
	Post        interface{}  `json:"post"`
	PostKeyAuth interface{}  `json:"post_key_auth"`
	AuthCheck   *AuthCheck   `json:"auth_check"`
	Response    interface{}  `json:"response"`
	Driver      string       `json:"driver"`
	IDExtractor *IDExtractor `json:"id_extractor"`
}

type CacheOptions struct {
	CacheTimeout               int         `json:"cache_timeout"`
	EnableCache                bool        `json:"enable_cache"`
	CacheAllSafeRequests       bool        `json:"cache_all_safe_requests"`
	CacheResponseCodes         interface{} `json:"cache_response_codes"`
	EnableUpstreamCacheControl bool        `json:"enable_upstream_cache_control"`
	CacheControlTTLHeader      string      `json:"cache_control_ttl_header"`
	CacheByHeaders             interface{} `json:"cache_by_headers"`
}

type AuthProvider struct {
	Name          string      `json:"name"`
	StorageEngine string      `json:"storage_engine"`
	Meta          interface{} `json:"meta"`
}

type SessionProvider struct {
	Name          string      `json:"name"`
	StorageEngine string      `json:"storage_engine"`
	Meta          interface{} `json:"meta"`
}

type EventHandlers struct {
	Events interface{} `json:"events"`
}

type CORS struct {
	Enable             bool        `json:"enable"`
	AllowedOrigins     interface{} `json:"allowed_origins"`
	AllowedMethods     interface{} `json:"allowed_methods"`
	AllowedHeaders     interface{} `json:"allowed_headers"`
	ExposedHeaders     interface{} `json:"exposed_headers"`
	AllowCredentials   bool        `json:"allow_credentials"`
	MaxAge             int         `json:"max_age"`
	OptionsPassthrough bool        `json:"options_passthrough"`
	Debug              bool        `json:"debug"`
}

type GlobalRateLimit struct {
	Rate int `json:"rate"`
	Per  int `json:"per"`
}

type Playground struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

type GraphQL struct {
	Enabled                 bool        `json:"enabled"`
	ExecutionMode           string      `json:"execution_mode"`
	Schema                  string      `json:"schema"`
	TypeFieldConfigurations interface{} `json:"type_field_configurations"`
	Playground              *Playground `json:"playground"`
}

// ListAPIs gets a list of APIs.
func (s *APIsService) ListAPIs() ([]*API, error) {
	var p []*API
	err := s.client.GET("/apis", &p)
	if err != nil {
		return nil, err
	}

	return p, nil
}

type CreateAPIOptions struct {
	ID          string       `json:"api_id"`
	Name        string       `json:"name"`
	Slug        string       `json:"slug"`
	OrgID       string       `json:"org_id"`
	Auth        *Auth        `json:"auth"`
	Definition  *Definition  `json:"definition"`
	VersionData *VersionData `json:"version_data"`
	Proxy       *Proxy       `json:"proxy"`
	Active      bool         `json:"active"`
}

// CreateAPI creates a new API.
func (s *APIsService) CreateAPI(opt *CreateAPIOptions) error {
	err := s.client.POST("/apis", nil, opt)
	if err != nil {
		return err
	}

	return nil
}
