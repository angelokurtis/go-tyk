package tyk

import "fmt"

// APIsService handles communication with the APIs.
type APIsService struct {
	client *Client
}

// API represents an API.
type API struct {
	ID                         string           `json:"api_id,omitempty"`
	Name                       string           `json:"name,omitempty"`
	Slug                       string           `json:"slug,omitempty"`
	ListenPort                 int              `json:"listen_port,omitempty"`
	Protocol                   string           `json:"protocol,omitempty"`
	EnableProxyProtocol        bool             `json:"enable_proxy_protocol,omitempty"`
	OrgID                      string           `json:"org_id,omitempty"`
	UseKeyless                 bool             `json:"use_keyless,omitempty"`
	UseOauth2                  bool             `json:"use_oauth2,omitempty"`
	UseOpenid                  bool             `json:"use_openid,omitempty"`
	OpenIDOptions              OpenIDOptions    `json:"openid_options,omitempty"`
	OauthMeta                  OAuthMeta        `json:"oauth_meta,omitempty"`
	Auth                       Auth             `json:"auth,omitempty"`
	AuthConfigs                interface{}      `json:"auth_configs,omitempty"`
	UseBasicAuth               bool             `json:"use_basic_auth,omitempty"`
	BasicAuth                  BasicAuth        `json:"basic_auth,omitempty"`
	UseMutualTLSAuth           bool             `json:"use_mutual_tls_auth,omitempty"`
	ClientCertificates         interface{}      `json:"client_certificates,omitempty"`
	UpstreamCertificates       interface{}      `json:"upstream_certificates,omitempty"`
	PinnedPublicKeys           interface{}      `json:"pinned_public_keys,omitempty"`
	EnableJwt                  bool             `json:"enable_jwt,omitempty"`
	UseStandardAuth            bool             `json:"use_standard_auth,omitempty"`
	UseGoPluginAuth            bool             `json:"use_go_plugin_auth,omitempty"`
	EnableCoprocessAuth        bool             `json:"enable_coprocess_auth,omitempty"`
	JwtSigningMethod           string           `json:"jwt_signing_method,omitempty"`
	JwtSource                  string           `json:"jwt_source,omitempty"`
	JwtIdentityBaseField       string           `json:"jwt_identity_base_field,omitempty"`
	JwtClientBaseField         string           `json:"jwt_client_base_field,omitempty"`
	JwtPolicyFieldName         string           `json:"jwt_policy_field_name,omitempty"`
	JwtDefaultPolicies         interface{}      `json:"jwt_default_policies,omitempty"`
	JwtIssuedAtValidationSkew  int              `json:"jwt_issued_at_validation_skew,omitempty"`
	JwtExpiresAtValidationSkew int              `json:"jwt_expires_at_validation_skew,omitempty"`
	JwtNotBeforeValidationSkew int              `json:"jwt_not_before_validation_skew,omitempty"`
	JwtSkipKid                 bool             `json:"jwt_skip_kid,omitempty"`
	JwtScopeToPolicyMapping    interface{}      `json:"jwt_scope_to_policy_mapping,omitempty"`
	JwtScopeClaimName          string           `json:"jwt_scope_claim_name,omitempty"`
	Notifications              Notifications    `json:"notifications,omitempty"`
	EnableSignatureChecking    bool             `json:"enable_signature_checking,omitempty"`
	HmacAllowedClockSkew       int              `json:"hmac_allowed_clock_skew,omitempty"`
	HmacAllowedAlgorithms      interface{}      `json:"hmac_allowed_algorithms,omitempty"`
	RequestSigning             RequestSigning   `json:"request_signing,omitempty"`
	BaseIdentityProvidedBy     string           `json:"base_identity_provided_by,omitempty"`
	Definition                 Definition       `json:"definition,omitempty"`
	VersionData                VersionData      `json:"version_data,omitempty"`
	UptimeTests                UptimeTests      `json:"uptime_tests,omitempty"`
	Proxy                      Proxy            `json:"proxy,omitempty"`
	DisableRateLimit           bool             `json:"disable_rate_limit,omitempty"`
	DisableQuota               bool             `json:"disable_quota,omitempty"`
	CustomMiddleware           CustomMiddleware `json:"custom_middleware,omitempty"`
	CustomMiddlewareBundle     string           `json:"custom_middleware_bundle,omitempty"`
	CacheOptions               CacheOptions     `json:"cache_options,omitempty"`
	SessionLifetime            int              `json:"session_lifetime,omitempty"`
	Active                     bool             `json:"active,omitempty"`
	Internal                   bool             `json:"internal,omitempty"`
	AuthProvider               AuthProvider     `json:"auth_provider,omitempty"`
	SessionProvider            SessionProvider  `json:"session_provider,omitempty"`
	EventHandlers              EventHandlers    `json:"event_handlers,omitempty"`
	EnableBatchRequestSupport  bool             `json:"enable_batch_request_support,omitempty"`
	EnableIPWhitelisting       bool             `json:"enable_ip_whitelisting,omitempty"`
	AllowedIps                 interface{}      `json:"allowed_ips,omitempty"`
	EnableIPBlacklisting       bool             `json:"enable_ip_blacklisting,omitempty"`
	BlacklistedIps             interface{}      `json:"blacklisted_ips,omitempty"`
	DontSetQuotaOnCreate       bool             `json:"dont_set_quota_on_create,omitempty"`
	ExpireAnalyticsAfter       int              `json:"expire_analytics_after,omitempty"`
	ResponseProcessors         interface{}      `json:"response_processors,omitempty"`
	CORS                       CORS             `json:"CORS,omitempty"`
	Domain                     string           `json:"domain,omitempty"`
	Certificates               interface{}      `json:"certificates,omitempty"`
	DoNotTrack                 bool             `json:"do_not_track,omitempty"`
	Tags                       interface{}      `json:"tags,omitempty"`
	EnableContextVars          bool             `json:"enable_context_vars,omitempty"`
	ConfigData                 interface{}      `json:"config_data,omitempty"`
	TagHeaders                 interface{}      `json:"tag_headers,omitempty"`
	GlobalRateLimit            GlobalRateLimit  `json:"global_rate_limit,omitempty"`
	StripAuthData              bool             `json:"strip_auth_data,omitempty"`
	EnableDetailedRecording    bool             `json:"enable_detailed_recording,omitempty"`
	GraphQL                    GraphQL          `json:"graphql,omitempty"`
}

// OpenIDOptions represents the OpenID options.
type OpenIDOptions struct {
	Providers         interface{} `json:"providers,omitempty"`
	SegregateByClient bool        `json:"segregate_by_client,omitempty"`
}

// OAuth represents the OAuth metadata.
type OAuthMeta struct {
	AllowedAccessTypes    interface{} `json:"allowed_access_types,omitempty"`
	AllowedAuthorizeTypes interface{} `json:"allowed_authorize_types,omitempty"`
	AuthLoginRedirect     string      `json:"auth_login_redirect,omitempty"`
}

// Signature represents an Signature.
type Signature struct {
	Algorithm        string `json:"algorithm,omitempty"`
	Header           string `json:"header,omitempty"`
	Secret           string `json:"secret,omitempty"`
	AllowedClockSkew int    `json:"allowed_clock_skew,omitempty"`
	ErrorCode        int    `json:"error_code,omitempty"`
	ErrorMessage     string `json:"error_message,omitempty"`
}

// Auth represents an auth.
type Auth struct {
	UseParam          bool      `json:"use_param,omitempty"`
	ParamName         string    `json:"param_name,omitempty"`
	UseCookie         bool      `json:"use_cookie,omitempty"`
	CookieName        string    `json:"cookie_name,omitempty"`
	AuthHeaderName    string    `json:"auth_header_name,omitempty"`
	UseCertificate    bool      `json:"use_certificate,omitempty"`
	ValidateSignature bool      `json:"validate_signature,omitempty"`
	Signature         Signature `json:"signature,omitempty"`
}

type BasicAuth struct {
	DisableCaching     bool   `json:"disable_caching,omitempty"`
	CacheTTL           int    `json:"cache_ttl,omitempty"`
	ExtractFromBody    bool   `json:"extract_from_body,omitempty"`
	BodyUserRegexp     string `json:"body_user_regexp,omitempty"`
	BodyPasswordRegexp string `json:"body_password_regexp,omitempty"`
}

type Notifications struct {
	SharedSecret        string `json:"shared_secret,omitempty"`
	OauthOnKeychangeURL string `json:"oauth_on_keychange_url,omitempty"`
}

type RequestSigning struct {
	IsEnabled       bool        `json:"is_enabled,omitempty"`
	Secret          string      `json:"secret,omitempty"`
	KeyID           string      `json:"key_id,omitempty"`
	Algorithm       string      `json:"algorithm,omitempty"`
	HeaderList      interface{} `json:"header_list,omitempty"`
	CertificateID   string      `json:"certificate_id,omitempty"`
	SignatureHeader string      `json:"signature_header,omitempty"`
}

type Definition struct {
	Location  string `json:"location,omitempty"`
	Key       string `json:"key,omitempty"`
	StripPath bool   `json:"strip_path,omitempty"`
}

type Paths struct {
	Ignored   interface{} `json:"ignored,omitempty"`
	WhiteList interface{} `json:"white_list,omitempty"`
	BlackList interface{} `json:"black_list,omitempty"`
}

type DefaultVersion struct {
	Name                        string      `json:"name,omitempty"`
	Expires                     string      `json:"expires,omitempty"`
	Paths                       Paths       `json:"paths,omitempty"`
	UseExtendedPaths            bool        `json:"use_extended_paths,omitempty"`
	ExtendedPaths               interface{} `json:"extended_paths,omitempty"`
	GlobalHeaders               interface{} `json:"global_headers,omitempty"`
	GlobalHeadersRemove         interface{} `json:"global_headers_remove,omitempty"`
	GlobalResponseHeaders       interface{} `json:"global_response_headers,omitempty"`
	GlobalResponseHeadersRemove interface{} `json:"global_response_headers_remove,omitempty"`
	IgnoreEndpointCase          bool        `json:"ignore_endpoint_case,omitempty"`
	GlobalSizeLimit             int         `json:"global_size_limit,omitempty"`
	OverrideTarget              string      `json:"override_target,omitempty"`
}

type Versions struct {
	Default DefaultVersion `json:"Default,omitempty"`
}

type VersionData struct {
	NotVersioned   bool     `json:"not_versioned,omitempty"`
	DefaultVersion string   `json:"default_version,omitempty"`
	Versions       Versions `json:"versions,omitempty"`
}

type ServiceDiscovery struct {
	UseDiscoveryService bool   `json:"use_discovery_service,omitempty"`
	QueryEndpoint       string `json:"query_endpoint,omitempty"`
	UseNestedQuery      bool   `json:"use_nested_query,omitempty"`
	ParentDataPath      string `json:"parent_data_path,omitempty"`
	DataPath            string `json:"data_path,omitempty"`
	PortDataPath        string `json:"port_data_path,omitempty"`
	TargetPath          string `json:"target_path,omitempty"`
	UseTargetList       bool   `json:"use_target_list,omitempty"`
	CacheTimeout        int    `json:"cache_timeout,omitempty"`
	EndpointReturnsList bool   `json:"endpoint_returns_list,omitempty"`
}

type Config struct {
	ExpireAfter      int              `json:"expire_utime_after,omitempty"`
	ServiceDiscovery ServiceDiscovery `json:"service_discovery,omitempty"`
	RecheckWait      int              `json:"recheck_wait,omitempty"`
}

type UptimeTests struct {
	CheckList interface{} `json:"check_list,omitempty"`
	Config    Config      `json:"config,omitempty"`
}

type Transport struct {
	SSLInsecureSkipVerify   bool        `json:"ssl_insecure_skip_verify,omitempty"`
	SSLCiphers              interface{} `json:"ssl_ciphers,omitempty"`
	SSLMinVersion           int         `json:"ssl_min_version,omitempty"`
	SSLForceCommonNameCheck bool        `json:"ssl_force_common_name_check,omitempty"`
	ProxyURL                string      `json:"proxy_url,omitempty"`
}

type Proxy struct {
	PreserveHostHeader          bool             `json:"preserve_host_header,omitempty"`
	ListenPath                  string           `json:"listen_path,omitempty"`
	TargetURL                   string           `json:"target_url,omitempty"`
	DisableStripSlash           bool             `json:"disable_strip_slash,omitempty"`
	StripListenPath             bool             `json:"strip_listen_path,omitempty"`
	EnableLoadBalancing         bool             `json:"enable_load_balancing,omitempty"`
	TargetList                  interface{}      `json:"target_list,omitempty"`
	CheckHostAgainstUptimeTests bool             `json:"check_host_against_uptime_tests,omitempty"`
	ServiceDiscovery            ServiceDiscovery `json:"service_discovery,omitempty"`
	Transport                   Transport        `json:"transport,omitempty"`
}

type AuthCheck struct {
	Name           string `json:"name,omitempty"`
	Path           string `json:"path,omitempty"`
	RequireSession bool   `json:"require_session,omitempty"`
	RawBodyOnly    bool   `json:"raw_body_only,omitempty"`
}

type IDExtractor struct {
	ExtractFrom     string      `json:"extract_from,omitempty"`
	ExtractWith     string      `json:"extract_with,omitempty"`
	ExtractorConfig interface{} `json:"extractor_config,omitempty"`
}

type CustomMiddleware struct {
	Pre         interface{} `json:"pre,omitempty"`
	Post        interface{} `json:"post,omitempty"`
	PostKeyAuth interface{} `json:"post_key_auth,omitempty"`
	AuthCheck   AuthCheck   `json:"auth_check,omitempty"`
	Response    interface{} `json:"response,omitempty"`
	Driver      string      `json:"driver,omitempty"`
	IDExtractor IDExtractor `json:"id_extractor,omitempty"`
}

type CacheOptions struct {
	CacheTimeout               int         `json:"cache_timeout,omitempty"`
	EnableCache                bool        `json:"enable_cache,omitempty"`
	CacheAllSafeRequests       bool        `json:"cache_all_safe_requests,omitempty"`
	CacheResponseCodes         interface{} `json:"cache_response_codes,omitempty"`
	EnableUpstreamCacheControl bool        `json:"enable_upstream_cache_control,omitempty"`
	CacheControlTTLHeader      string      `json:"cache_control_ttl_header,omitempty"`
	CacheByHeaders             interface{} `json:"cache_by_headers,omitempty"`
}

type AuthProvider struct {
	Name          string      `json:"name,omitempty"`
	StorageEngine string      `json:"storage_engine,omitempty"`
	Meta          interface{} `json:"meta,omitempty"`
}

type SessionProvider struct {
	Name          string      `json:"name,omitempty"`
	StorageEngine string      `json:"storage_engine,omitempty"`
	Meta          interface{} `json:"meta,omitempty"`
}

type EventHandlers struct {
	Events interface{} `json:"events,omitempty"`
}

type CORS struct {
	Enable             bool        `json:"enable,omitempty"`
	AllowedOrigins     interface{} `json:"allowed_origins,omitempty"`
	AllowedMethods     interface{} `json:"allowed_methods,omitempty"`
	AllowedHeaders     interface{} `json:"allowed_headers,omitempty"`
	ExposedHeaders     interface{} `json:"exposed_headers,omitempty"`
	AllowCredentials   bool        `json:"allow_credentials,omitempty"`
	MaxAge             int         `json:"max_age,omitempty"`
	OptionsPassthrough bool        `json:"options_passthrough,omitempty"`
	Debug              bool        `json:"debug,omitempty"`
}

type GlobalRateLimit struct {
	Rate int `json:"rate,omitempty"`
	Per  int `json:"per,omitempty"`
}

type Playground struct {
	Enabled bool   `json:"enabled,omitempty"`
	Path    string `json:"path,omitempty"`
}

type GraphQL struct {
	Enabled                 bool        `json:"enabled,omitempty"`
	ExecutionMode           string      `json:"execution_mode,omitempty"`
	Schema                  string      `json:"schema,omitempty"`
	TypeFieldConfigurations interface{} `json:"type_field_configurations,omitempty"`
	Playground              Playground  `json:"playground,omitempty"`
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

// GetAPI gets a specific API, identified by ID.
func (s *APIsService) GetAPI(id string) (*API, error) {
	u := fmt.Sprintf("/apis/%s", id)

	p := new(API)
	err := s.client.GET(u, p)
	if err != nil {
		return nil, err
	}

	return p, nil
}

type CreateAPIOptions struct {
	ID                         string           `json:"api_id,omitempty"`
	Active                     bool             `json:"active,omitempty"`
	AllowedIps                 interface{}      `json:"allowed_ips,omitempty"`
	Auth                       Auth             `json:"auth,omitempty"`
	AuthConfigs                interface{}      `json:"auth_configs,omitempty"`
	AuthProvider               AuthProvider     `json:"auth_provider,omitempty"`
	BaseIdentityProvidedBy     string           `json:"base_identity_provided_by,omitempty"`
	BasicAuth                  BasicAuth        `json:"basic_auth,omitempty"`
	BlacklistedIps             interface{}      `json:"blacklisted_ips,omitempty"`
	CacheOptions               CacheOptions     `json:"cache_options,omitempty"`
	Certificates               interface{}      `json:"certificates,omitempty"`
	ClientCertificates         interface{}      `json:"client_certificates,omitempty"`
	ConfigData                 interface{}      `json:"config_data,omitempty"`
	CORS                       CORS             `json:"CORS,omitempty"`
	CustomMiddleware           CustomMiddleware `json:"custom_middleware,omitempty"`
	CustomMiddlewareBundle     string           `json:"custom_middleware_bundle,omitempty"`
	Definition                 Definition       `json:"definition,omitempty"`
	DisableQuota               bool             `json:"disable_quota,omitempty"`
	DisableRateLimit           bool             `json:"disable_rate_limit,omitempty"`
	DoNotTrack                 bool             `json:"do_not_track,omitempty"`
	Domain                     string           `json:"domain,omitempty"`
	DontSetQuotaOnCreate       bool             `json:"dont_set_quota_on_create,omitempty"`
	EnableBatchRequestSupport  bool             `json:"enable_batch_request_support,omitempty"`
	EnableContextVars          bool             `json:"enable_context_vars,omitempty"`
	EnableCoprocessAuth        bool             `json:"enable_coprocess_auth,omitempty"`
	EnableDetailedRecording    bool             `json:"enable_detailed_recording,omitempty"`
	EnableIPBlacklisting       bool             `json:"enable_ip_blacklisting,omitempty"`
	EnableIPWhitelisting       bool             `json:"enable_ip_whitelisting,omitempty"`
	EnableJwt                  bool             `json:"enable_jwt,omitempty"`
	EnableProxyProtocol        bool             `json:"enable_proxy_protocol,omitempty"`
	EnableSignatureChecking    bool             `json:"enable_signature_checking,omitempty"`
	EventHandlers              EventHandlers    `json:"event_handlers,omitempty"`
	ExpireAnalyticsAfter       int              `json:"expire_analytics_after,omitempty"`
	GlobalRateLimit            GlobalRateLimit  `json:"global_rate_limit,omitempty"`
	Graphql                    GraphQL          `json:"graphql,omitempty"`
	HmacAllowedAlgorithms      interface{}      `json:"hmac_allowed_algorithms,omitempty"`
	HmacAllowedClockSkew       int              `json:"hmac_allowed_clock_skew,omitempty"`
	Internal                   bool             `json:"internal,omitempty"`
	JwtClientBaseField         string           `json:"jwt_client_base_field,omitempty"`
	JwtDefaultPolicies         interface{}      `json:"jwt_default_policies,omitempty"`
	JwtExpiresAtValidationSkew int              `json:"jwt_expires_at_validation_skew,omitempty"`
	JwtIdentityBaseField       string           `json:"jwt_identity_base_field,omitempty"`
	JwtIssuedAtValidationSkew  int              `json:"jwt_issued_at_validation_skew,omitempty"`
	JwtNotBeforeValidationSkew int              `json:"jwt_not_before_validation_skew,omitempty"`
	JwtPolicyFieldName         string           `json:"jwt_policy_field_name,omitempty"`
	JwtScopeClaimName          string           `json:"jwt_scope_claim_name,omitempty"`
	JwtScopeToPolicyMapping    interface{}      `json:"jwt_scope_to_policy_mapping,omitempty"`
	JwtSigningMethod           string           `json:"jwt_signing_method,omitempty"`
	JwtSkipKid                 bool             `json:"jwt_skip_kid,omitempty"`
	JwtSource                  string           `json:"jwt_source,omitempty"`
	ListenPort                 int              `json:"listen_port,omitempty"`
	Name                       string           `json:"name,omitempty"`
	Notifications              Notifications    `json:"notifications,omitempty"`
	OauthMeta                  OAuthMeta        `json:"oauth_meta,omitempty"`
	OpenidOptions              OpenIDOptions    `json:"openid_options,omitempty"`
	OrgID                      string           `json:"org_id,omitempty"`
	PinnedPublicKeys           interface{}      `json:"pinned_public_keys,omitempty"`
	Protocol                   string           `json:"protocol,omitempty"`
	Proxy                      Proxy            `json:"proxy,omitempty"`
	RequestSigning             RequestSigning   `json:"request_signing,omitempty"`
	ResponseProcessors         interface{}      `json:"response_processors,omitempty"`
	SessionLifetime            int              `json:"session_lifetime,omitempty"`
	SessionProvider            SessionProvider  `json:"session_provider,omitempty"`
	Slug                       string           `json:"slug,omitempty"`
	StripAuthData              bool             `json:"strip_auth_data,omitempty"`
	TagHeaders                 interface{}      `json:"tag_headers,omitempty"`
	Tags                       interface{}      `json:"tags,omitempty"`
	UpstreamCertificates       interface{}      `json:"upstream_certificates,omitempty"`
	UptimeTests                UptimeTests      `json:"uptime_tests,omitempty"`
	UseBasicAuth               bool             `json:"use_basic_auth,omitempty"`
	UseGoPluginAuth            bool             `json:"use_go_plugin_auth,omitempty"`
	UseKeyless                 bool             `json:"use_keyless,omitempty"`
	UseMutualTLSAuth           bool             `json:"use_mutual_tls_auth,omitempty"`
	UseOauth2                  bool             `json:"use_oauth2,omitempty"`
	UseOpenid                  bool             `json:"use_openid,omitempty"`
	UseStandardAuth            bool             `json:"use_standard_auth,omitempty"`
	VersionData                VersionData      `json:"version_data,omitempty"`
}

// CreateAPI creates a new API.
func (s *APIsService) CreateAPI(opt *CreateAPIOptions) error {
	err := s.client.POST("/apis", nil, opt)
	if err != nil {
		return err
	}

	return nil
}

// DeleteAPI removes an API including all associated resources.
func (s *APIsService) DeleteAPI(id string) error {
	u := fmt.Sprintf("/apis/%s", id)
	return s.client.DELETE(u, nil)
}
