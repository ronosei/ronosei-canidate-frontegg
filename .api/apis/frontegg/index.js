"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var oas_1 = __importDefault(require("oas"));
var core_1 = __importDefault(require("api/dist/core"));
var openapi_json_1 = __importDefault(require("./openapi.json"));
var SDK = /** @class */ (function () {
    function SDK() {
        this.spec = oas_1.default.init(openapi_json_1.default);
        this.core = new core_1.default(this.spec, 'frontegg/1.0 (api/6.1.1)');
    }
    /**
     * Optionally configure various options that the SDK allows.
     *
     * @param config Object of supported SDK options and toggles.
     * @param config.timeout Override the default `fetch` request timeout of 30 seconds. This number
     * should be represented in milliseconds.
     */
    SDK.prototype.config = function (config) {
        this.core.setConfig(config);
    };
    /**
     * If the API you're using requires authentication you can supply the required credentials
     * through this method and the library will magically determine how they should be used
     * within your API request.
     *
     * With the exception of OpenID and MutualTLS, it supports all forms of authentication
     * supported by the OpenAPI specification.
     *
     * @example <caption>HTTP Basic auth</caption>
     * sdk.auth('username', 'password');
     *
     * @example <caption>Bearer tokens (HTTP or OAuth 2)</caption>
     * sdk.auth('myBearerToken');
     *
     * @example <caption>API Keys</caption>
     * sdk.auth('myApiKey');
     *
     * @see {@link https://spec.openapis.org/oas/v3.0.3#fixed-fields-22}
     * @see {@link https://spec.openapis.org/oas/v3.1.0#fixed-fields-22}
     * @param values Your auth credentials for the API; can specify up to two strings or numbers.
     */
    SDK.prototype.auth = function () {
        var _a;
        var values = [];
        for (var _i = 0; _i < arguments.length; _i++) {
            values[_i] = arguments[_i];
        }
        (_a = this.core).setAuth.apply(_a, values);
        return this;
    };
    /**
     * If the API you're using offers alternate server URLs, and server variables, you can tell
     * the SDK which one to use with this method. To use it you can supply either one of the
     * server URLs that are contained within the OpenAPI definition (along with any server
     * variables), or you can pass it a fully qualified URL to use (that may or may not exist
     * within the OpenAPI definition).
     *
     * @example <caption>Server URL with server variables</caption>
     * sdk.server('https://{region}.api.example.com/{basePath}', {
     *   name: 'eu',
     *   basePath: 'v14',
     * });
     *
     * @example <caption>Fully qualified server URL</caption>
     * sdk.server('https://eu.api.example.com/v14');
     *
     * @param url Server URL
     * @param variables An object of variables to replace into the server URL.
     */
    SDK.prototype.server = function (url, variables) {
        if (variables === void 0) { variables = {}; }
        this.core.setServer(url, variables);
    };
    /**
     * This route gets users for an application.
     *
     * @summary Get users for application
     */
    SDK.prototype.applicationsControllerV1_getUsersForApplication = function (metadata) {
        return this.core.fetch('/resources/applications/v1/{appId}/users', 'get', metadata);
    };
    /**
     * This route gets applications for a user.
     *
     * @summary Get applications for user
     */
    SDK.prototype.applicationsControllerV1_getApplicationsForUser = function (metadata) {
        return this.core.fetch('/resources/applications/v1/{userId}/apps', 'get', metadata);
    };
    /**
     * This route gets applications for multiple users.
     *
     * @summary Get applications for multiple users
     */
    SDK.prototype.applicationsControllerV1_getApplicationsForMultipleUsers = function (metadata) {
        return this.core.fetch('/resources/applications/v1/users-apps', 'get', metadata);
    };
    /**
     * This route gets users for multiple applications.
     *
     * @summary Get users for multiple applications
     */
    SDK.prototype.applicationsControllerV1_getUsersForMultipleApplications = function (metadata) {
        return this.core.fetch('/resources/applications/v1/apps-users', 'get', metadata);
    };
    /**
     * This route assigns users to an application.
     *
     * @summary Assign users to application
     */
    SDK.prototype.applicationsControllerV1_assignUsersToApplication = function (body) {
        return this.core.fetch('/resources/applications/v1', 'post', body);
    };
    /**
     * This route unassigns users from an application.
     *
     * @summary Unassign users from application
     */
    SDK.prototype.applicationsControllerV1_unassignUsersFromApplication = function (body) {
        return this.core.fetch('/resources/applications/v1', 'delete', body);
    };
    /**
     * This route assigns user to multiple applications.
     *
     * @summary Assign user to multiple applications
     */
    SDK.prototype.applicationsControllerV1_assignUserToMultipleApplications = function (body) {
        return this.core.fetch('/resources/applications/v1/apps-user', 'post', body);
    };
    /**
     * This route unassigns user from multiple applications.
     *
     * @summary Unassign user from multiple applications
     */
    SDK.prototype.applicationsControllerV1_unassignUserFromMultipleApplications = function (body) {
        return this.core.fetch('/resources/applications/v1/user-apps', 'delete', body);
    };
    /**
     * This route gets the active user tenants for an application.
     *
     * @summary Get user active tenants in applications
     */
    SDK.prototype.applicationsActiveUserTenantsControllerV1_getUserApplicationActiveTenants = function (metadata) {
        return this.core.fetch('/resources/applications/user-tenants/active/v1', 'get', metadata);
    };
    /**
     * This route updates the active user tenants for an application.
     *
     * @summary Switch users active tenant in applications
     */
    SDK.prototype.applicationsActiveUserTenantsControllerV1_switchUserApplicationActiveTenant = function (body, metadata) {
        return this.core.fetch('/resources/applications/user-tenants/active/v1', 'put', body, metadata);
    };
    /**
     * This route authenticates a tenant’s or user’s API token. The clientId and secret key are
     * in Admin Portal ➜ API Tokens. Send these values as params in the POST body and
     * authenticate to your Frontegg domain by replacing api.frontegg.com with your Frontegg
     * domain.</br>**NOTE**: This route enforces(by default) a rotation mechanism for refresh
     * tokens associated with the API token. It limits each token to a maximum of 100 refresh
     * tokens simultaneously. When a client authenticates using the same API token for the
     * 101th time, the earliest refresh token is automatically invalidated.
     *
     * @summary Authenticate using API token
     */
    SDK.prototype.authenticationApiTokenControllerV2_authApiToken = function (body) {
        return this.core.fetch('/resources/auth/v2/api-token', 'post', body);
    };
    /**
     * This route refreshes a JWT using the refresh token value. If the refresh token is valid,
     * the route returns a new JWT and refresh token. Send the **`frontegg-vendor-host`** as a
     * header to declare which vendor. This is your domain name in the Frontegg Portal ➜
     * Workspace Settings ➜ Domains ➜ Domain Name.
     *
     * @summary Refresh API token
     */
    SDK.prototype.authenticationApiTokenControllerV2_refreshToken = function (body) {
        return this.core.fetch('/resources/auth/v2/api-token/token/refresh', 'post', body);
    };
    /**
     * This route authenticates a local user using email and password. Send the
     * **`frontegg-vendor-host`** as a header to declare which vendor. This is your domain name
     * in the Frontegg Portal ➜ Workspace Settings ➜ Domains ➜ Domain Name. Optionally, send
     * login information for the user as POST body params. Include the invitation token if the
     * user is signing up by invitation. Send the recaptcha token if the recaptcha is enabled
     * for login.
     *
     * @summary Authenticate user with password
     */
    SDK.prototype.authenticatioAuthenticationControllerV1_authenticateLocalUser = function (body, metadata) {
        return this.core.fetch('/resources/auth/v1/user', 'post', body, metadata);
    };
    /**
     * This route refreshes a JWT based on the refresh token expiration time. If the refresh
     * token is valid, the route returns a new JWT and refresh token. Please note that the
     * route expects the refresh cookie of the logged in user as well. Send the
     * **`frontegg-vendor-host`** as a header to declare which vendor. This is your domain name
     * in the Frontegg Portal ➜ Workspace Settings ➜ Domains ➜ Domain Name. Configure your JWT
     * settings in the Frontegg Portal.
     *
     * @summary Refresh user JWT token
     */
    SDK.prototype.authenticatioAuthenticationControllerV1_refreshToken = function (body, metadata) {
        return this.core.fetch('/resources/auth/v1/user/token/refresh', 'post', body, metadata);
    };
    /**
     * This route logs out a user using the refresh token that is passed as a cookie. Send the
     * **`frontegg-vendor-host`** as a header to declare which vendor. This route is designed
     * for Frontegg embedded login or integrations that use only Frontegg APIs
     *
     * @summary Logout user
     */
    SDK.prototype.authenticatioAuthenticationControllerV1_logout = function (metadata) {
        return this.core.fetch('/resources/auth/v1/logout', 'post', metadata);
    };
    /**
     * This route recovers MFA for a non logged-in user. Send the user’s email and a recovery
     * code as params in the POST body. The recovery code comes from the MFA authenticator app
     * when you set up MFA.
     *
     * @summary Recover MFA
     */
    SDK.prototype.authenticationMFAControllerV1_recoverMfa = function (body) {
        return this.core.fetch('/resources/auth/v1/user/mfa/recover', 'post', body);
    };
    /**
     * This route disables MFA enrollment for a logged-in user for a specific tenant. Send the
     * **`frontegg-user-id`** header to declare which user. The MFA token should be obtained
     * from the authenticator app. A vendor token is required for this route, it can be
     * obtained from the vendor authentication route.
     *
     * @summary Disable authenticator app MFA
     */
    SDK.prototype.usersMfaControllerV1_disableAuthAppMfa = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/mfa/disable', 'post', body, metadata);
    };
    /**
     * This route disables MFA enrollment for a logged-in user for a specific tenant. Send the
     * **`frontegg-user-id`** header to declare which user. The MFA token should be obtained
     * from the authenticator app. A vendor token is required for this route, it can be
     * obtained from the vendor authentication route.
     *
     * @summary Disable authenticator app MFA
     */
    SDK.prototype.usersMfaControllerV1_disableAuthenticatorMfa = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/mfa/authenticator/{deviceId}/disable/verify', 'post', body, metadata);
    };
    /**
     * Pre-disable SMS MFA
     *
     */
    SDK.prototype.usersMfaControllerV1_preDisableSMSMfa = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/mfa/sms/{deviceId}/disable', 'post', body, metadata);
    };
    /**
     * Disable SMS MFA
     *
     */
    SDK.prototype.usersMfaControllerV1_disableSMSMfa = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/mfa/sms/{deviceId}/disable/verify', 'post', body, metadata);
    };
    /**
     * This route verifies the MFA code from an authenticator app. Send the
     * **`frontegg-vendor-host`** as a header. This is your domain name in the Frontegg Portal
     * ➜ Workspace Settings ➜ Domains ➜ Domain Name. Send information required for MFA in the
     * POST body. The `value` is the service name from your Authentication Settings in the
     * Frontegg Portal. The MFA token is from the authenticator app.
     *
     * @summary Verify MFA using code from authenticator app
     */
    SDK.prototype.authenticationMFAControllerV1_verifyAuthenticatorMfaCode = function (body) {
        return this.core.fetch('/resources/auth/v1/user/mfa/verify', 'post', body);
    };
    /**
     * Request verify MFA using email code
     *
     */
    SDK.prototype.authenticationMFAControllerV1_preVerifyEmailOtcMfa = function (body) {
        return this.core.fetch('/resources/auth/v1/user/mfa/emailcode', 'post', body);
    };
    /**
     * Verify MFA using email code
     *
     */
    SDK.prototype.authenticationMFAControllerV1_verifyEmailOtcMfa = function (body) {
        return this.core.fetch('/resources/auth/v1/user/mfa/emailcode/verify', 'post', body);
    };
    /**
     * Pre enroll MFA using Authenticator App
     *
     */
    SDK.prototype.authenticationMFAControllerV1_preEnrollAuthenticatorMfa = function (body) {
        return this.core.fetch('/resources/auth/v1/user/mfa/authenticator/enroll', 'post', body);
    };
    /**
     * Enroll MFA using Authenticator App
     *
     */
    SDK.prototype.authenticationMFAControllerV1_enrollAuthenticatorMfa = function (body) {
        return this.core.fetch('/resources/auth/v1/user/mfa/authenticator/enroll/verify', 'post', body);
    };
    /**
     * This route verifies MFA as part of the authentication process. Send the
     * **`frontegg-vendor-host`** as a header. This is your domain name in the Frontegg Portal
     * ➜ Workspace Settings ➜ Domains ➜ Domain Name. Send information required for MFA in the
     * POST body. The `value` is the service name from your Authentication Settings in the
     * Frontegg Portal. The MFA token is from the authenticator app.
     *
     * @summary Verify MFA using authenticator app
     */
    SDK.prototype.authenticationMFAControllerV1_verifyAuthenticatorMfa = function (body, metadata) {
        return this.core.fetch('/resources/auth/v1/user/mfa/authenticator/{deviceId}/verify', 'post', body, metadata);
    };
    /**
     * Pre-enroll MFA using sms
     *
     */
    SDK.prototype.authenticationMFAControllerV1_preEnrollSmsMfa = function (body) {
        return this.core.fetch('/resources/auth/v1/user/mfa/sms/enroll', 'post', body);
    };
    /**
     * Enroll MFA using sms
     *
     */
    SDK.prototype.authenticationMFAControllerV1_enrollSmsMfa = function (body) {
        return this.core.fetch('/resources/auth/v1/user/mfa/sms/enroll/verify', 'post', body);
    };
    /**
     * Request to verify MFA using sms
     *
     */
    SDK.prototype.authenticationMFAControllerV1_preVerifySmsMfa = function (body, metadata) {
        return this.core.fetch('/resources/auth/v1/user/mfa/sms/{deviceId}', 'post', body, metadata);
    };
    /**
     * Verify MFA using sms
     *
     */
    SDK.prototype.authenticationMFAControllerV1_verifySmsMfa = function (body, metadata) {
        return this.core.fetch('/resources/auth/v1/user/mfa/sms/{deviceId}/verify', 'post', body, metadata);
    };
    /**
     * Pre enroll MFA using WebAuthN
     *
     */
    SDK.prototype.authenticationMFAControllerV1_preEnrollWebauthnMfa = function (body) {
        return this.core.fetch('/resources/auth/v1/user/mfa/webauthn/enroll', 'post', body);
    };
    /**
     * Enroll MFA using WebAuthN
     *
     */
    SDK.prototype.authenticationMFAControllerV1_enrollWebauthnMfa = function (body) {
        return this.core.fetch('/resources/auth/v1/user/mfa/webauthn/enroll/verify', 'post', body);
    };
    /**
     * Request verify MFA using WebAuthN
     *
     */
    SDK.prototype.authenticationMFAControllerV1_preVerifyWebauthnMfa = function (body, metadata) {
        return this.core.fetch('/resources/auth/v1/user/mfa/webauthn/{deviceId}', 'post', body, metadata);
    };
    /**
     * Verify MFA using webauthn
     *
     */
    SDK.prototype.authenticationMFAControllerV1_verifyWebauthnMfa = function (body, metadata) {
        return this.core.fetch('/resources/auth/v1/user/mfa/webauthn/{deviceId}/verify', 'post', body, metadata);
    };
    /**
     * This route checks if remember device is allowed for all tenants. To check if remember
     * device is allowed for a specific tenant, send the tenant’s ID in the
     * **`frontegg-tenant-id`** header. Get the mfa token from the authenticator app and send
     * it as a query params.
     *
     * @summary Check if remember device allowed
     */
    SDK.prototype.securityPolicyController_checkIfAllowToRememberDevice = function (metadata) {
        return this.core.fetch('/resources/configurations/v1/mfa-policy/allow-remember-device', 'get', metadata);
    };
    /**
     * This route enrolls MFA for a logged-in user for a specific tenant. Send the
     * **`frontegg-user-id`** header to declare which user. A vendor token is required for this
     * route, it can be obtained from the vendor authentication route.
     *
     * @summary Enroll authenticator app MFA
     */
    SDK.prototype.usersMfaControllerV1_enrollAuthAppMfa = function (metadata) {
        return this.core.fetch('/resources/users/v1/mfa/enroll', 'post', metadata);
    };
    /**
     * This route enrolls MFA for a logged-in user for a specific tenant. Send the
     * **`frontegg-user-id`** header to declare which user. A vendor token is required for this
     * route, it can be obtained from the vendor authentication route.
     *
     * @summary Enroll authenticator app MFA
     */
    SDK.prototype.usersMfaControllerV1_enrollAuthenticatorMfa = function (metadata) {
        return this.core.fetch('/resources/users/v1/mfa/authenticator/enroll', 'post', metadata);
    };
    /**
     * This route verifies MFA enrollment using a QR code. Send the **`frontegg-user-id`**
     * header to declare which user. Send information required for MFA in the POST body. The
     * MFA token should be obtained from the authenticator app after scanning the QR code
     * received . A vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Verify authenticator app MFA enrollment
     */
    SDK.prototype.usersMfaControllerV1_verifyAuthAppMfaEnrollment = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/mfa/enroll/verify', 'post', body, metadata);
    };
    /**
     * This route verifies MFA enrollment using a QR code. Send the **`frontegg-user-id`**
     * header to declare which user. Send information required for MFA in the POST body. The
     * MFA token should be obtained from the authenticator app after scanning the QR code
     * received . A vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Verify authenticator app MFA enrollment
     */
    SDK.prototype.usersMfaControllerV1_verifyAuthenticatorMfaEnrollment = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/mfa/authenticator/enroll/verify', 'post', body, metadata);
    };
    /**
     * Enroll SMS MFA
     *
     */
    SDK.prototype.usersMfaControllerV1_preEnrollSmsMfa = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/mfa/sms/enroll', 'post', body, metadata);
    };
    /**
     * Verify MFA enrollment
     *
     */
    SDK.prototype.usersMfaControllerV1_enrollSmsMfa = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/mfa/sms/enroll/verify', 'post', body, metadata);
    };
    /**
     * This route triggers the system to send an SMS to the user and is the first step when
     * authenticating using the sms otc passwordless mechanism. Send the
     * **`frontegg-vendor-host`** as a header to declare which vendor. This is your domain name
     * in the Frontegg Portal ➜ Workspace Settings ➜ Domains ➜ Domain Name. Send the user's
     * email as POST body params. Include the invitation token if the user is signing up by
     * invitation. Send the recaptcha token if the recaptcha is enabled for login.
     *
     * @summary SMS code prelogin
     */
    SDK.prototype.authenticationPasswordlessControllerV1_smsCodePreLogin = function (body) {
        return this.core.fetch('/resources/auth/v1/passwordless/smscode/prelogin', 'post', body);
    };
    /**
     * This route authenticates a local user and is the second step when authenticating using
     * the sms otc passwordless mechanism. Send the **`frontegg-vendor-host`** as a header to
     * declare which vendor. This is your domain name in the Frontegg Portal ➜ Workspace
     * Settings ➜ Domains ➜ Domain Name. Send the user's token id as a POST body params.
     * Include the invitation token if the user is signing up by invitation. Send the recaptcha
     * token if the recaptcha is enabled for login. The route returns the refresh cookie and
     * JWT.
     *
     * @summary SMS code postlogin
     */
    SDK.prototype.authenticationPasswordlessControllerV1_smsCodePostLogin = function (body) {
        return this.core.fetch('/resources/auth/v1/passwordless/smscode/postlogin', 'post', body);
    };
    /**
     * This route triggers the system to send the magic link to the user and is the first step
     * when authenticating a local user with the magic link passwordless mechanism. Send the
     * **`frontegg-vendor-host`** as a header to declare which vendor. This is your domain name
     * in the Frontegg Portal ➜ Workspace Settings ➜ Domains ➜ Domain Name. Send the user's
     * email as POST body params. Include the invitation token if the user is signing up by
     * invitation. Send the recaptcha token if the recaptcha is enabled for login.
     *
     * @summary Magic link prelogin
     */
    SDK.prototype.authenticationPasswordlessControllerV1_magicLinkPrelogin = function (body) {
        return this.core.fetch('/resources/auth/v1/passwordless/magiclink/prelogin', 'post', body);
    };
    /**
     * This route authenticates a local user and is the second step when using the magic link
     * passwordless mechanism. Send the **`frontegg-vendor-host`** as a header to declare which
     * vendor. This is your domain name in the Frontegg Portal ➜ Workspace Settings ➜ Domains ➜
     * Domain Name. Send the user's token id as POST body params. Include the invitation token
     * if the user is signing up by invitation. Send the recaptcha token if the recaptcha is
     * enabled for login. The route returns the refresh cookie and JWT.
     *
     * @summary Magic link postlogin
     */
    SDK.prototype.authenticationPasswordlessControllerV1_magicLinkPostLogin = function (body) {
        return this.core.fetch('/resources/auth/v1/passwordless/magiclink/postlogin', 'post', body);
    };
    /**
     * This route triggers the system to send a one-time code to the user and is the first step
     * when authenticating a local user using the email otc passwordless mechanism. Send the
     * **`frontegg-vendor-host`** as a header to declare which vendor. This is your domain name
     * in the Frontegg Portal ➜ Workspace Settings ➜ Domains ➜ Domain Name. Send the user's
     * email as POST body params. Include the invitation token if the user is signing up by
     * invitation. Send the recaptcha token if the recaptcha is enabled for login.
     *
     * @summary OTC (One-Time Code) prelogin
     */
    SDK.prototype.authenticationPasswordlessControllerV1_emailCodePrelogin = function (body) {
        return this.core.fetch('/resources/auth/v1/passwordless/code/prelogin', 'post', body);
    };
    /**
     * This route authenticates a local user and is the second step when using the email otc
     * passwordless mechanism. Send the **`frontegg-vendor-host`** as a header to declare which
     * vendor. This is your domain name in the Frontegg Portal ➜ Workspace Settings ➜ Domains ➜
     * Domain Name. Send the user's token id as POST body params. Include the invitation token
     * if the user is signing up by invitation. Send the recaptcha token if the recaptcha is
     * enabled for login. The route returns the refresh cookie and JWT.
     *
     * @summary OTC (One-Time Code) postlogin
     */
    SDK.prototype.authenticationPasswordlessControllerV1_emailCodePostLogin = function (body) {
        return this.core.fetch('/resources/auth/v1/passwordless/code/postlogin', 'post', body);
    };
    /**
     * This route creates a general invitation token. To create an invitation token for a
     * specific tenant, send the tenant’s ID in the request’s body. To create an invitation
     * token for a specific user of a tenant, you can add the user ID on the body params. If a
     * user ID was provided, you can decide wether to send an email to the user or not via the
     * shouldSendEmail param. In order to set up a specific expiration time, use the
     * expiresInMinutes to declare when the invite is being invalidated. A vendor token is
     * required for this route, it can be obtained from the vendor authentication route.
     *
     * @summary Create tenant invite
     */
    SDK.prototype.tenantInvitesController_createTenantInvite = function (body) {
        return this.core.fetch('/resources/tenants/invites/v1', 'post', body);
    };
    /**
     * This route gets all invitations for all tenants. A vendor token is required for this
     * route, it can be obtained from the vendor authentication route.
     *
     * @summary Get all tenant invites
     */
    SDK.prototype.tenantInvitesController_getAllInvites = function () {
        return this.core.fetch('/resources/tenants/invites/v1/all', 'get');
    };
    /**
     * This route deletes an invitation to join a tenant using the invitation ID. You can find
     * it via the Get all tenant invites API. Send the invitation ID as a path param - you can
     * get if via the **Get all tenant invites** API. A vendor token is required for this
     * route, it can be obtained from the vendor authentication route.
     *
     * @summary Delete a tenant invite
     */
    SDK.prototype.tenantInvitesController_deleteTenantInvite = function (metadata) {
        return this.core.fetch('/resources/tenants/invites/v1/token/{id}', 'delete', metadata);
    };
    /**
     * This route updates the identity management configuration for a vendor. Send values in
     * the POST body for params that you want to add or update. See the dropdown for available
     * values for each param.
     *
     * @summary Update identity management configuration
     */
    SDK.prototype.vendorConfigController_addOrUpdateConfig = function (body) {
        return this.core.fetch('/resources/configurations/v1', 'post', body);
    };
    /**
     * This route gets the identity management configuration for a vendor.
     *
     * @summary Get identity management configuration
     */
    SDK.prototype.vendorConfigController_getVendorConfig = function () {
        return this.core.fetch('/resources/configurations/v1', 'get');
    };
    /**
     * This route creates a captcha policy for all tenants. To enable the Captcha Policy, make
     * sure to set the enabled variable to true, the site key and secret key to the ones you
     * got from reCaptcha and the minimum score to a number between 0 to 1.
     *
     * @summary Create captcha policy
     */
    SDK.prototype.captchaPolicyController_createCaptchaPolicy = function (body) {
        return this.core.fetch('/resources/configurations/v1/captcha-policy', 'post', body);
    };
    /**
     * This route updates a captcha policy for all tenants. To enable the Captcha Policy, make
     * sure to set the enabled variable to true, the site key and secret key to the ones you
     * got from reCaptcha and the minimum score to a number between 0 to 1.
     *
     * @summary Update captcha policy
     */
    SDK.prototype.captchaPolicyController_updateCaptchaPolicy = function (body) {
        return this.core.fetch('/resources/configurations/v1/captcha-policy', 'put', body);
    };
    /**
     * This route gets the captcha policy. It returns the policy’s ID, site key, secret key,
     * minimum score and ignored emails and wether the .
     *
     * @summary Get captcha policy
     */
    SDK.prototype.captchaPolicyController_getCaptchaPolicy = function () {
        return this.core.fetch('/resources/configurations/v1/captcha-policy', 'get');
    };
    /**
     * This route creates a custom social login provider using OAuth details of the identity
     * provider
     *
     * @summary Create custom oauth provider
     */
    SDK.prototype.ssoV2Controller_createSsoProvider = function (body) {
        return this.core.fetch('/resources/sso/custom/v1', 'post', body);
    };
    /**
     * This route fetches the custom social login providers on an environment
     *
     * @summary Get custom oauth provider
     */
    SDK.prototype.ssoV2Controller_getSsoProviders = function () {
        return this.core.fetch('/resources/sso/custom/v1', 'get');
    };
    /**
     * This route updates the custom social login provider on an environment by ID
     *
     * @summary Update custom oauth provider
     */
    SDK.prototype.ssoV2Controller_updateSsoProvider = function (body, metadata) {
        return this.core.fetch('/resources/sso/custom/v1/{id}', 'patch', body, metadata);
    };
    /**
     * This route deletes the custom social login provider on an environment by ID
     *
     * @summary Delete custom oauth provider
     */
    SDK.prototype.ssoV2Controller_deleteSsoProvider = function (metadata) {
        return this.core.fetch('/resources/sso/custom/v1/{id}', 'delete', metadata);
    };
    /**
     * This route enables you to migrate your users from Auth0 to Frontegg easily. Add the
     * Domain, Client ID, Secret and the tenant’s ID Field Name - they’ll be found on Auth0 and
     * the migration will be as smooth as possible.
     *
     * @summary Migrate from Auth0
     */
    SDK.prototype.usersControllerV1_migrateUserFromAuth0 = function (body) {
        return this.core.fetch('/resources/migrations/v1/auth0', 'post', body);
    };
    /**
     * This route enables you to migrate a user by sending the following required fields:
     * user’s email, their tenantId and metadata, a new user will be created. This endpoint
     * takes other properties as well, such as the user’s name, their phone number, hashed
     * password, etc...
     *
     * @summary Migrate a vendor user
     */
    SDK.prototype.usersControllerV1_migrateUserForVendor = function (body) {
        return this.core.fetch('/resources/migrations/v1/local', 'post', body);
    };
    /**
     * This route enables you to migrate users in bulk. Expects an array of `users`. Each entry
     * must include a user's `email` and `tenantId`, which specifies that user's parent
     * account. Use the the other fields as needed to store additional information. We
     * recommend using the `metadata` property if you need to store custom information in a
     * user's object.
     *
     * @summary Migrate vendor users in bulk
     */
    SDK.prototype.usersControllerV1_bulkMigrateUserForVendor = function (body) {
        return this.core.fetch('/resources/migrations/v1/local/bulk', 'post', body);
    };
    /**
     * This route returns the status of a pending or completed migration. The payload includes
     * the migration's current `state`, the number of migrated users, and any errors that
     * occured during migration. Payload is limited to 1,000 users.
     *
     * @summary Check status of bulk migration
     */
    SDK.prototype.usersControllerV1_checkBulkMigrationStatus = function (metadata) {
        return this.core.fetch('/resources/migrations/v1/local/bulk/status/{migrationId}', 'get', metadata);
    };
    /**
     * Get information about the delegation configuration (if enabled). A [vendor
     * token](/reference/authenticate_vendor) is required for this route.
     *
     * @summary Get delegation donfiguration
     */
    SDK.prototype.delegationConfigurationControllerV1_getDelegationConfiguration = function () {
        return this.core.fetch('/resources/configurations/v1/delegation', 'get');
    };
    /**
     * Enable or disable the ability to use delegation in a token exchange flow. A [vendor
     * token](/reference/authenticate_vendor) is required for this route.
     *
     * @summary Create or update a delegation configuration
     */
    SDK.prototype.delegationConfigurationControllerV1_createOrUpdateDelegationConfiguration = function (body) {
        return this.core.fetch('/resources/configurations/v1/delegation', 'post', body);
    };
    /**
     * Frontegg sends emails via SendGrid. If you already have an account on SendGrid and you
     * wish emails to be sent from your SendGrid account, pass the SendGrid secret key as a
     * body param. A vendor token is required for this route, it can be obtained from the
     * vendor authentication route.
     *
     * @summary Create or update configuration
     */
    SDK.prototype.mailConfigController_createOrUpdateMailConfig = function (body) {
        return this.core.fetch('/resources/mail/v1/configurations', 'post', body);
    };
    /**
     * This route returns the mail configuration setup on Frontegg for your SendGrid account. A
     * vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Get configuration
     */
    SDK.prototype.mailConfigController_getMailConfig = function () {
        return this.core.fetch('/resources/mail/v1/configurations', 'get');
    };
    /**
     * A vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Delete configuration
     */
    SDK.prototype.mailConfigController_deleteMailConfig = function () {
        return this.core.fetch('/resources/mail/v1/configurations', 'delete');
    };
    /**
     * This route creates or updates an email template. Select the email template using the
     * type. The type value needs to be the name of one of the Frontegg email templates. See
     * the dropdown for available values. Also, set the sender using senderEmail. Optionally,
     * include values for the other available body params. Send the information for the
     * template in the POST body. A vendor token is required for this route, it can be obtained
     * from the vendor authentication route.
     *
     * @summary Add or update template
     */
    SDK.prototype.mailV1Controller_addOrUpdateTemplate = function (body) {
        return this.core.fetch('/resources/mail/v1/configs/templates', 'post', body);
    };
    /**
     * This route gets all the vendor’s email templates. In order to get a specific template,
     * pass its type as a query param. A vendor token is required for this route, it can be
     * obtained from the vendor authentication route.
     *
     * @summary Get template
     */
    SDK.prototype.mailV1Controller_getTemplateConfiguration = function (metadata) {
        return this.core.fetch('/resources/mail/v1/configs/templates', 'get', metadata);
    };
    /**
     * This route deletes specified email template. Select the email template using the ID of
     * the template - which can be obtained via the **Get template** API. A vendor token is
     * required for this route, it can be obtained from the vendor authentication route.
     *
     * @summary Delete template
     */
    SDK.prototype.mailV1Controller_deleteTemplate = function (metadata) {
        return this.core.fetch('/resources/mail/v1/configs/templates/{templateId}', 'delete', metadata);
    };
    /**
     * This route gets default email template by type, pass required type as a query param.
     *
     * @summary Get default template by type
     */
    SDK.prototype.mailV1Controller_getDefaultTemplateConfiguration = function (metadata) {
        return this.core.fetch('/resources/mail/v1/configs/{type}/default', 'get', metadata);
    };
    /**
     * Get active access tokens list
     *
     */
    SDK.prototype.vendorOnlyUserAccessTokensV1Controller_getActiveAccessTokens = function (metadata) {
        return this.core.fetch('/resources/vendor-only/users/access-tokens/v1/active', 'get', metadata);
    };
    /**
     * Get user access token data
     *
     */
    SDK.prototype.vendorOnlyUserAccessTokensV1Controller_getUserAccessTokenData = function (metadata) {
        return this.core.fetch('/resources/vendor-only/users/access-tokens/v1/{id}', 'get', metadata);
    };
    /**
     * Get tenant access token data
     *
     */
    SDK.prototype.vendorOnlyTenantAccessTokensV1Controller_getTenantAccessTokenData = function (metadata) {
        return this.core.fetch('/resources/vendor-only/tenants/access-tokens/v1/{id}', 'get', metadata);
    };
    /**
     * This route updates the MFA configuration for a vendor. Send values in the POST body as
     * objects for params that you want to add or update. See the dropdowns for available
     * values for each object param.
     *
     * @summary Update MFA configuration
     */
    SDK.prototype.mfaController_upsertMfaConfig = function (body) {
        return this.core.fetch('/resources/configurations/v1/mfa', 'post', body);
    };
    /**
     * This route gets the MFA configuration for a vendor.
     *
     * @summary Get MFA configuration
     */
    SDK.prototype.mfaController_getMfaConfig = function () {
        return this.core.fetch('/resources/configurations/v1/mfa', 'get');
    };
    /**
     * This route returns all permissions categories for a vendor. Each category is an object
     * containing the name, description, permissions, and other defining information.
     *
     * @summary Get permissions categories
     */
    SDK.prototype.permissionsCategoriesController_getAllCategoriesWithPermissions = function () {
        return this.core.fetch('/resources/permissions/v1/categories', 'get');
    };
    /**
     * Use this route to add a new permissions category. Each category you add requires you to
     * send information about the category in the POST body. Note that you do not associate the
     * category with permissions here. You do that using the add and update permission routes
     * where you send the category ID as a body parameter.
     *
     * @summary Create category
     */
    SDK.prototype.permissionsCategoriesController_createPermissionCategory = function (body) {
        return this.core.fetch('/resources/permissions/v1/categories', 'post', body);
    };
    /**
     * This route updates an existing permissions category. Add the category ID as a path
     * parameter to the route url to specify which category you are updating. Send the updated
     * information about the category in the PATCH body. Note that here is not where you update
     * the permissions associated with the category. Use the add or update permissions routes
     * to do that. Use the **Get categories** API to get
     *
     * @summary Update category
     */
    SDK.prototype.permissionsCategoriesController_updateCategory = function (body, metadata) {
        return this.core.fetch('/resources/permissions/v1/categories/{categoryId}', 'patch', body, metadata);
    };
    /**
     * This route deletes a category. Add the category ID as a path parameter to the route url
     * to specify which category you are deleting. Use the **Get categories** API to get the
     * category ID.
     *
     * @summary Delete category
     */
    SDK.prototype.permissionsCategoriesController_deleteCategory = function (metadata) {
        return this.core.fetch('/resources/permissions/v1/categories/{categoryId}', 'delete', metadata);
    };
    /**
     * This route returns all permissions for the vendor. Each permission is an object
     * containing the name, description, assigned roles, categories, and other defining
     * information.
     *
     * @summary Get permissions
     */
    SDK.prototype.permissionsControllerV1_getAllPermissions = function () {
        return this.core.fetch('/resources/permissions/v1', 'get');
    };
    /**
     * This route adds a new permission. Each permission you add requires information about the
     * permission in the POST body. Note that you do not associate permissions to the role
     * here. Use the associate permission to roles route to do that.
     *
     * @summary Create permissions
     */
    SDK.prototype.permissionsControllerV1_addPermissions = function (body) {
        return this.core.fetch('/resources/permissions/v1', 'post', body);
    };
    /**
     * This route deletes a permission. Add the permission ID as a path parameter to the route
     * url to specify which permission you are deleting.  Use the **Get permissions** API to
     * get the permission ID.
     *
     * @summary Delete permission
     */
    SDK.prototype.permissionsControllerV1_deletePermission = function (metadata) {
        return this.core.fetch('/resources/permissions/v1/{permissionId}', 'delete', metadata);
    };
    /**
     * This route updates an existing permission. Add the permission ID as a path parameter to
     * the route url to specify which permission you are updating. Send the updated information
     * about the permission in the PATCH body. Note that you do not update roles for the
     * permission here. Use the associate permission to roles route to do that.
     *
     * @summary Update permission
     */
    SDK.prototype.permissionsControllerV1_updatePermission = function (body, metadata) {
        return this.core.fetch('/resources/permissions/v1/{permissionId}', 'patch', body, metadata);
    };
    /**
     * This route associates a permission to multiple roles. Add the permission ID as a path
     * parameter to the route url and include the role IDs in the request body as an array of
     * strings. Any pre-existing roles associated with the permission will stay associated. Use
     * the **Get roles** API to get the role IDs.
     *
     * @summary Set a permission to multiple roles
     */
    SDK.prototype.permissionsControllerV1_setRolesToPermission = function (body, metadata) {
        return this.core.fetch('/resources/permissions/v1/{permissionId}/roles', 'put', body, metadata);
    };
    /**
     * This route accepts an array of **`permissionIds`** and the type for these permissions
     * classifications. This allows segregating which permissions will be used from self
     * service
     *
     * @summary Set permissions classification
     */
    SDK.prototype.permissionsControllerV1_updatePermissionsAssignmentType = function (body) {
        return this.core.fetch('/resources/permissions/v1/classification', 'put', body);
    };
    /**
     * This route returns all roles for all tenants. To get a role for a specific tenant, send
     * the tenant ID in the **`frontegg-tenant-id`** header. Each role is an object containing
     * the name, permissions, and other defining information.
     *
     * @summary Get roles
     */
    SDK.prototype.permissionsControllerV1_getAllRoles = function (metadata) {
        return this.core.fetch('/resources/roles/v1', 'get', metadata);
    };
    /**
     * This route adds a new role for all tenants. To add a role for a specific tenant, send
     * tenant ID in the **`frontegg-tenant-id`** header. Each role you add requires information
     * about the role in the POST body. Note that you do not assign permissions to the role
     * here. Use the attach permissions to role route to do that.
     *
     * @summary Create roles
     */
    SDK.prototype.permissionsControllerV1_addRoles = function (body, metadata) {
        return this.core.fetch('/resources/roles/v1', 'post', body, metadata);
    };
    /**
     * This route deletes a role. Add the role ID as a path parameter to the route url to
     * specify which role you are deleting.
     *
     * @summary Delete role
     */
    SDK.prototype.permissionsControllerV1_deleteRole = function (metadata) {
        return this.core.fetch('/resources/roles/v1/{roleId}', 'delete', metadata);
    };
    /**
     * This route updates an existing role. Add the role ID as a path parameter to the route
     * url to specify which role you are updating. Send the updated information about the role
     * in the PATCH body. Note that you do not update permissions for the role here. Use the
     * attach permissions to role route to do that. Use the **Get roles** API to get the role
     * ID.
     *
     * @summary Update role
     */
    SDK.prototype.permissionsControllerV1_updateRole = function (body, metadata) {
        return this.core.fetch('/resources/roles/v1/{roleId}', 'patch', body, metadata);
    };
    /**
     * This route assigns permissions to a role. Add the role ID as a path parameter to the
     * route url and include the permission IDs in the request body as an array of strings. Any
     * pre-existing permissions will be overridden by the new permissions. Use the get roles
     * API to get the role IDs. Use the **Get permissions** API to get the permissions IDs.
     *
     * @summary Set multiple permissions to a role
     */
    SDK.prototype.permissionsControllerV1_setPermissionsToRole = function (body, metadata) {
        return this.core.fetch('/resources/roles/v1/{roleId}/permissions', 'put', body, metadata);
    };
    /**
     * This route creates or updates SMS configuration for a vendor.
     *
     * @summary Creates or updates a vendor SMS config
     */
    SDK.prototype.vendorSmsController_createSmsVendorConfig = function (body) {
        return this.core.fetch('/resources/configurations/v1/sms', 'post', body);
    };
    /**
     * Deletes a vendor SMS config
     *
     */
    SDK.prototype.vendorSmsController_deleteSmsVendorConfig = function () {
        return this.core.fetch('/resources/configurations/v1/sms', 'delete');
    };
    /**
     * Gets a vendor SMS config
     *
     */
    SDK.prototype.vendorSmsController_getSmsVendorConfig = function () {
        return this.core.fetch('/resources/configurations/v1/sms', 'get');
    };
    /**
     * Gets vendor SMS templates
     *
     */
    SDK.prototype.vendorSmsController_getAllSmsTemplates = function () {
        return this.core.fetch('/resources/configurations/v1/sms/templates', 'get');
    };
    /**
     * Gets vendor SMS template by type
     *
     */
    SDK.prototype.vendorSmsController_getSmsTemplate = function (metadata) {
        return this.core.fetch('/resources/configurations/v1/sms/templates/{type}', 'get', metadata);
    };
    /**
     * Deletes vendor SMS template by type
     *
     */
    SDK.prototype.vendorSmsController_deleteSmsTemplate = function (metadata) {
        return this.core.fetch('/resources/configurations/v1/sms/templates/{type}', 'delete', metadata);
    };
    /**
     * Create or update a vendor SMS template
     *
     */
    SDK.prototype.vendorSmsController_createSmsTemplate = function (body, metadata) {
        return this.core.fetch('/resources/configurations/v1/sms/templates/{type}', 'post', body, metadata);
    };
    /**
     * Gets vendor default SMS template by type
     *
     */
    SDK.prototype.vendorSmsController_getSmsDefaultTemplate = function (metadata) {
        return this.core.fetch('/resources/configurations/v1/sms/templates/{type}/default', 'get', metadata);
    };
    /**
     * Get environment session configuration
     *
     */
    SDK.prototype.sessionConfigurationControllerV1_getVendorSessionConfiguration = function () {
        return this.core.fetch('/resources/configurations/sessions/v1/vendor', 'get');
    };
    /**
     * This route gets all vendor's user sources.
     *
     * @summary Get vendor user sources
     */
    SDK.prototype.userSourcesControllerV1_getUserSources = function () {
        return this.core.fetch('/resources/user-sources/v1', 'get');
    };
    /**
     * This route gets a user source by id.
     *
     * @summary Get user source
     */
    SDK.prototype.userSourcesControllerV1_getUserSource = function (metadata) {
        return this.core.fetch('/resources/user-sources/v1/{id}', 'get', metadata);
    };
    /**
     * This route deletes a user source.
     *
     * @summary Delete user source
     */
    SDK.prototype.userSourcesControllerV1_deleteUserSource = function (metadata) {
        return this.core.fetch('/resources/user-sources/v1/{id}', 'delete', metadata);
    };
    /**
     * This route creates a new external user source.
     *
     * @summary Create vendor external user source
     */
    SDK.prototype.userSourcesControllerV1_createAuth0ExternalUserSource = function (body) {
        return this.core.fetch('/resources/user-sources/v1/external/auth0', 'post', body);
    };
    /**
     * This route creates a new external user source.
     *
     * @summary Create vendor external user source
     */
    SDK.prototype.userSourcesControllerV1_createCognitoExternalUserSource = function (body) {
        return this.core.fetch('/resources/user-sources/v1/external/cognito', 'post', body);
    };
    /**
     * This route creates a new external user source.
     *
     * @summary Create vendor external user source
     */
    SDK.prototype.userSourcesControllerV1_createCustomCodeExternalUserSource = function (body) {
        return this.core.fetch('/resources/user-sources/v1/external/custom-code', 'post', body);
    };
    /**
     * This route creates a new federation user source.
     *
     * @summary Create vendor federation user source
     */
    SDK.prototype.userSourcesControllerV1_createFederationUserSource = function (body) {
        return this.core.fetch('/resources/user-sources/v1/federation', 'post', body);
    };
    /**
     * This route updates an external user source.
     *
     * @summary Create vendor external user source
     */
    SDK.prototype.userSourcesControllerV1_updateAuth0ExternalUserSource = function (body, metadata) {
        return this.core.fetch('/resources/user-sources/v1/external/auth0/{id}', 'put', body, metadata);
    };
    /**
     * This route updates an external user source.
     *
     * @summary Create vendor external user source
     */
    SDK.prototype.userSourcesControllerV1_updateCognitoExternalUserSource = function (body, metadata) {
        return this.core.fetch('/resources/user-sources/v1/external/cognito/{id}', 'put', body, metadata);
    };
    /**
     * This route updates an external user source.
     *
     * @summary Create vendor external user source
     */
    SDK.prototype.userSourcesControllerV1_updateCustomCodeExternalUserSource = function (body, metadata) {
        return this.core.fetch('/resources/user-sources/v1/external/custom-code/{id}', 'put', body, metadata);
    };
    /**
     * This route updates a federation user source.
     *
     * @summary Create vendor external user source
     */
    SDK.prototype.userSourcesControllerV1_updateFederationUserSource = function (body, metadata) {
        return this.core.fetch('/resources/user-sources/v1/federation/{id}', 'put', body, metadata);
    };
    /**
     * This route assigns applications to a user source.
     *
     * @summary Assign applications to a user source
     */
    SDK.prototype.userSourcesControllerV1_assignUserSource = function (body) {
        return this.core.fetch('/resources/user-sources/v1/assign', 'post', body);
    };
    /**
     * This route unassigns applications from a user source.
     *
     * @summary Unassign applications from a user source
     */
    SDK.prototype.userSourcesControllerV1_unassignUserSource = function (body) {
        return this.core.fetch('/resources/user-sources/v1/unassign', 'post', body);
    };
    /**
     * This route gets all of users of a user source.
     *
     * @summary Get user source users
     */
    SDK.prototype.userSourcesControllerV1_getUserSourceUsers = function (metadata) {
        return this.core.fetch('/resources/user-sources/v1/{id}/users', 'get', metadata);
    };
    /**
     * This route gets a user by its ID regardless of any tenant the user belongs to. Send the
     * user’s ID as a path params. The route is for vendor-use only.
     *
     * @summary Get user
     */
    SDK.prototype.vendorOnlyUsers_getUserById = function (metadata) {
        return this.core.fetch('/resources/vendor-only/users/v1/{userId}', 'get', metadata);
    };
    /**
     * This route unenrolls a user from MFA regardless of any tenant the user belongs to. Send
     * the user’s ID as a path params. The route is for vendor-use only.
     *
     * @summary Unenroll user from MFA globally
     */
    SDK.prototype.vendorOnlyUsers_MFAUnenroll = function (metadata) {
        return this.core.fetch('/resources/vendor-only/users/v1/{userId}/mfa/unenroll', 'post', metadata);
    };
    /**
     * This route verify user email and password. Send the user’s email and password and the
     * response will be true or false. The route is for vendor-use only.
     *
     * @summary Verify user's password
     */
    SDK.prototype.vendorOnlyUsers_verifyUserPassword = function (body) {
        return this.core.fetch('/resources/vendor-only/users/v1/passwords/verify', 'post', body);
    };
    /**
     * This route creates a user and allows setting **`mfaBypass`** property on that user for
     * testing purposes. The route is for vendor-use only.
     *
     * @summary Create user
     */
    SDK.prototype.vendorOnlyUsers_createUser = function (body) {
        return this.core.fetch('/resources/vendor-only/users/v1', 'post', body);
    };
    /**
     * This route gets the tenants statuses of vendor users. Expects an array of **`userIds`**
     * with max of 200 and optionally an array of **`userTenantStatuses`** as query params.
     * Note that there is a limit of 2000 tenants statuses per user.
     *
     * @summary Get users tenants statuses
     */
    SDK.prototype.get = function (metadata) {
        return this.core.fetch('/resources/tenants/users/v1/statuses', 'get', metadata);
    };
    /**
     * This route updates the settings for temporary users, use it to enable or disable it for
     * an environment
     *
     * @summary Set temporary users configuration
     */
    SDK.prototype.temporaryUsersV1Controller_updateConfiguration = function (body) {
        return this.core.fetch('/resources/users/temporary/v1/configuration', 'put', body);
    };
    /**
     * This route get the settings for temporary users, use it to check whether the policy is's
     * enabled or disabled
     *
     * @summary Gets temporary users configuration
     */
    SDK.prototype.temporaryUsersV1Controller_getConfiguration = function () {
        return this.core.fetch('/resources/users/temporary/v1/configuration', 'get');
    };
    /**
     * This route enables you to invite users to tenant in bulk. Expects an array of `users`.
     * Each entry must include a user's `email`.
     *
     * @summary Invite users to tenant in bulk
     */
    SDK.prototype.usersBulkControllerV1_bulkInviteUsers = function (body, metadata) {
        return this.core.fetch('/resources/users/bulk/v1/invite', 'post', body, metadata);
    };
    /**
     * This route enables you to invite users to tenant in bulk. Expects an array of `users`.
     * Each entry must include a user's `email`.
     *
     * @summary Get status of bulk invite task
     */
    SDK.prototype.usersBulkControllerV1_getBulkInviteStatus = function (metadata) {
        return this.core.fetch('/resources/users/bulk/v1/status/{id}', 'get', metadata);
    };
    /**
     * This route get user by email
     *
     * @summary Get user by email
     */
    SDK.prototype.usersControllerV1_getUserByEmail = function (metadata) {
        return this.core.fetch('/resources/users/v1/email', 'get', metadata);
    };
    /**
     * This route gets a specific user from a tenant. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header to declare which tenant and send the user’s ID as a path
     * params to declare which user. A vendor token is required for this route, it can be
     * obtained from the vendor authentication route.
     *
     * @summary Get user by ID
     */
    SDK.prototype.usersControllerV1_getUserById = function (metadata) {
        return this.core.fetch('/resources/users/v1/{id}', 'get', metadata);
    };
    /**
     * This route updates a user’s information globally, not just for a specific tenant. Send
     * the user’s ID as a path params to declare which user. Send the updated user values in
     * the PUT body. The PUT request does a complete update of the resource, so include values
     * for all the body params that you want to have values. This is a global update, so do not
     * send a **`frontegg-tenant-id`** header.
     *
     * @summary Update user globally
     */
    SDK.prototype.usersControllerV1_updateUserForVendor = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/{userId}', 'put', body, metadata);
    };
    /**
     * This route removes a user globally or from a specific tenant. To remove the user
     * globally, no need to send a **`frontegg-tenant-id`**. To remove the user from only a
     * specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header. Send the
     * user's ID as a path params to declare which user you are removing. A vendor token is
     * required for this route, it can be obtained from the vendor authentication route.
     *
     * @summary Remove user
     */
    SDK.prototype.usersControllerV1_removeUserFromTenant = function (metadata) {
        return this.core.fetch('/resources/users/v1/{userId}', 'delete', metadata);
    };
    /**
     * This route marks a user as verified. Send the user’s ID as a path params. A vendor token
     * is required for this route, it can be obtained from the vendor authentication route.
     *
     * @summary Verify user
     */
    SDK.prototype.usersControllerV1_verifyUser = function (metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/verify', 'post', metadata);
    };
    /**
     * This route sets whether a user is invisible or visible. If a user is invisible, the user
     * data remains in the Frontegg system but the user will not appear in the list of users in
     * the admin box. An invisible user remains part of the tenant. Send the user’s ID as a
     * path params. Also send as a PUT body params a Boolean value for invisible. True is
     * invisible and false is visible. A vendor token is required for this route, it can be
     * obtained from the vendor authentication route.
     *
     * @summary Make user invisible
     */
    SDK.prototype.usersControllerV1_setUserInvisibleMode = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/invisible', 'put', body, metadata);
    };
    /**
     * This route sets whether a user is a super user. A super user has access to all tenants
     * within the workspace. Send the user ID as a path params. Also send as a PUT body params
     * a Boolean value for super user. True is super user and false is not. A vendor token is
     * required for this route, it can be obtained from the vendor authentication route.
     *
     * @summary Make User superuser
     */
    SDK.prototype.usersControllerV1_setUserSuperuserMode = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/superuser', 'put', body, metadata);
    };
    /**
     * This route is for the vendor to set the active tenant of a user. The active tenant is
     * the tenant the user will see in their admin portal and also the tenant for which the API
     * reference will default to in situations where a route is tenant specific. Send the user
     * ID as a path param and the tenant ID as a PUT body param. When using a non-existing
     * tenant ID, there will be a tenant create for the provided ID. A vendor token is required
     * for this route, it can be obtained from the vendor authentication route.
     *
     * @summary Set user's tenant
     */
    SDK.prototype.usersControllerV1_updateUserTenantForVendor = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/tenant', 'put', body, metadata);
    };
    /**
     * This route adds a user to a tenant. Send the user ID as a path params and the tenant ID
     * as a PUT body params. To skip the invite email requirement, pass as an optional PUT body
     * params for skipInviteEmail. Set its value to true to skip the invite email. A vendor
     * token is required for this route, it can be obtained from the vendor authentication
     * route.
     *
     * @summary Add to tenant
     */
    SDK.prototype.usersControllerV1_addUserToTenantForVendor = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/tenant', 'post', body, metadata);
    };
    /**
     * This route updates the email address for a user globally, regardless of tenant. Send the
     * user’s ID as a path params. Send the user’s new email address as a PUT body params.
     *
     * @summary Update user email
     */
    SDK.prototype.usersControllerV1_updateUserEmail = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/email', 'put', body, metadata);
    };
    /**
     * This route generates a new activation token for a user. Send the user’s ID as a path
     * params. You may need this route in combination with the routes under Users Activation.
     * It will not send the activation email itself, but return the activation link and token.
     * A vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Generate activation token
     */
    SDK.prototype.usersControllerV1_generateUserActivationLink = function (metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/links/generate-activation-token', 'post', metadata);
    };
    /**
     * This route generates a password reset token for a user. Send the user’s ID as a path
     * params. You may need this route in combination with the routes under Users Passwords. It
     * will not send the reset password email itself, but return the reset link and token. A
     * vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Generate password reset token
     */
    SDK.prototype.usersControllerV1_generateUserPasswordResetLink = function (metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/links/generate-password-reset-token', 'post', metadata);
    };
    /**
     * This route unlocks a locked user. An unlocked user can sign in and use the system
     * globally, regardless of the tenant. To unlock a user, call this route and send the
     * user’s ID as a path params. A vendor token is required for this route, it can be
     * obtained from the vendor authentication route.
     *
     * @summary Unlock user
     */
    SDK.prototype.usersControllerV1_unlockUser = function (metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/unlock', 'post', metadata);
    };
    /**
     * This route locks a user. A locked user cannot sign in or use the system globally,
     * regardless of the tenant. To lock a user, call this route and send the user’s ID as a
     * path params. A vendor token is required for this route, it can be obtained from the
     * vendor authentication route.
     *
     * @summary Lock user
     */
    SDK.prototype.usersControllerV1_lockUser = function (metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/lock', 'post', metadata);
    };
    /**
     * This route migrates all the users from the source tenant to the target. Specify in the
     * request body the srcTenantId (the source tenant ID) and targetTenantId (the target
     * tenant ID). A vendor token is required for this route, it can be obtained from the
     * vendor authentication route.
     *
     * @summary Move all users from one tenant to another
     */
    SDK.prototype.usersControllerV1_moveAllUsersTenants = function (body) {
        return this.core.fetch('/resources/users/v1/tenants/migrate', 'put', body);
    };
    /**
     * This route gets an invitation for a specific user to join a tenant. Send the user’s ID
     * in the **`frontegg-user-id`** header and the tenant’s ID in the **`frontegg-tenant-id`**
     * header.
     *
     * @summary Get tenant invite of user
     */
    SDK.prototype.tenantInvitesController_getTenantInviteForUser = function (metadata) {
        return this.core.fetch('/resources/tenants/invites/v1/user', 'get', metadata);
    };
    /**
     * This route creates an invitation for a specific user to join a tenant. Send the user’s
     * ID in the **`frontegg-user-id`** header and the tenant’s ID in the
     * **`frontegg-tenant-id`** header. To create a general invitation, use the general
     * invitation route.
     *
     * @summary Create tenant invite for user
     */
    SDK.prototype.tenantInvitesController_createTenantInviteForUser = function (body, metadata) {
        return this.core.fetch('/resources/tenants/invites/v1/user', 'post', body, metadata);
    };
    /**
     * This route deletes an invitation for a specific user to join a tenant. Send the user’s
     * ID in the **`frontegg-user-id`** header and the tenant’s ID in the
     * **`frontegg-tenant-id`** header. To delete a general invitation, use the general
     * invitation route.
     *
     * @summary Delete tenant invite of user
     */
    SDK.prototype.tenantInvitesController_deleteTenantInviteForUser = function (metadata) {
        return this.core.fetch('/resources/tenants/invites/v1/user', 'delete', metadata);
    };
    /**
     * This route updates an invitation for a specific user to join a tenant. In order to set
     * up a specific expiration time, use the expiresInMinutes to declare when the invite is
     * being invalidated. The shouldSendEmail boolean declares wether an invitation email will
     * be sent or not. Send the user’s ID in the **`frontegg-user-id`** header and the tenant’s
     * ID in the **`frontegg-tenant-id`** header. A vendor token is required for this route, it
     * can be obtained from the vendor authentication route.
     *
     * @summary Update tenant invite of user
     */
    SDK.prototype.tenantInvitesController_updateTenantInviteForUser = function (body, metadata) {
        return this.core.fetch('/resources/tenants/invites/v1/user', 'patch', body, metadata);
    };
    /**
     * This route verifies a tenant invitation. Pass the invitation token as the token param. A
     * vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Verify tenant invite
     */
    SDK.prototype.tenantInvitesController_verifyTenantInvite = function (body) {
        return this.core.fetch('/resources/tenants/invites/v1/verify', 'post', body);
    };
    /**
     * This route checks if the vendor allows tenant invitations and if notifications are
     * active. A vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Get tenant invite configuration
     */
    SDK.prototype.getInvitationConfiguration = function () {
        return this.core.fetch('/resources/tenants/invites/v1/configuration', 'get');
    };
    /**
     * This route creates a new domain restriction for a tenant. Send values in the POST body
     * as objects. See the dropdowns for available values for each object param.
     *
     * @summary Create domain restriction
     */
    SDK.prototype.domainRestrictionsController_createDomainRestriction = function (body) {
        return this.core.fetch('/resources/configurations/restrictions/v1/email-domain', 'post', body);
    };
    /**
     * This route gets the domain restrictions for a tenant.
     *
     * @summary Get domain restrictions
     */
    SDK.prototype.domainRestrictionsController_getDomainRestrictions = function () {
        return this.core.fetch('/resources/configurations/restrictions/v1/email-domain', 'get');
    };
    /**
     * This route gets the domain restrictions for a tenant.
     *
     * @summary Get domain restrictions
     */
    SDK.prototype.domainRestrictionsController_getDomainRestrictionsConfig = function () {
        return this.core.fetch('/resources/configurations/restrictions/v1/email-domain/config', 'get');
    };
    /**
     * This route updates domain restrictions config, can toggle check on/off.
     *
     * @summary Change domain restrictions config list type and toggle it off/on
     */
    SDK.prototype.domainRestrictionsController_updateDomainRestrictionsConfig = function (body) {
        return this.core.fetch('/resources/configurations/restrictions/v1/email-domain/config', 'post', body);
    };
    /**
     * This route deletes domain restriction.
     *
     * @summary Delete domain restriction
     */
    SDK.prototype.domainRestrictionsController_deleteDomainRestriction = function (metadata) {
        return this.core.fetch('/resources/configurations/restrictions/v1/email-domain/{id}', 'delete', metadata);
    };
    /**
     * This route replaces all domains from the incoming request
     *
     * @summary Replace bulk domain restriction
     */
    SDK.prototype.domainRestrictionsController_createBulkDomainsRestriction = function (body) {
        return this.core.fetch('/resources/configurations/restrictions/v1/email-domain/replace-bulk', 'post', body);
    };
    /**
     * This route gets all user groups for a tenant.
     *
     * @summary Get all groups
     */
    SDK.prototype.groupsControllerV1_getAllGroups = function (metadata) {
        return this.core.fetch('/resources/groups/v1', 'get', metadata);
    };
    /**
     * This route creates user group for a tenant.
     *
     * @summary Create group
     */
    SDK.prototype.groupsControllerV1_createGroup = function (body) {
        return this.core.fetch('/resources/groups/v1', 'post', body);
    };
    /**
     * This route gets user group by given IDs for a tenant.
     *
     * @summary Get groups by ids
     */
    SDK.prototype.groupsControllerV1_getGroupsByIds = function (body, metadata) {
        return this.core.fetch('/resources/groups/v1/bulkGet', 'post', body, metadata);
    };
    /**
     * This route updates user group by id for a tenant.
     *
     * @summary Update group
     */
    SDK.prototype.groupsControllerV1_updateGroup = function (body, metadata) {
        return this.core.fetch('/resources/groups/v1/{id}', 'patch', body, metadata);
    };
    /**
     * This route deletes user group by id for a tenant.
     *
     * @summary Delete group
     */
    SDK.prototype.groupsControllerV1_deleteGroup = function (metadata) {
        return this.core.fetch('/resources/groups/v1/{id}', 'delete', metadata);
    };
    /**
     * This route gets user group by given ID for a tenant.
     *
     * @summary Get group by ID
     */
    SDK.prototype.groupsControllerV1_getGroupById = function (metadata) {
        return this.core.fetch('/resources/groups/v1/{id}', 'get', metadata);
    };
    /**
     * This route gets the user group configuration for a vendor.
     *
     * @summary Get groups configuration
     */
    SDK.prototype.groupsControllerV1_getGroupsConfiguration = function () {
        return this.core.fetch('/resources/groups/v1/config', 'get');
    };
    /**
     * This route creates or updates the user group configuration for a vendor.
     *
     * @summary Create or update groups configuration
     */
    SDK.prototype.groupsControllerV1_createOrUpdateGroupsConfiguration = function (body) {
        return this.core.fetch('/resources/groups/v1/config', 'post', body);
    };
    /**
     * This route adds requested roles to existing group. User can assign only roles that are
     * lower then his own.
     *
     * @summary Add roles to group
     */
    SDK.prototype.groupsControllerV1_addRolesToGroup = function (body, metadata) {
        return this.core.fetch('/resources/groups/v1/{groupId}/roles', 'post', body, metadata);
    };
    /**
     * This route removes requested roles from existing group.
     *
     * @summary Remove roles from group
     */
    SDK.prototype.groupsControllerV1_removeRolesFromGroup = function (body, metadata) {
        return this.core.fetch('/resources/groups/v1/{groupId}/roles', 'delete', body, metadata);
    };
    /**
     * This route adds requested users to existing group. Only allowed for users that have
     * higher roles then group roles.
     *
     * @summary Add users to group
     */
    SDK.prototype.groupsControllerV1_addUsersToGroup = function (body, metadata) {
        return this.core.fetch('/resources/groups/v1/{groupId}/users', 'post', body, metadata);
    };
    /**
     * This route removes requested users from existing group.
     *
     * @summary Remove users from group
     */
    SDK.prototype.groupsControllerV1_removeUsersFromGroup = function (body, metadata) {
        return this.core.fetch('/resources/groups/v1/{groupId}/users', 'delete', body, metadata);
    };
    /**
     * This route gets all user groups for a tenant.
     *
     * @summary Get all groups paginated
     */
    SDK.prototype.groupsControllerV2_getAllGroupsPaginated = function (metadata) {
        return this.core.fetch('/resources/groups/v2', 'get', metadata);
    };
    /**
     * This route creates or updates ip restrictions config.
     *
     * @summary Create or update IP restriction configuration (ALLOW/BLOCK)
     */
    SDK.prototype.iPRestrictionsControllerV1_createDomainRestriction = function (body) {
        return this.core.fetch('/resources/configurations/v1/restrictions/ip/config', 'post', body);
    };
    /**
     * This route gets the ip restrictions config for a tenant.
     *
     * @summary Get IP restriction configuration (ALLOW/BLOCK)
     */
    SDK.prototype.iPRestrictionsControllerV1_getIpRestrictionConfig = function () {
        return this.core.fetch('/resources/configurations/v1/restrictions/ip/config', 'get');
    };
    /**
     * This route gets the ip restrictions for a tenant.
     *
     * @summary Get all IP restrictions
     */
    SDK.prototype.iPRestrictionsControllerV1_getAllIpRestrictions = function (metadata) {
        return this.core.fetch('/resources/configurations/v1/restrictions/ip', 'get', metadata);
    };
    /**
     * This route creates or updates ip restriction for a tenant. Send values in the POST body
     * as objects. See the dropdowns for available values for each object param.
     *
     * @summary Create IP restriction
     */
    SDK.prototype.iPRestrictionsControllerV1_createIpRestriction = function (body) {
        return this.core.fetch('/resources/configurations/v1/restrictions/ip', 'post', body);
    };
    /**
     * This route checks if current ip is allowed.
     *
     * @summary Test Current IP
     */
    SDK.prototype.iPRestrictionsControllerV1_testCurrentIp = function () {
        return this.core.fetch('/resources/configurations/v1/restrictions/ip/verify', 'post');
    };
    /**
     * This route checks if current ip is active in the allow list.
     *
     * @summary Test current IP is in allow list
     */
    SDK.prototype.testCurrentIpInAllowList = function () {
        return this.core.fetch('/resources/configurations/v1/restrictions/ip/verify/allow', 'post');
    };
    /**
     * This route deletes ip restriction.
     *
     * @summary Delete IP restriction by IP
     */
    SDK.prototype.iPRestrictionsControllerV1_deleteIpRestrictionById = function (metadata) {
        return this.core.fetch('/resources/configurations/v1/restrictions/ip/{id}', 'delete', metadata);
    };
    /**
     * This route creates a lockout policy for all tenants. To create a lockout policy for a
     * specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header. To enable
     * the Lockout Policy, make sure to set the enabled variable to true and the maximum
     * attempts to a number of your preference.
     *
     * @summary Create lockout policy
     */
    SDK.prototype.lockoutPolicyController_createLockoutPolicy = function (body, metadata) {
        return this.core.fetch('/resources/configurations/v1/lockout-policy', 'post', body, metadata);
    };
    /**
     * This route updates a lockout policy for all tenants. To update a lockout policy for a
     * specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header. To disable
     * the lockout policy, make sure to set the enabled variable to false. The maximum attempts
     * variable can also be changed to a number of your preference
     *
     * @summary Update lockout policy
     */
    SDK.prototype.lockoutPolicyController_updateLockoutPolicy = function (body, metadata) {
        return this.core.fetch('/resources/configurations/v1/lockout-policy', 'patch', body, metadata);
    };
    /**
     * This route gets the lockout policy for all tenants or one tenant specifically. To get
     * the lockout policy for a specific tenant, send the tenant’s ID in the
     * **`frontegg-tenant-id`** header.
     *
     * @summary Get lockout policy
     */
    SDK.prototype.lockoutPolicyController_getLockoutPolicy = function (metadata) {
        return this.core.fetch('/resources/configurations/v1/lockout-policy', 'get', metadata);
    };
    /**
     * This route creates the MFA policy globally or for a specific tenant. To create an MFA
     * policy for a specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`**
     * header.
     *
     * @summary Create MFA policy
     */
    SDK.prototype.securityPolicyController_createMfaPolicy = function (body, metadata) {
        return this.core.fetch('/resources/configurations/v1/mfa-policy', 'post', body, metadata);
    };
    /**
     * This route updates the MFA policy for all tenants. To update an MFA policy for a
     * specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header.
     *
     * @summary Update security policy
     */
    SDK.prototype.securityPolicyController_updateSecurityPolicy = function (body, metadata) {
        return this.core.fetch('/resources/configurations/v1/mfa-policy', 'patch', body, metadata);
    };
    /**
     * This route creates or updates the MFA policy for all tenants. To create or update an MFA
     * policy for a specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`**
     * header.
     *
     * @summary Upsert security policy
     */
    SDK.prototype.securityPolicyController_upsertSecurityPolicy = function (body, metadata) {
        return this.core.fetch('/resources/configurations/v1/mfa-policy', 'put', body, metadata);
    };
    /**
     * This route gets the MFA policy for all tenants. To get the MFA policy for a specific
     * tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header.
     *
     * @summary Get security policy
     */
    SDK.prototype.securityPolicyController_getSecurityPolicy = function (metadata) {
        return this.core.fetch('/resources/configurations/v1/mfa-policy', 'get', metadata);
    };
    /**
     * Get MFA strategies
     *
     */
    SDK.prototype.mFAStrategiesControllerV1_getMFAStrategies = function () {
        return this.core.fetch('/resources/configurations/v1/mfa/strategies', 'get');
    };
    /**
     * Create or update MFA strategy
     *
     */
    SDK.prototype.mFAStrategiesControllerV1_createOrUpdateMFAStrategy = function (body) {
        return this.core.fetch('/resources/configurations/v1/mfa/strategies', 'post', body);
    };
    /**
     * This route updates the password policy for all tenants. To update the password policy
     * for a specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header. Send
     * the updated values as POST body params.
     *
     * @summary Update password configuration
     */
    SDK.prototype.passwordPolicyController_addOrUpdatePasswordConfig = function (body, metadata) {
        return this.core.fetch('/resources/configurations/v1/password', 'post', body, metadata);
    };
    /**
     * This route gets the password policy for all tenants. To get the password policy for a
     * specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header.
     *
     * @summary Gets password policy configuration
     */
    SDK.prototype.passwordPolicyController_getPasswordConfig = function (metadata) {
        return this.core.fetch('/resources/configurations/v1/password', 'get', metadata);
    };
    /**
     * This route creates the password history policy for all tenants. To create a password
     * history policy for a specific tenant, send the tenant’s ID in the
     * **`frontegg-tenant-id`** header. To enable the Password History, make sure to set the
     * enabled variable to true and the password history size to a number between 1 to 10.
     *
     * @summary Create password history policy
     */
    SDK.prototype.passwordHistoryPolicyController_createPolicy = function (body, metadata) {
        return this.core.fetch('/resources/configurations/v1/password-history-policy', 'post', body, metadata);
    };
    /**
     * This route updates the password history policy for all tenants. To update a password
     * history policy for a specific tenant, send the tenant’s ID in the
     * **`frontegg-tenant-id`** header. To disable the password history policy, make sure to
     * set the enabled variable to false. The password history size can also be changed to a
     * number between 1 to 10
     *
     * @summary Update password history policy
     */
    SDK.prototype.passwordHistoryPolicyController_updatePolicy = function (body, metadata) {
        return this.core.fetch('/resources/configurations/v1/password-history-policy', 'patch', body, metadata);
    };
    /**
     * This route gets the password history policy for all tenants or one tenant specifically.
     * To create a password history policy for a specific tenant, send the tenant’s ID in the
     * **`frontegg-tenant-id`** header.
     *
     * @summary Get password history policy
     */
    SDK.prototype.passwordHistoryPolicyController_getPolicy = function (metadata) {
        return this.core.fetch('/resources/configurations/v1/password-history-policy', 'get', metadata);
    };
    /**
     * This route sends a reset password email to the user. Send the user’s email in the POST
     * body. If your email template uses metadata, send email metadata in the POST body, too.
     *
     * @summary Reset password
     */
    SDK.prototype.usersPasswordControllerV1_resetPassword = function (body) {
        return this.core.fetch('/resources/users/v1/passwords/reset', 'post', body);
    };
    /**
     * This route verifies a user’s password using a verification token. Send the userId,
     * token, and password in the POST body. For the token, see the route under users for
     * generating user password reset token.
     *
     * @summary Verify password
     */
    SDK.prototype.usersPasswordControllerV1_verifyResetPassword = function (body) {
        return this.core.fetch('/resources/users/v1/passwords/reset/verify', 'post', body);
    };
    /**
     * This route changes the password for a logged-in user. Send the **`frontegg-user-id`**
     * and **`frontegg-tenant-id`** headers to declare which user and which tenant. Send the
     * current and new passwords in the POST body.
     *
     * @summary Change password
     */
    SDK.prototype.usersPasswordControllerV1_changePassword = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/passwords/change', 'post', body, metadata);
    };
    /**
     * This route gets the user’s hardest password configuration. This is useful when a user
     * belongs to multiple tenants and does not have the same password complexity for all of
     * them. The route returns the strictest setting the user is subject to.
     *
     * @summary Get strictest password configuration
     */
    SDK.prototype.usersPasswordControllerV1_getUserPasswordConfig = function (metadata) {
        return this.core.fetch('/resources/users/v1/passwords/config', 'get', metadata);
    };
    /**
     * Create user access token
     *
     */
    SDK.prototype.userAccessTokensV1Controller_createUserAccessToken = function (body, metadata) {
        return this.core.fetch('/resources/users/access-tokens/v1', 'post', body, metadata);
    };
    /**
     * Get user access tokens
     *
     */
    SDK.prototype.userAccessTokensV1Controller_getUserAccessTokens = function (metadata) {
        return this.core.fetch('/resources/users/access-tokens/v1', 'get', metadata);
    };
    /**
     * Delete user access token by token ID
     *
     */
    SDK.prototype.userAccessTokensV1Controller_deleteUserAccessToken = function (metadata) {
        return this.core.fetch('/resources/users/access-tokens/v1/{id}', 'delete', metadata);
    };
    /**
     * This route creates a user-specific API token. Send the user’s ID in the
     * **`frontegg-user-id`** header and the tenant’s ID in the **`frontegg-tenant-id`**
     * header. Optionally, send as POST body params values for metadata and description.
     *
     * @summary Create user client credentials token
     */
    SDK.prototype.userApiTokensV1Controller_createTenantApiToken = function (body, metadata) {
        return this.core.fetch('/resources/users/api-tokens/v1', 'post', body, metadata);
    };
    /**
     * This route gets a user-specific API token. Send the user’s ID in the
     * **`frontegg-user-id`** header and the tenant’s ID in the **`frontegg-tenant-id`**
     * header.
     *
     * @summary Get user client credentials tokens
     */
    SDK.prototype.userApiTokensV1Controller_getApiTokens = function (metadata) {
        return this.core.fetch('/resources/users/api-tokens/v1', 'get', metadata);
    };
    /**
     * This route deletes a user-specific API token. Send the token as the ID path param. Send
     * the user’s ID in the **`frontegg-user-id`** header and the tenant’s ID in the
     * **`frontegg-tenant-id`** header. Optionally, send as POST body params values for
     * metadata and description.
     *
     * @summary Delete user client credentials token by token ID
     */
    SDK.prototype.userApiTokensV1Controller_deleteApiToken = function (metadata) {
        return this.core.fetch('/resources/users/api-tokens/v1/{id}', 'delete', metadata);
    };
    /**
     * This route returns all roles for vendor. Each role is an object containing the name,
     * permissions, and other defining information.
     *
     * @summary Get roles v2
     */
    SDK.prototype.permissionsControllerV2_getAllRoles = function (metadata) {
        return this.core.fetch('/resources/roles/v2', 'get', metadata);
    };
    /**
     * This route adds a new role for a specific tenant. Send the tenant ID in the
     * **`frontegg-tenant-id`** header. Add the required permissions within the request body to
     * customize the role.
     *
     * @summary Create a new role
     */
    SDK.prototype.rolesControllerV2_addRole = function (body, metadata) {
        return this.core.fetch('/resources/roles/v2', 'post', body, metadata);
    };
    /**
     * This route returns all levels from roles for vendor.
     *
     * @summary Get distinct levels of roles
     */
    SDK.prototype.rolesControllerV2_getDistinctLevels = function (metadata) {
        return this.core.fetch('/resources/roles/v2/distinct-levels', 'get', metadata);
    };
    /**
     * This route returns all assigned tenant ids from roles for vendor.
     *
     * @summary Get distinct assigned tenants of roles
     */
    SDK.prototype.rolesControllerV2_getDistinctTenants = function (metadata) {
        return this.core.fetch('/resources/roles/v2/distinct-tenants', 'get', metadata);
    };
    /**
     * This route gets the Session configuration for the entire environment or a specific
     * tenant. To get the Session configuration for a specific tenant, send the tenant’s id in
     * the **`frontegg-tenant-id`** header
     *
     * @summary Get tenant or vendor default session configuration
     */
    SDK.prototype.sessionConfigurationControllerV1_getSessionConfiguration = function (metadata) {
        return this.core.fetch('/resources/configurations/sessions/v1', 'get', metadata);
    };
    /**
     * This route creates or updates Session configuration for the entire environment or a
     * specific tenant. To update the Session configuration for a specific tenant, send the
     * tenant’s ID in the **`frontegg-tenant-id`** header
     *
     * @summary Create or update tenant or vendor default session configuration
     */
    SDK.prototype.sessionConfigurationControllerV1_createSessionConfiguration = function (body, metadata) {
        return this.core.fetch('/resources/configurations/sessions/v1', 'post', body, metadata);
    };
    /**
     * Create tenant access token
     *
     */
    SDK.prototype.tenantAccessTokensV1Controller_createTenantAccessToken = function (body, metadata) {
        return this.core.fetch('/resources/tenants/access-tokens/v1', 'post', body, metadata);
    };
    /**
     * Get tenant access tokens
     *
     */
    SDK.prototype.tenantAccessTokensV1Controller_getTenantAccessTokens = function (metadata) {
        return this.core.fetch('/resources/tenants/access-tokens/v1', 'get', metadata);
    };
    /**
     * Delete tenant access token
     *
     */
    SDK.prototype.tenantAccessTokensV1Controller_deleteTenantAccessToken = function (metadata) {
        return this.core.fetch('/resources/tenants/access-tokens/v1/{id}', 'delete', metadata);
    };
    /**
     * Do not use. Instead, use v2 of this route.
     *
     * @summary Create client credentials token
     */
    SDK.prototype.tenantApiTokensV1Controller_createTenantApiToken = function (body, metadata) {
        return this.core.fetch('/resources/tenants/api-tokens/v1', 'post', body, metadata);
    };
    /**
     * This route gets all API tokens for a specific tenant. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header.
     *
     * @summary Get client credentials tokens
     */
    SDK.prototype.tenantApiTokensV1Controller_getTenantsApiTokens = function (metadata) {
        return this.core.fetch('/resources/tenants/api-tokens/v1', 'get', metadata);
    };
    /**
     * This route deletes a tenant API token. Send the token ID as the path param. Send the
     * tenant’s ID in the **`frontegg-tenant-id`** header.
     *
     * @summary Delete client credentials token
     */
    SDK.prototype.tenantApiTokensV1Controller_deleteTenantApiToken = function (metadata) {
        return this.core.fetch('/resources/tenants/api-tokens/v1/{id}', 'delete', metadata);
    };
    /**
     * This route updates a tenant API token. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header. Optionally, send as POST body params values for
     * description, roles, and permissions for the token.
     *
     * @summary Update client credentials token
     */
    SDK.prototype.tenantApiTokensV1Controller_updateTenantApiToken = function (body, metadata) {
        return this.core.fetch('/resources/tenants/api-tokens/v1/{id}', 'patch', body, metadata);
    };
    /**
     * This route creates a tenant API token. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header. Optionally, send as POST body params values for
     * metadata, description, roles, and permissions for the token.</br></br>You can get roles
     * & permissions via API
     *
     * @summary Create client credentials token
     */
    SDK.prototype.tenantApiTokensV2Controller_createTenantApiToken = function (body, metadata) {
        return this.core.fetch('/resources/tenants/api-tokens/v2', 'post', body, metadata);
    };
    /**
     * This route updates the settings for temporary users, use it to enable or disable it for
     * an environment
     *
     * @summary Sets a permanent user to temporary
     */
    SDK.prototype.temporaryUsersV1Controller_editTimeLimit = function (body, metadata) {
        return this.core.fetch('/resources/users/temporary/v1/{userId}', 'put', body, metadata);
    };
    /**
     * This route sets an existing temporary user as permanent. Send the user’s ID as a path
     * params.
     *
     * @summary Sets a temporary user to permanent
     */
    SDK.prototype.temporaryUsersV1Controller_setUserPermanent = function (metadata) {
        return this.core.fetch('/resources/users/temporary/v1/{userId}', 'delete', metadata);
    };
    /**
     * This route resets the activation token for a user and triggers a new activation email
     * being sent to the user’s email.
     *
     * @summary Reset user activation token
     */
    SDK.prototype.usersActivationControllerV1_resetActivationToken = function (body) {
        return this.core.fetch('/resources/users/v1/activate/reset', 'post', body);
    };
    /**
     * This route resets an invitation for a user to join a specific tenant. Send the tenant’s
     * ID in the **`frontegg-tenant-id`** header and the user's email in the POST body. It
     * returns a new invitation link with a new token.
     *
     * @summary Reset invitation
     */
    SDK.prototype.usersTenantManagementControllerV1_resetTenantInvitationToken = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/invitation/reset', 'post', body, metadata);
    };
    /**
     * This route resets all invitation for a user to join all sub tenants which currently have
     * invitation token. Send the tenant’s ID in the **`frontegg-tenant-id`** header and the
     * user's email in the POST body. It returns a new invitation link with a new token.
     *
     * @summary Reset all invitation tokens
     */
    SDK.prototype.usersTenantManagementControllerV1_resetAllTenantsInvitationToken = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/invitation/reset/all', 'post', body, metadata);
    };
    /**
     * This route gets all users for a tenant/vendor. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header to declare which tenant or leave it empty for all
     * tenants' users
     *
     * @summary Get users
     */
    SDK.prototype.usersControllerV3_getUsers = function (metadata) {
        return this.core.fetch('/resources/users/v3', 'get', metadata);
    };
    /**
     * This route gets all users roles for a tenant. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header to declare which tenant.
     *
     * @summary Get users roles
     */
    SDK.prototype.usersControllerV3_getUsersRoles = function (metadata) {
        return this.core.fetch('/resources/users/v3/roles', 'get', metadata);
    };
    /**
     * This route gets all users groups for a tenant. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header to declare which tenant.
     *
     * @summary Get users groups
     */
    SDK.prototype.usersControllerV3_getUsersGroups = function (metadata) {
        return this.core.fetch('/resources/users/v3/groups', 'get', metadata);
    };
    /**
     * This route creates a user for a specific tenant. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header to declare to what tenant this user is assigned. Send
     * the user's information in the POST body. The user's email and metadata are required. The
     * metadata can be empty, like `{}`.
     *
     * @summary Invite user
     */
    SDK.prototype.usersControllerV2_createUser = function (body, metadata) {
        return this.core.fetch('/resources/users/v2', 'post', body, metadata);
    };
    /**
     * This route updates a logged-in user's profile. Send the updated values in the PUT body.
     * Mind to use your Frontegg subdomain/custom domain as a host. A user token is required
     * for this route. A user token can be obtained after user authentication.
     *
     * @summary Update user profile
     */
    SDK.prototype.usersControllerV2_updateUserProfile = function (body) {
        return this.core.fetch('/resources/users/v2/me', 'put', body);
    };
    /**
     * This route gets a logged-in user's profile. No params required. Mind to use your
     * Frontegg subdomain/custom domain as a host. A user token is required for this route. A
     * user token can be obtained after user authentication.
     *
     * @summary Get user profile
     */
    SDK.prototype.usersControllerV2_getUserProfile = function () {
        return this.core.fetch('/resources/users/v2/me', 'get');
    };
    /**
     * Use the V2 route for Invite User. This route is no longer relevant.
     *
     * @summary Create user
     */
    SDK.prototype.usersControllerV1_createUser = function (body, metadata) {
        return this.core.fetch('/resources/users/v1', 'post', body, metadata);
    };
    /**
     * Get Users v1
     *
     */
    SDK.prototype.usersControllerV1_getUsers = function (metadata) {
        return this.core.fetch('/resources/users/v1', 'get', metadata);
    };
    /**
     * This route updates a user’s information for a specific tenant. Send the
     * **`frontegg-user-id`** and **`frontegg-tenant-id`** headers to declare which user and
     * which tenant.
     *
     * @summary Update user
     */
    SDK.prototype.usersControllerV1_updateUser = function (body, metadata) {
        return this.core.fetch('/resources/users/v1', 'put', body, metadata);
    };
    /**
     * This route associates roles to a specific user for a specific tenant. Send the tenant’s
     * ID in the **`frontegg-tenant-id`** header to declare which tenant. Send the role IDs in
     * the POST body. The role IDs need to be an array of strings. Also send the user's ID as a
     * path params.
     *
     * @summary Assign roles to user
     */
    SDK.prototype.usersControllerV1_addRolesToUser = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/roles', 'post', body, metadata);
    };
    /**
     * This route disassociates roles from a specific user for a specific tenant. Send the
     * tenant’s ID in the **`frontegg-tenant-id`** header to declare which tenant. Send the
     * role IDs in the POST body. The role IDs need to be an array of strings. Also send the
     * user's ID as a path params.
     *
     * @summary Unassign roles from user
     */
    SDK.prototype.usersControllerV1_deleteRolesFromUser = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/{userId}/roles', 'delete', body, metadata);
    };
    /**
     * This route updates the logged in user’s tenant . The user uses it when they have
     * multiple tenants and they want to change the current tenant they log in to. Send the
     * **`frontegg-user-id`** and **`frontegg-tenant-id`** headers to declare which user and
     * which tenant. Send the tenant ID in the POST body.
     *
     * @summary Update user's active tenant
     */
    SDK.prototype.usersControllerV1_updateUserTenant = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/tenant', 'put', body, metadata);
    };
    /**
     * This route activates a non-activated user. You can use it to create your own activation
     * flow. Send the **`frontegg-vendor-host`** as a header to declare which vendor. This is
     * your domain name in the Frontegg Portal ➜ Workspace Settings ➜ Domains ➜ Domain Name.
     * Send the required userId and activation token in the POST body. For generating an
     * activation token, see the route under users for generating an activation token. If the
     * vendor's sign in flow requires a password or recaptcha, send those values in the POST
     * body. Instead of this route, consider using our email template for user activation.
     *
     * @summary Activate user
     */
    SDK.prototype.usersActivationControllerV1_activateUser = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/activate', 'post', body, metadata);
    };
    /**
     * This route gets a user’s activation strategy. The activation strategy tells the vendor
     * whether the user needs to set a password. Send the required userId and activation token
     * in the POST body. For the activation token, see the route under users for generating an
     * activation token. The route returns a Boolean called shouldSetPassword. If it is true,
     * the user needs to to set a password. If it is false, the user does not need to set a
     * password. For instance, SSO users do not set passwords.
     *
     * @summary Get user activation strategy
     */
    SDK.prototype.usersActivationControllerV1_getActivationStrategy = function (metadata) {
        return this.core.fetch('/resources/users/v1/activate/strategy', 'get', metadata);
    };
    /**
     * This route accepts an invitation for a user to join a specific tenant. Send the required
     * userId and activation token in the POST body. The userId and activation token appear as
     * a query params in the url Frontegg sends to the user in the activation email.
     *
     * @summary Accept invitation
     */
    SDK.prototype.usersTenantManagementControllerV1_acceptInvitation = function (body) {
        return this.core.fetch('/resources/users/v1/invitation/accept', 'post', body);
    };
    /**
     * This route is for signing up a new user and new tenant. Send the
     * **`frontegg-vendor-host`** header. This is your domain name in the Frontegg Portal ➜
     * Workspace Settings ➜ Domains ➜ Domain Name. Send the user's information in the POST
     * body. The user's email, provider, companyName, and metadata are required. The provider
     * is the authentication provider, like local, saml, google, github. See the dropdown for
     * available values. The metadata can be empty, like `{}`. You also can send in the POST
     * body additional information as shown in the example. A vendor token is required for this
     * route, it can be obtained from the vendor authentication route.
     *
     * @summary Signup user
     */
    SDK.prototype.usersControllerV1_signUpUser = function (body, metadata) {
        return this.core.fetch('/resources/users/v1/signUp', 'post', body, metadata);
    };
    /**
     * This route gets a logged-in user's profile. No params required. Mind to use your
     * Frontegg subdomain/custom domain as a host. A user token is required for this route. A
     * user token can be obtained after user authentication.
     *
     * @summary Get user profile
     */
    SDK.prototype.usersControllerV3_getUserProfile = function () {
        return this.core.fetch('/resources/users/v3/me', 'get');
    };
    /**
     * This route gets the list of tenants that a logged-in user belongs to. No params
     * required. Mind to use your Frontegg subdomain/custom domain as a host. A user token is
     * required for this route. A user token can be obtained after user authentication.
     *
     * @summary Get user tenants
     */
    SDK.prototype.usersControllerV2_getUserTenants = function (metadata) {
        return this.core.fetch('/resources/users/v2/me/tenants', 'get', metadata);
    };
    /**
     * This route gets the list of tenants with hierarchy metadata that a logged-in user
     * belongs to. If the user is a member of several tenants in a tree some might be reduced.
     * No params required. Mind to use your Frontegg subdomain/custom domain as a host. A user
     * token is required for this route. A user token can be obtained after user
     * authentication.
     *
     * @summary Get user tenants' hierarchy
     */
    SDK.prototype.usersControllerV2_getUserTenantsHierarchy = function () {
        return this.core.fetch('/resources/users/v2/me/hierarchy', 'get');
    };
    /**
     * This route gets the list of permissions and roles that a logged-in user has. No params
     * required. Mind to use your Frontegg subdomain/custom domain as a host. A user token is
     * required for this route. A user token can be obtained after user authentication.
     *
     * @summary Get user permissions and roles
     */
    SDK.prototype.usersControllerV1_getMeAuthorization = function () {
        return this.core.fetch('/resources/users/v1/me/authorization', 'get');
    };
    /**
     * This route gets the list of tenants that a logged-in user belongs to. No params
     * required. Mind to use your Frontegg subdomain/custom domain as a host. A user token is
     * required for this route. A user token can be obtained after user authentication.
     *
     * @summary Get user tenants
     */
    SDK.prototype.usersControllerV1_getUserTenants = function () {
        return this.core.fetch('/resources/users/v1/me/tenants', 'get');
    };
    /**
     * This route returns all the user's active sessions. Specify the user by sending its ID in
     * frontegg-user-id header.
     *
     * @summary Get user's active sessions
     */
    SDK.prototype.userSessionsControllerV1_getActiveSessions = function (metadata) {
        return this.core.fetch('/resources/users/sessions/v1/me', 'get', metadata);
    };
    /**
     * This route deletes all user's session. Specify the user by sending its ID in
     * frontegg-user-id header.
     *
     * @summary Delete all user sessions
     */
    SDK.prototype.userSessionsControllerV1_deleteAllUserActiveSessions = function (metadata) {
        return this.core.fetch('/resources/users/sessions/v1/me/all', 'delete', metadata);
    };
    /**
     * This route deletes user's session. Specify the user by sending its ID in
     * frontegg-user-id header and the session ID in the url param.
     *
     * @summary Delete single user's session
     */
    SDK.prototype.userSessionsControllerV1_deleteUserSession = function (metadata) {
        return this.core.fetch('/resources/users/sessions/v1/me/{id}', 'delete', metadata);
    };
    return SDK;
}());
var createSDK = (function () { return new SDK(); })();
module.exports = createSDK;
