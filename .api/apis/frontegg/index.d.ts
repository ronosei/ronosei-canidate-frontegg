import type * as types from './types';
import type { ConfigOptions, FetchResponse } from 'api/dist/core';
import Oas from 'oas';
import APICore from 'api/dist/core';
declare class SDK {
    spec: Oas;
    core: APICore;
    constructor();
    /**
     * Optionally configure various options that the SDK allows.
     *
     * @param config Object of supported SDK options and toggles.
     * @param config.timeout Override the default `fetch` request timeout of 30 seconds. This number
     * should be represented in milliseconds.
     */
    config(config: ConfigOptions): void;
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
    auth(...values: string[] | number[]): this;
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
    server(url: string, variables?: {}): void;
    /**
     * This route gets users for an application.
     *
     * @summary Get users for application
     */
    applicationsControllerV1_getUsersForApplication(metadata: types.ApplicationsControllerV1GetUsersForApplicationMetadataParam): Promise<FetchResponse<200, types.ApplicationsControllerV1GetUsersForApplicationResponse200>>;
    /**
     * This route gets applications for a user.
     *
     * @summary Get applications for user
     */
    applicationsControllerV1_getApplicationsForUser(metadata: types.ApplicationsControllerV1GetApplicationsForUserMetadataParam): Promise<FetchResponse<200, types.ApplicationsControllerV1GetApplicationsForUserResponse200>>;
    /**
     * This route gets applications for multiple users.
     *
     * @summary Get applications for multiple users
     */
    applicationsControllerV1_getApplicationsForMultipleUsers(metadata: types.ApplicationsControllerV1GetApplicationsForMultipleUsersMetadataParam): Promise<FetchResponse<200, types.ApplicationsControllerV1GetApplicationsForMultipleUsersResponse200>>;
    /**
     * This route gets users for multiple applications.
     *
     * @summary Get users for multiple applications
     */
    applicationsControllerV1_getUsersForMultipleApplications(metadata: types.ApplicationsControllerV1GetUsersForMultipleApplicationsMetadataParam): Promise<FetchResponse<200, types.ApplicationsControllerV1GetUsersForMultipleApplicationsResponse200>>;
    /**
     * This route assigns users to an application.
     *
     * @summary Assign users to application
     */
    applicationsControllerV1_assignUsersToApplication(body: types.ApplicationsControllerV1AssignUsersToApplicationBodyParam): Promise<FetchResponse<200, types.ApplicationsControllerV1AssignUsersToApplicationResponse200> | FetchResponse<201, types.ApplicationsControllerV1AssignUsersToApplicationResponse201>>;
    /**
     * This route unassigns users from an application.
     *
     * @summary Unassign users from application
     */
    applicationsControllerV1_unassignUsersFromApplication(body: types.ApplicationsControllerV1UnassignUsersFromApplicationBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route assigns user to multiple applications.
     *
     * @summary Assign user to multiple applications
     */
    applicationsControllerV1_assignUserToMultipleApplications(body: types.ApplicationsControllerV1AssignUserToMultipleApplicationsBodyParam): Promise<FetchResponse<200, types.ApplicationsControllerV1AssignUserToMultipleApplicationsResponse200> | FetchResponse<201, types.ApplicationsControllerV1AssignUserToMultipleApplicationsResponse201>>;
    /**
     * This route unassigns user from multiple applications.
     *
     * @summary Unassign user from multiple applications
     */
    applicationsControllerV1_unassignUserFromMultipleApplications(body: types.ApplicationsControllerV1UnassignUserFromMultipleApplicationsBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets the active user tenants for an application.
     *
     * @summary Get user active tenants in applications
     */
    applicationsActiveUserTenantsControllerV1_getUserApplicationActiveTenants(metadata: types.ApplicationsActiveUserTenantsControllerV1GetUserApplicationActiveTenantsMetadataParam): Promise<FetchResponse<200, types.ApplicationsActiveUserTenantsControllerV1GetUserApplicationActiveTenantsResponse200>>;
    /**
     * This route updates the active user tenants for an application.
     *
     * @summary Switch users active tenant in applications
     */
    applicationsActiveUserTenantsControllerV1_switchUserApplicationActiveTenant(body: types.ApplicationsActiveUserTenantsControllerV1SwitchUserApplicationActiveTenantBodyParam, metadata: types.ApplicationsActiveUserTenantsControllerV1SwitchUserApplicationActiveTenantMetadataParam): Promise<FetchResponse<number, unknown>>;
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
    authenticationApiTokenControllerV2_authApiToken(body: types.AuthenticationApiTokenControllerV2AuthApiTokenBodyParam): Promise<FetchResponse<200, types.AuthenticationApiTokenControllerV2AuthApiTokenResponse200>>;
    /**
     * This route refreshes a JWT using the refresh token value. If the refresh token is valid,
     * the route returns a new JWT and refresh token. Send the **`frontegg-vendor-host`** as a
     * header to declare which vendor. This is your domain name in the Frontegg Portal ➜
     * Workspace Settings ➜ Domains ➜ Domain Name.
     *
     * @summary Refresh API token
     */
    authenticationApiTokenControllerV2_refreshToken(body: types.AuthenticationApiTokenControllerV2RefreshTokenBodyParam): Promise<FetchResponse<200, types.AuthenticationApiTokenControllerV2RefreshTokenResponse200>>;
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
    authenticatioAuthenticationControllerV1_authenticateLocalUser(body: types.AuthenticatioAuthenticationControllerV1AuthenticateLocalUserBodyParam, metadata?: types.AuthenticatioAuthenticationControllerV1AuthenticateLocalUserMetadataParam): Promise<FetchResponse<200, types.AuthenticatioAuthenticationControllerV1AuthenticateLocalUserResponse200>>;
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
    authenticatioAuthenticationControllerV1_refreshToken(body: types.AuthenticatioAuthenticationControllerV1RefreshTokenBodyParam, metadata: types.AuthenticatioAuthenticationControllerV1RefreshTokenMetadataParam): Promise<FetchResponse<201, types.AuthenticatioAuthenticationControllerV1RefreshTokenResponse201>>;
    /**
     * This route logs out a user using the refresh token that is passed as a cookie. Send the
     * **`frontegg-vendor-host`** as a header to declare which vendor. This route is designed
     * for Frontegg embedded login or integrations that use only Frontegg APIs
     *
     * @summary Logout user
     */
    authenticatioAuthenticationControllerV1_logout(metadata: types.AuthenticatioAuthenticationControllerV1LogoutMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route recovers MFA for a non logged-in user. Send the user’s email and a recovery
     * code as params in the POST body. The recovery code comes from the MFA authenticator app
     * when you set up MFA.
     *
     * @summary Recover MFA
     */
    authenticationMFAControllerV1_recoverMfa(body: types.AuthenticationMfaControllerV1RecoverMfaBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route disables MFA enrollment for a logged-in user for a specific tenant. Send the
     * **`frontegg-user-id`** header to declare which user. The MFA token should be obtained
     * from the authenticator app. A vendor token is required for this route, it can be
     * obtained from the vendor authentication route.
     *
     * @summary Disable authenticator app MFA
     */
    usersMfaControllerV1_disableAuthAppMfa(body: types.UsersMfaControllerV1DisableAuthAppMfaBodyParam, metadata: types.UsersMfaControllerV1DisableAuthAppMfaMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route disables MFA enrollment for a logged-in user for a specific tenant. Send the
     * **`frontegg-user-id`** header to declare which user. The MFA token should be obtained
     * from the authenticator app. A vendor token is required for this route, it can be
     * obtained from the vendor authentication route.
     *
     * @summary Disable authenticator app MFA
     */
    usersMfaControllerV1_disableAuthenticatorMfa(body: types.UsersMfaControllerV1DisableAuthenticatorMfaBodyParam, metadata: types.UsersMfaControllerV1DisableAuthenticatorMfaMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Pre-disable SMS MFA
     *
     */
    usersMfaControllerV1_preDisableSMSMfa(body: types.UsersMfaControllerV1PreDisableSmsMfaBodyParam, metadata: types.UsersMfaControllerV1PreDisableSmsMfaMetadataParam): Promise<FetchResponse<200, types.UsersMfaControllerV1PreDisableSmsMfaResponse200>>;
    /**
     * Disable SMS MFA
     *
     */
    usersMfaControllerV1_disableSMSMfa(body: types.UsersMfaControllerV1DisableSmsMfaBodyParam, metadata: types.UsersMfaControllerV1DisableSmsMfaMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route verifies the MFA code from an authenticator app. Send the
     * **`frontegg-vendor-host`** as a header. This is your domain name in the Frontegg Portal
     * ➜ Workspace Settings ➜ Domains ➜ Domain Name. Send information required for MFA in the
     * POST body. The `value` is the service name from your Authentication Settings in the
     * Frontegg Portal. The MFA token is from the authenticator app.
     *
     * @summary Verify MFA using code from authenticator app
     */
    authenticationMFAControllerV1_verifyAuthenticatorMfaCode(body: types.AuthenticationMfaControllerV1VerifyAuthenticatorMfaCodeBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Request verify MFA using email code
     *
     */
    authenticationMFAControllerV1_preVerifyEmailOtcMfa(body: types.AuthenticationMfaControllerV1PreVerifyEmailOtcMfaBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Verify MFA using email code
     *
     */
    authenticationMFAControllerV1_verifyEmailOtcMfa(body: types.AuthenticationMfaControllerV1VerifyEmailOtcMfaBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Pre enroll MFA using Authenticator App
     *
     */
    authenticationMFAControllerV1_preEnrollAuthenticatorMfa(body: types.AuthenticationMfaControllerV1PreEnrollAuthenticatorMfaBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Enroll MFA using Authenticator App
     *
     */
    authenticationMFAControllerV1_enrollAuthenticatorMfa(body: types.AuthenticationMfaControllerV1EnrollAuthenticatorMfaBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route verifies MFA as part of the authentication process. Send the
     * **`frontegg-vendor-host`** as a header. This is your domain name in the Frontegg Portal
     * ➜ Workspace Settings ➜ Domains ➜ Domain Name. Send information required for MFA in the
     * POST body. The `value` is the service name from your Authentication Settings in the
     * Frontegg Portal. The MFA token is from the authenticator app.
     *
     * @summary Verify MFA using authenticator app
     */
    authenticationMFAControllerV1_verifyAuthenticatorMfa(body: types.AuthenticationMfaControllerV1VerifyAuthenticatorMfaBodyParam, metadata: types.AuthenticationMfaControllerV1VerifyAuthenticatorMfaMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Pre-enroll MFA using sms
     *
     */
    authenticationMFAControllerV1_preEnrollSmsMfa(body: types.AuthenticationMfaControllerV1PreEnrollSmsMfaBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Enroll MFA using sms
     *
     */
    authenticationMFAControllerV1_enrollSmsMfa(body: types.AuthenticationMfaControllerV1EnrollSmsMfaBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Request to verify MFA using sms
     *
     */
    authenticationMFAControllerV1_preVerifySmsMfa(body: types.AuthenticationMfaControllerV1PreVerifySmsMfaBodyParam, metadata: types.AuthenticationMfaControllerV1PreVerifySmsMfaMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Verify MFA using sms
     *
     */
    authenticationMFAControllerV1_verifySmsMfa(body: types.AuthenticationMfaControllerV1VerifySmsMfaBodyParam, metadata: types.AuthenticationMfaControllerV1VerifySmsMfaMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Pre enroll MFA using WebAuthN
     *
     */
    authenticationMFAControllerV1_preEnrollWebauthnMfa(body: types.AuthenticationMfaControllerV1PreEnrollWebauthnMfaBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Enroll MFA using WebAuthN
     *
     */
    authenticationMFAControllerV1_enrollWebauthnMfa(body: types.AuthenticationMfaControllerV1EnrollWebauthnMfaBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Request verify MFA using WebAuthN
     *
     */
    authenticationMFAControllerV1_preVerifyWebauthnMfa(body: types.AuthenticationMfaControllerV1PreVerifyWebauthnMfaBodyParam, metadata: types.AuthenticationMfaControllerV1PreVerifyWebauthnMfaMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Verify MFA using webauthn
     *
     */
    authenticationMFAControllerV1_verifyWebauthnMfa(body: types.AuthenticationMfaControllerV1VerifyWebauthnMfaBodyParam, metadata: types.AuthenticationMfaControllerV1VerifyWebauthnMfaMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route checks if remember device is allowed for all tenants. To check if remember
     * device is allowed for a specific tenant, send the tenant’s ID in the
     * **`frontegg-tenant-id`** header. Get the mfa token from the authenticator app and send
     * it as a query params.
     *
     * @summary Check if remember device allowed
     */
    securityPolicyController_checkIfAllowToRememberDevice(metadata: types.SecurityPolicyControllerCheckIfAllowToRememberDeviceMetadataParam): Promise<FetchResponse<200, types.SecurityPolicyControllerCheckIfAllowToRememberDeviceResponse200>>;
    /**
     * This route enrolls MFA for a logged-in user for a specific tenant. Send the
     * **`frontegg-user-id`** header to declare which user. A vendor token is required for this
     * route, it can be obtained from the vendor authentication route.
     *
     * @summary Enroll authenticator app MFA
     */
    usersMfaControllerV1_enrollAuthAppMfa(metadata: types.UsersMfaControllerV1EnrollAuthAppMfaMetadataParam): Promise<FetchResponse<200, types.UsersMfaControllerV1EnrollAuthAppMfaResponse200>>;
    /**
     * This route enrolls MFA for a logged-in user for a specific tenant. Send the
     * **`frontegg-user-id`** header to declare which user. A vendor token is required for this
     * route, it can be obtained from the vendor authentication route.
     *
     * @summary Enroll authenticator app MFA
     */
    usersMfaControllerV1_enrollAuthenticatorMfa(metadata: types.UsersMfaControllerV1EnrollAuthenticatorMfaMetadataParam): Promise<FetchResponse<200, types.UsersMfaControllerV1EnrollAuthenticatorMfaResponse200>>;
    /**
     * This route verifies MFA enrollment using a QR code. Send the **`frontegg-user-id`**
     * header to declare which user. Send information required for MFA in the POST body. The
     * MFA token should be obtained from the authenticator app after scanning the QR code
     * received . A vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Verify authenticator app MFA enrollment
     */
    usersMfaControllerV1_verifyAuthAppMfaEnrollment(body: types.UsersMfaControllerV1VerifyAuthAppMfaEnrollmentBodyParam, metadata: types.UsersMfaControllerV1VerifyAuthAppMfaEnrollmentMetadataParam): Promise<FetchResponse<200, types.UsersMfaControllerV1VerifyAuthAppMfaEnrollmentResponse200>>;
    /**
     * This route verifies MFA enrollment using a QR code. Send the **`frontegg-user-id`**
     * header to declare which user. Send information required for MFA in the POST body. The
     * MFA token should be obtained from the authenticator app after scanning the QR code
     * received . A vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Verify authenticator app MFA enrollment
     */
    usersMfaControllerV1_verifyAuthenticatorMfaEnrollment(body: types.UsersMfaControllerV1VerifyAuthenticatorMfaEnrollmentBodyParam, metadata: types.UsersMfaControllerV1VerifyAuthenticatorMfaEnrollmentMetadataParam): Promise<FetchResponse<200, types.UsersMfaControllerV1VerifyAuthenticatorMfaEnrollmentResponse200>>;
    /**
     * Enroll SMS MFA
     *
     */
    usersMfaControllerV1_preEnrollSmsMfa(body: types.UsersMfaControllerV1PreEnrollSmsMfaBodyParam, metadata: types.UsersMfaControllerV1PreEnrollSmsMfaMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Verify MFA enrollment
     *
     */
    usersMfaControllerV1_enrollSmsMfa(body: types.UsersMfaControllerV1EnrollSmsMfaBodyParam, metadata: types.UsersMfaControllerV1EnrollSmsMfaMetadataParam): Promise<FetchResponse<number, unknown>>;
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
    authenticationPasswordlessControllerV1_smsCodePreLogin(body: types.AuthenticationPasswordlessControllerV1SmsCodePreLoginBodyParam): Promise<FetchResponse<201, types.AuthenticationPasswordlessControllerV1SmsCodePreLoginResponse201>>;
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
    authenticationPasswordlessControllerV1_smsCodePostLogin(body: types.AuthenticationPasswordlessControllerV1SmsCodePostLoginBodyParam): Promise<FetchResponse<201, types.AuthenticationPasswordlessControllerV1SmsCodePostLoginResponse201>>;
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
    authenticationPasswordlessControllerV1_magicLinkPrelogin(body: types.AuthenticationPasswordlessControllerV1MagicLinkPreloginBodyParam): Promise<FetchResponse<number, unknown>>;
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
    authenticationPasswordlessControllerV1_magicLinkPostLogin(body: types.AuthenticationPasswordlessControllerV1MagicLinkPostLoginBodyParam): Promise<FetchResponse<201, types.AuthenticationPasswordlessControllerV1MagicLinkPostLoginResponse201>>;
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
    authenticationPasswordlessControllerV1_emailCodePrelogin(body: types.AuthenticationPasswordlessControllerV1EmailCodePreloginBodyParam): Promise<FetchResponse<number, unknown>>;
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
    authenticationPasswordlessControllerV1_emailCodePostLogin(body: types.AuthenticationPasswordlessControllerV1EmailCodePostLoginBodyParam): Promise<FetchResponse<201, types.AuthenticationPasswordlessControllerV1EmailCodePostLoginResponse201>>;
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
    tenantInvitesController_createTenantInvite(body: types.TenantInvitesControllerCreateTenantInviteBodyParam): Promise<FetchResponse<201, types.TenantInvitesControllerCreateTenantInviteResponse201>>;
    /**
     * This route gets all invitations for all tenants. A vendor token is required for this
     * route, it can be obtained from the vendor authentication route.
     *
     * @summary Get all tenant invites
     */
    tenantInvitesController_getAllInvites(): Promise<FetchResponse<200, types.TenantInvitesControllerGetAllInvitesResponse200>>;
    /**
     * This route deletes an invitation to join a tenant using the invitation ID. You can find
     * it via the Get all tenant invites API. Send the invitation ID as a path param - you can
     * get if via the **Get all tenant invites** API. A vendor token is required for this
     * route, it can be obtained from the vendor authentication route.
     *
     * @summary Delete a tenant invite
     */
    tenantInvitesController_deleteTenantInvite(metadata: types.TenantInvitesControllerDeleteTenantInviteMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route updates the identity management configuration for a vendor. Send values in
     * the POST body for params that you want to add or update. See the dropdown for available
     * values for each param.
     *
     * @summary Update identity management configuration
     */
    vendorConfigController_addOrUpdateConfig(body: types.VendorConfigControllerAddOrUpdateConfigBodyParam): Promise<FetchResponse<201, types.VendorConfigControllerAddOrUpdateConfigResponse201>>;
    /**
     * This route gets the identity management configuration for a vendor.
     *
     * @summary Get identity management configuration
     */
    vendorConfigController_getVendorConfig(): Promise<FetchResponse<200, types.VendorConfigControllerGetVendorConfigResponse200>>;
    /**
     * This route creates a captcha policy for all tenants. To enable the Captcha Policy, make
     * sure to set the enabled variable to true, the site key and secret key to the ones you
     * got from reCaptcha and the minimum score to a number between 0 to 1.
     *
     * @summary Create captcha policy
     */
    captchaPolicyController_createCaptchaPolicy(body: types.CaptchaPolicyControllerCreateCaptchaPolicyBodyParam): Promise<FetchResponse<201, types.CaptchaPolicyControllerCreateCaptchaPolicyResponse201>>;
    /**
     * This route updates a captcha policy for all tenants. To enable the Captcha Policy, make
     * sure to set the enabled variable to true, the site key and secret key to the ones you
     * got from reCaptcha and the minimum score to a number between 0 to 1.
     *
     * @summary Update captcha policy
     */
    captchaPolicyController_updateCaptchaPolicy(body: types.CaptchaPolicyControllerUpdateCaptchaPolicyBodyParam): Promise<FetchResponse<200, types.CaptchaPolicyControllerUpdateCaptchaPolicyResponse200>>;
    /**
     * This route gets the captcha policy. It returns the policy’s ID, site key, secret key,
     * minimum score and ignored emails and wether the .
     *
     * @summary Get captcha policy
     */
    captchaPolicyController_getCaptchaPolicy(): Promise<FetchResponse<200, types.CaptchaPolicyControllerGetCaptchaPolicyResponse200>>;
    /**
     * This route creates a custom social login provider using OAuth details of the identity
     * provider
     *
     * @summary Create custom oauth provider
     */
    ssoV2Controller_createSsoProvider(body: types.SsoV2ControllerCreateSsoProviderBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route fetches the custom social login providers on an environment
     *
     * @summary Get custom oauth provider
     */
    ssoV2Controller_getSsoProviders(): Promise<FetchResponse<number, unknown>>;
    /**
     * This route updates the custom social login provider on an environment by ID
     *
     * @summary Update custom oauth provider
     */
    ssoV2Controller_updateSsoProvider(body: types.SsoV2ControllerUpdateSsoProviderBodyParam, metadata: types.SsoV2ControllerUpdateSsoProviderMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route deletes the custom social login provider on an environment by ID
     *
     * @summary Delete custom oauth provider
     */
    ssoV2Controller_deleteSsoProvider(metadata: types.SsoV2ControllerDeleteSsoProviderMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route enables you to migrate your users from Auth0 to Frontegg easily. Add the
     * Domain, Client ID, Secret and the tenant’s ID Field Name - they’ll be found on Auth0 and
     * the migration will be as smooth as possible.
     *
     * @summary Migrate from Auth0
     */
    usersControllerV1_migrateUserFromAuth0(body: types.UsersControllerV1MigrateUserFromAuth0BodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route enables you to migrate a user by sending the following required fields:
     * user’s email, their tenantId and metadata, a new user will be created. This endpoint
     * takes other properties as well, such as the user’s name, their phone number, hashed
     * password, etc...
     *
     * @summary Migrate a vendor user
     */
    usersControllerV1_migrateUserForVendor(body: types.UsersControllerV1MigrateUserForVendorBodyParam): Promise<FetchResponse<201, types.UsersControllerV1MigrateUserForVendorResponse201>>;
    /**
     * This route enables you to migrate users in bulk. Expects an array of `users`. Each entry
     * must include a user's `email` and `tenantId`, which specifies that user's parent
     * account. Use the the other fields as needed to store additional information. We
     * recommend using the `metadata` property if you need to store custom information in a
     * user's object.
     *
     * @summary Migrate vendor users in bulk
     */
    usersControllerV1_bulkMigrateUserForVendor(body: types.UsersControllerV1BulkMigrateUserForVendorBodyParam): Promise<FetchResponse<202, types.UsersControllerV1BulkMigrateUserForVendorResponse202>>;
    /**
     * This route returns the status of a pending or completed migration. The payload includes
     * the migration's current `state`, the number of migrated users, and any errors that
     * occured during migration. Payload is limited to 1,000 users.
     *
     * @summary Check status of bulk migration
     */
    usersControllerV1_checkBulkMigrationStatus(metadata: types.UsersControllerV1CheckBulkMigrationStatusMetadataParam): Promise<FetchResponse<200, types.UsersControllerV1CheckBulkMigrationStatusResponse200>>;
    /**
     * Get information about the delegation configuration (if enabled). A [vendor
     * token](/reference/authenticate_vendor) is required for this route.
     *
     * @summary Get delegation donfiguration
     */
    delegationConfigurationControllerV1_getDelegationConfiguration(): Promise<FetchResponse<200, types.DelegationConfigurationControllerV1GetDelegationConfigurationResponse200>>;
    /**
     * Enable or disable the ability to use delegation in a token exchange flow. A [vendor
     * token](/reference/authenticate_vendor) is required for this route.
     *
     * @summary Create or update a delegation configuration
     */
    delegationConfigurationControllerV1_createOrUpdateDelegationConfiguration(body: types.DelegationConfigurationControllerV1CreateOrUpdateDelegationConfigurationBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Frontegg sends emails via SendGrid. If you already have an account on SendGrid and you
     * wish emails to be sent from your SendGrid account, pass the SendGrid secret key as a
     * body param. A vendor token is required for this route, it can be obtained from the
     * vendor authentication route.
     *
     * @summary Create or update configuration
     */
    mailConfigController_createOrUpdateMailConfig(body: types.MailConfigControllerCreateOrUpdateMailConfigBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route returns the mail configuration setup on Frontegg for your SendGrid account. A
     * vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Get configuration
     */
    mailConfigController_getMailConfig(): Promise<FetchResponse<200, types.MailConfigControllerGetMailConfigResponse200>>;
    /**
     * A vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Delete configuration
     */
    mailConfigController_deleteMailConfig(): Promise<FetchResponse<number, unknown>>;
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
    mailV1Controller_addOrUpdateTemplate(body: types.MailV1ControllerAddOrUpdateTemplateBodyParam): Promise<FetchResponse<201, types.MailV1ControllerAddOrUpdateTemplateResponse201>>;
    /**
     * This route gets all the vendor’s email templates. In order to get a specific template,
     * pass its type as a query param. A vendor token is required for this route, it can be
     * obtained from the vendor authentication route.
     *
     * @summary Get template
     */
    mailV1Controller_getTemplateConfiguration(metadata?: types.MailV1ControllerGetTemplateConfigurationMetadataParam): Promise<FetchResponse<200, types.MailV1ControllerGetTemplateConfigurationResponse200>>;
    /**
     * This route deletes specified email template. Select the email template using the ID of
     * the template - which can be obtained via the **Get template** API. A vendor token is
     * required for this route, it can be obtained from the vendor authentication route.
     *
     * @summary Delete template
     */
    mailV1Controller_deleteTemplate(metadata: types.MailV1ControllerDeleteTemplateMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets default email template by type, pass required type as a query param.
     *
     * @summary Get default template by type
     */
    mailV1Controller_getDefaultTemplateConfiguration(metadata: types.MailV1ControllerGetDefaultTemplateConfigurationMetadataParam): Promise<FetchResponse<200, types.MailV1ControllerGetDefaultTemplateConfigurationResponse200>>;
    /**
     * Get active access tokens list
     *
     */
    vendorOnlyUserAccessTokensV1Controller_getActiveAccessTokens(metadata: types.VendorOnlyUserAccessTokensV1ControllerGetActiveAccessTokensMetadataParam): Promise<FetchResponse<200, types.VendorOnlyUserAccessTokensV1ControllerGetActiveAccessTokensResponse200>>;
    /**
     * Get user access token data
     *
     */
    vendorOnlyUserAccessTokensV1Controller_getUserAccessTokenData(metadata: types.VendorOnlyUserAccessTokensV1ControllerGetUserAccessTokenDataMetadataParam): Promise<FetchResponse<200, types.VendorOnlyUserAccessTokensV1ControllerGetUserAccessTokenDataResponse200>>;
    /**
     * Get tenant access token data
     *
     */
    vendorOnlyTenantAccessTokensV1Controller_getTenantAccessTokenData(metadata: types.VendorOnlyTenantAccessTokensV1ControllerGetTenantAccessTokenDataMetadataParam): Promise<FetchResponse<200, types.VendorOnlyTenantAccessTokensV1ControllerGetTenantAccessTokenDataResponse200>>;
    /**
     * This route updates the MFA configuration for a vendor. Send values in the POST body as
     * objects for params that you want to add or update. See the dropdowns for available
     * values for each object param.
     *
     * @summary Update MFA configuration
     */
    mfaController_upsertMfaConfig(body: types.MfaControllerUpsertMfaConfigBodyParam): Promise<FetchResponse<201, types.MfaControllerUpsertMfaConfigResponse201>>;
    /**
     * This route gets the MFA configuration for a vendor.
     *
     * @summary Get MFA configuration
     */
    mfaController_getMfaConfig(): Promise<FetchResponse<200, types.MfaControllerGetMfaConfigResponse200>>;
    /**
     * This route returns all permissions categories for a vendor. Each category is an object
     * containing the name, description, permissions, and other defining information.
     *
     * @summary Get permissions categories
     */
    permissionsCategoriesController_getAllCategoriesWithPermissions(): Promise<FetchResponse<200, types.PermissionsCategoriesControllerGetAllCategoriesWithPermissionsResponse200>>;
    /**
     * Use this route to add a new permissions category. Each category you add requires you to
     * send information about the category in the POST body. Note that you do not associate the
     * category with permissions here. You do that using the add and update permission routes
     * where you send the category ID as a body parameter.
     *
     * @summary Create category
     */
    permissionsCategoriesController_createPermissionCategory(body: types.PermissionsCategoriesControllerCreatePermissionCategoryBodyParam): Promise<FetchResponse<201, types.PermissionsCategoriesControllerCreatePermissionCategoryResponse201>>;
    /**
     * This route updates an existing permissions category. Add the category ID as a path
     * parameter to the route url to specify which category you are updating. Send the updated
     * information about the category in the PATCH body. Note that here is not where you update
     * the permissions associated with the category. Use the add or update permissions routes
     * to do that. Use the **Get categories** API to get
     *
     * @summary Update category
     */
    permissionsCategoriesController_updateCategory(body: types.PermissionsCategoriesControllerUpdateCategoryBodyParam, metadata: types.PermissionsCategoriesControllerUpdateCategoryMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route deletes a category. Add the category ID as a path parameter to the route url
     * to specify which category you are deleting. Use the **Get categories** API to get the
     * category ID.
     *
     * @summary Delete category
     */
    permissionsCategoriesController_deleteCategory(metadata: types.PermissionsCategoriesControllerDeleteCategoryMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route returns all permissions for the vendor. Each permission is an object
     * containing the name, description, assigned roles, categories, and other defining
     * information.
     *
     * @summary Get permissions
     */
    permissionsControllerV1_getAllPermissions(): Promise<FetchResponse<200, types.PermissionsControllerV1GetAllPermissionsResponse200>>;
    /**
     * This route adds a new permission. Each permission you add requires information about the
     * permission in the POST body. Note that you do not associate permissions to the role
     * here. Use the associate permission to roles route to do that.
     *
     * @summary Create permissions
     */
    permissionsControllerV1_addPermissions(body: types.PermissionsControllerV1AddPermissionsBodyParam): Promise<FetchResponse<201, types.PermissionsControllerV1AddPermissionsResponse201>>;
    /**
     * This route deletes a permission. Add the permission ID as a path parameter to the route
     * url to specify which permission you are deleting.  Use the **Get permissions** API to
     * get the permission ID.
     *
     * @summary Delete permission
     */
    permissionsControllerV1_deletePermission(metadata: types.PermissionsControllerV1DeletePermissionMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route updates an existing permission. Add the permission ID as a path parameter to
     * the route url to specify which permission you are updating. Send the updated information
     * about the permission in the PATCH body. Note that you do not update roles for the
     * permission here. Use the associate permission to roles route to do that.
     *
     * @summary Update permission
     */
    permissionsControllerV1_updatePermission(body: types.PermissionsControllerV1UpdatePermissionBodyParam, metadata: types.PermissionsControllerV1UpdatePermissionMetadataParam): Promise<FetchResponse<200, types.PermissionsControllerV1UpdatePermissionResponse200>>;
    /**
     * This route associates a permission to multiple roles. Add the permission ID as a path
     * parameter to the route url and include the role IDs in the request body as an array of
     * strings. Any pre-existing roles associated with the permission will stay associated. Use
     * the **Get roles** API to get the role IDs.
     *
     * @summary Set a permission to multiple roles
     */
    permissionsControllerV1_setRolesToPermission(body: types.PermissionsControllerV1SetRolesToPermissionBodyParam, metadata: types.PermissionsControllerV1SetRolesToPermissionMetadataParam): Promise<FetchResponse<200, types.PermissionsControllerV1SetRolesToPermissionResponse200>>;
    /**
     * This route accepts an array of **`permissionIds`** and the type for these permissions
     * classifications. This allows segregating which permissions will be used from self
     * service
     *
     * @summary Set permissions classification
     */
    permissionsControllerV1_updatePermissionsAssignmentType(body: types.PermissionsControllerV1UpdatePermissionsAssignmentTypeBodyParam): Promise<FetchResponse<200, types.PermissionsControllerV1UpdatePermissionsAssignmentTypeResponse200>>;
    /**
     * This route returns all roles for all tenants. To get a role for a specific tenant, send
     * the tenant ID in the **`frontegg-tenant-id`** header. Each role is an object containing
     * the name, permissions, and other defining information.
     *
     * @summary Get roles
     */
    permissionsControllerV1_getAllRoles(metadata?: types.PermissionsControllerV1GetAllRolesMetadataParam): Promise<FetchResponse<200, types.PermissionsControllerV1GetAllRolesResponse200>>;
    /**
     * This route adds a new role for all tenants. To add a role for a specific tenant, send
     * tenant ID in the **`frontegg-tenant-id`** header. Each role you add requires information
     * about the role in the POST body. Note that you do not assign permissions to the role
     * here. Use the attach permissions to role route to do that.
     *
     * @summary Create roles
     */
    permissionsControllerV1_addRoles(body: types.PermissionsControllerV1AddRolesBodyParam, metadata?: types.PermissionsControllerV1AddRolesMetadataParam): Promise<FetchResponse<201, types.PermissionsControllerV1AddRolesResponse201>>;
    /**
     * This route deletes a role. Add the role ID as a path parameter to the route url to
     * specify which role you are deleting.
     *
     * @summary Delete role
     */
    permissionsControllerV1_deleteRole(metadata: types.PermissionsControllerV1DeleteRoleMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route updates an existing role. Add the role ID as a path parameter to the route
     * url to specify which role you are updating. Send the updated information about the role
     * in the PATCH body. Note that you do not update permissions for the role here. Use the
     * attach permissions to role route to do that. Use the **Get roles** API to get the role
     * ID.
     *
     * @summary Update role
     */
    permissionsControllerV1_updateRole(body: types.PermissionsControllerV1UpdateRoleBodyParam, metadata: types.PermissionsControllerV1UpdateRoleMetadataParam): Promise<FetchResponse<200, types.PermissionsControllerV1UpdateRoleResponse200>>;
    /**
     * This route assigns permissions to a role. Add the role ID as a path parameter to the
     * route url and include the permission IDs in the request body as an array of strings. Any
     * pre-existing permissions will be overridden by the new permissions. Use the get roles
     * API to get the role IDs. Use the **Get permissions** API to get the permissions IDs.
     *
     * @summary Set multiple permissions to a role
     */
    permissionsControllerV1_setPermissionsToRole(body: types.PermissionsControllerV1SetPermissionsToRoleBodyParam, metadata: types.PermissionsControllerV1SetPermissionsToRoleMetadataParam): Promise<FetchResponse<200, types.PermissionsControllerV1SetPermissionsToRoleResponse200>>;
    /**
     * This route creates or updates SMS configuration for a vendor.
     *
     * @summary Creates or updates a vendor SMS config
     */
    vendorSmsController_createSmsVendorConfig(body: types.VendorSmsControllerCreateSmsVendorConfigBodyParam): Promise<FetchResponse<200, types.VendorSmsControllerCreateSmsVendorConfigResponse200> | FetchResponse<201, types.VendorSmsControllerCreateSmsVendorConfigResponse201>>;
    /**
     * Deletes a vendor SMS config
     *
     */
    vendorSmsController_deleteSmsVendorConfig(): Promise<FetchResponse<number, unknown>>;
    /**
     * Gets a vendor SMS config
     *
     */
    vendorSmsController_getSmsVendorConfig(): Promise<FetchResponse<200, types.VendorSmsControllerGetSmsVendorConfigResponse200>>;
    /**
     * Gets vendor SMS templates
     *
     */
    vendorSmsController_getAllSmsTemplates(): Promise<FetchResponse<200, types.VendorSmsControllerGetAllSmsTemplatesResponse200>>;
    /**
     * Gets vendor SMS template by type
     *
     */
    vendorSmsController_getSmsTemplate(metadata: types.VendorSmsControllerGetSmsTemplateMetadataParam): Promise<FetchResponse<200, types.VendorSmsControllerGetSmsTemplateResponse200>>;
    /**
     * Deletes vendor SMS template by type
     *
     */
    vendorSmsController_deleteSmsTemplate(metadata: types.VendorSmsControllerDeleteSmsTemplateMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Create or update a vendor SMS template
     *
     */
    vendorSmsController_createSmsTemplate(body: types.VendorSmsControllerCreateSmsTemplateBodyParam, metadata: types.VendorSmsControllerCreateSmsTemplateMetadataParam): Promise<FetchResponse<200, types.VendorSmsControllerCreateSmsTemplateResponse200> | FetchResponse<201, types.VendorSmsControllerCreateSmsTemplateResponse201>>;
    /**
     * Gets vendor default SMS template by type
     *
     */
    vendorSmsController_getSmsDefaultTemplate(metadata: types.VendorSmsControllerGetSmsDefaultTemplateMetadataParam): Promise<FetchResponse<200, types.VendorSmsControllerGetSmsDefaultTemplateResponse200>>;
    /**
     * Get environment session configuration
     *
     */
    sessionConfigurationControllerV1_getVendorSessionConfiguration(): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets all vendor's user sources.
     *
     * @summary Get vendor user sources
     */
    userSourcesControllerV1_getUserSources(): Promise<FetchResponse<200, types.UserSourcesControllerV1GetUserSourcesResponse200>>;
    /**
     * This route gets a user source by id.
     *
     * @summary Get user source
     */
    userSourcesControllerV1_getUserSource(metadata: types.UserSourcesControllerV1GetUserSourceMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route deletes a user source.
     *
     * @summary Delete user source
     */
    userSourcesControllerV1_deleteUserSource(metadata: types.UserSourcesControllerV1DeleteUserSourceMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route creates a new external user source.
     *
     * @summary Create vendor external user source
     */
    userSourcesControllerV1_createAuth0ExternalUserSource(body: types.UserSourcesControllerV1CreateAuth0ExternalUserSourceBodyParam): Promise<FetchResponse<201, types.UserSourcesControllerV1CreateAuth0ExternalUserSourceResponse201>>;
    /**
     * This route creates a new external user source.
     *
     * @summary Create vendor external user source
     */
    userSourcesControllerV1_createCognitoExternalUserSource(body: types.UserSourcesControllerV1CreateCognitoExternalUserSourceBodyParam): Promise<FetchResponse<201, types.UserSourcesControllerV1CreateCognitoExternalUserSourceResponse201>>;
    /**
     * This route creates a new external user source.
     *
     * @summary Create vendor external user source
     */
    userSourcesControllerV1_createCustomCodeExternalUserSource(body: types.UserSourcesControllerV1CreateCustomCodeExternalUserSourceBodyParam): Promise<FetchResponse<201, types.UserSourcesControllerV1CreateCustomCodeExternalUserSourceResponse201>>;
    /**
     * This route creates a new federation user source.
     *
     * @summary Create vendor federation user source
     */
    userSourcesControllerV1_createFederationUserSource(body: types.UserSourcesControllerV1CreateFederationUserSourceBodyParam): Promise<FetchResponse<201, types.UserSourcesControllerV1CreateFederationUserSourceResponse201>>;
    /**
     * This route updates an external user source.
     *
     * @summary Create vendor external user source
     */
    userSourcesControllerV1_updateAuth0ExternalUserSource(body: types.UserSourcesControllerV1UpdateAuth0ExternalUserSourceBodyParam, metadata: types.UserSourcesControllerV1UpdateAuth0ExternalUserSourceMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route updates an external user source.
     *
     * @summary Create vendor external user source
     */
    userSourcesControllerV1_updateCognitoExternalUserSource(body: types.UserSourcesControllerV1UpdateCognitoExternalUserSourceBodyParam, metadata: types.UserSourcesControllerV1UpdateCognitoExternalUserSourceMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route updates an external user source.
     *
     * @summary Create vendor external user source
     */
    userSourcesControllerV1_updateCustomCodeExternalUserSource(body: types.UserSourcesControllerV1UpdateCustomCodeExternalUserSourceBodyParam, metadata: types.UserSourcesControllerV1UpdateCustomCodeExternalUserSourceMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route updates a federation user source.
     *
     * @summary Create vendor external user source
     */
    userSourcesControllerV1_updateFederationUserSource(body: types.UserSourcesControllerV1UpdateFederationUserSourceBodyParam, metadata: types.UserSourcesControllerV1UpdateFederationUserSourceMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route assigns applications to a user source.
     *
     * @summary Assign applications to a user source
     */
    userSourcesControllerV1_assignUserSource(body: types.UserSourcesControllerV1AssignUserSourceBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route unassigns applications from a user source.
     *
     * @summary Unassign applications from a user source
     */
    userSourcesControllerV1_unassignUserSource(body: types.UserSourcesControllerV1UnassignUserSourceBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets all of users of a user source.
     *
     * @summary Get user source users
     */
    userSourcesControllerV1_getUserSourceUsers(metadata: types.UserSourcesControllerV1GetUserSourceUsersMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets a user by its ID regardless of any tenant the user belongs to. Send the
     * user’s ID as a path params. The route is for vendor-use only.
     *
     * @summary Get user
     */
    vendorOnlyUsers_getUserById(metadata: types.VendorOnlyUsersGetUserByIdMetadataParam): Promise<FetchResponse<200, types.VendorOnlyUsersGetUserByIdResponse200>>;
    /**
     * This route unenrolls a user from MFA regardless of any tenant the user belongs to. Send
     * the user’s ID as a path params. The route is for vendor-use only.
     *
     * @summary Unenroll user from MFA globally
     */
    vendorOnlyUsers_MFAUnenroll(metadata: types.VendorOnlyUsersMfaUnenrollMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route verify user email and password. Send the user’s email and password and the
     * response will be true or false. The route is for vendor-use only.
     *
     * @summary Verify user's password
     */
    vendorOnlyUsers_verifyUserPassword(body: types.VendorOnlyUsersVerifyUserPasswordBodyParam): Promise<FetchResponse<200, types.VendorOnlyUsersVerifyUserPasswordResponse200>>;
    /**
     * This route creates a user and allows setting **`mfaBypass`** property on that user for
     * testing purposes. The route is for vendor-use only.
     *
     * @summary Create user
     */
    vendorOnlyUsers_createUser(body: types.VendorOnlyUsersCreateUserBodyParam): Promise<FetchResponse<201, types.VendorOnlyUsersCreateUserResponse201>>;
    /**
     * This route gets the tenants statuses of vendor users. Expects an array of **`userIds`**
     * with max of 200 and optionally an array of **`userTenantStatuses`** as query params.
     * Note that there is a limit of 2000 tenants statuses per user.
     *
     * @summary Get users tenants statuses
     */
    get(metadata: types.GetMetadataParam): Promise<FetchResponse<200, types.GetResponse200>>;
    /**
     * This route updates the settings for temporary users, use it to enable or disable it for
     * an environment
     *
     * @summary Set temporary users configuration
     */
    temporaryUsersV1Controller_updateConfiguration(body: types.TemporaryUsersV1ControllerUpdateConfigurationBodyParam): Promise<FetchResponse<200, types.TemporaryUsersV1ControllerUpdateConfigurationResponse200>>;
    /**
     * This route get the settings for temporary users, use it to check whether the policy is's
     * enabled or disabled
     *
     * @summary Gets temporary users configuration
     */
    temporaryUsersV1Controller_getConfiguration(): Promise<FetchResponse<200, types.TemporaryUsersV1ControllerGetConfigurationResponse200>>;
    /**
     * This route enables you to invite users to tenant in bulk. Expects an array of `users`.
     * Each entry must include a user's `email`.
     *
     * @summary Invite users to tenant in bulk
     */
    usersBulkControllerV1_bulkInviteUsers(body: types.UsersBulkControllerV1BulkInviteUsersBodyParam, metadata: types.UsersBulkControllerV1BulkInviteUsersMetadataParam): Promise<FetchResponse<202, types.UsersBulkControllerV1BulkInviteUsersResponse202>>;
    /**
     * This route enables you to invite users to tenant in bulk. Expects an array of `users`.
     * Each entry must include a user's `email`.
     *
     * @summary Get status of bulk invite task
     */
    usersBulkControllerV1_getBulkInviteStatus(metadata: types.UsersBulkControllerV1GetBulkInviteStatusMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route get user by email
     *
     * @summary Get user by email
     */
    usersControllerV1_getUserByEmail(metadata: types.UsersControllerV1GetUserByEmailMetadataParam): Promise<FetchResponse<200, types.UsersControllerV1GetUserByEmailResponse200>>;
    /**
     * This route gets a specific user from a tenant. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header to declare which tenant and send the user’s ID as a path
     * params to declare which user. A vendor token is required for this route, it can be
     * obtained from the vendor authentication route.
     *
     * @summary Get user by ID
     */
    usersControllerV1_getUserById(metadata: types.UsersControllerV1GetUserByIdMetadataParam): Promise<FetchResponse<200, types.UsersControllerV1GetUserByIdResponse200>>;
    /**
     * This route updates a user’s information globally, not just for a specific tenant. Send
     * the user’s ID as a path params to declare which user. Send the updated user values in
     * the PUT body. The PUT request does a complete update of the resource, so include values
     * for all the body params that you want to have values. This is a global update, so do not
     * send a **`frontegg-tenant-id`** header.
     *
     * @summary Update user globally
     */
    usersControllerV1_updateUserForVendor(body: types.UsersControllerV1UpdateUserForVendorBodyParam, metadata: types.UsersControllerV1UpdateUserForVendorMetadataParam): Promise<FetchResponse<200, types.UsersControllerV1UpdateUserForVendorResponse200>>;
    /**
     * This route removes a user globally or from a specific tenant. To remove the user
     * globally, no need to send a **`frontegg-tenant-id`**. To remove the user from only a
     * specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header. Send the
     * user's ID as a path params to declare which user you are removing. A vendor token is
     * required for this route, it can be obtained from the vendor authentication route.
     *
     * @summary Remove user
     */
    usersControllerV1_removeUserFromTenant(metadata: types.UsersControllerV1RemoveUserFromTenantMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route marks a user as verified. Send the user’s ID as a path params. A vendor token
     * is required for this route, it can be obtained from the vendor authentication route.
     *
     * @summary Verify user
     */
    usersControllerV1_verifyUser(metadata: types.UsersControllerV1VerifyUserMetadataParam): Promise<FetchResponse<number, unknown>>;
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
    usersControllerV1_setUserInvisibleMode(body: types.UsersControllerV1SetUserInvisibleModeBodyParam, metadata: types.UsersControllerV1SetUserInvisibleModeMetadataParam): Promise<FetchResponse<200, types.UsersControllerV1SetUserInvisibleModeResponse200>>;
    /**
     * This route sets whether a user is a super user. A super user has access to all tenants
     * within the workspace. Send the user ID as a path params. Also send as a PUT body params
     * a Boolean value for super user. True is super user and false is not. A vendor token is
     * required for this route, it can be obtained from the vendor authentication route.
     *
     * @summary Make User superuser
     */
    usersControllerV1_setUserSuperuserMode(body: types.UsersControllerV1SetUserSuperuserModeBodyParam, metadata: types.UsersControllerV1SetUserSuperuserModeMetadataParam): Promise<FetchResponse<200, types.UsersControllerV1SetUserSuperuserModeResponse200>>;
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
    usersControllerV1_updateUserTenantForVendor(body: types.UsersControllerV1UpdateUserTenantForVendorBodyParam, metadata: types.UsersControllerV1UpdateUserTenantForVendorMetadataParam): Promise<FetchResponse<200, types.UsersControllerV1UpdateUserTenantForVendorResponse200>>;
    /**
     * This route adds a user to a tenant. Send the user ID as a path params and the tenant ID
     * as a PUT body params. To skip the invite email requirement, pass as an optional PUT body
     * params for skipInviteEmail. Set its value to true to skip the invite email. A vendor
     * token is required for this route, it can be obtained from the vendor authentication
     * route.
     *
     * @summary Add to tenant
     */
    usersControllerV1_addUserToTenantForVendor(body: types.UsersControllerV1AddUserToTenantForVendorBodyParam, metadata: types.UsersControllerV1AddUserToTenantForVendorMetadataParam): Promise<FetchResponse<201, types.UsersControllerV1AddUserToTenantForVendorResponse201>>;
    /**
     * This route updates the email address for a user globally, regardless of tenant. Send the
     * user’s ID as a path params. Send the user’s new email address as a PUT body params.
     *
     * @summary Update user email
     */
    usersControllerV1_updateUserEmail(body: types.UsersControllerV1UpdateUserEmailBodyParam, metadata: types.UsersControllerV1UpdateUserEmailMetadataParam): Promise<FetchResponse<200, types.UsersControllerV1UpdateUserEmailResponse200>>;
    /**
     * This route generates a new activation token for a user. Send the user’s ID as a path
     * params. You may need this route in combination with the routes under Users Activation.
     * It will not send the activation email itself, but return the activation link and token.
     * A vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Generate activation token
     */
    usersControllerV1_generateUserActivationLink(metadata: types.UsersControllerV1GenerateUserActivationLinkMetadataParam): Promise<FetchResponse<201, types.UsersControllerV1GenerateUserActivationLinkResponse201>>;
    /**
     * This route generates a password reset token for a user. Send the user’s ID as a path
     * params. You may need this route in combination with the routes under Users Passwords. It
     * will not send the reset password email itself, but return the reset link and token. A
     * vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Generate password reset token
     */
    usersControllerV1_generateUserPasswordResetLink(metadata: types.UsersControllerV1GenerateUserPasswordResetLinkMetadataParam): Promise<FetchResponse<201, types.UsersControllerV1GenerateUserPasswordResetLinkResponse201>>;
    /**
     * This route unlocks a locked user. An unlocked user can sign in and use the system
     * globally, regardless of the tenant. To unlock a user, call this route and send the
     * user’s ID as a path params. A vendor token is required for this route, it can be
     * obtained from the vendor authentication route.
     *
     * @summary Unlock user
     */
    usersControllerV1_unlockUser(metadata: types.UsersControllerV1UnlockUserMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route locks a user. A locked user cannot sign in or use the system globally,
     * regardless of the tenant. To lock a user, call this route and send the user’s ID as a
     * path params. A vendor token is required for this route, it can be obtained from the
     * vendor authentication route.
     *
     * @summary Lock user
     */
    usersControllerV1_lockUser(metadata: types.UsersControllerV1LockUserMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route migrates all the users from the source tenant to the target. Specify in the
     * request body the srcTenantId (the source tenant ID) and targetTenantId (the target
     * tenant ID). A vendor token is required for this route, it can be obtained from the
     * vendor authentication route.
     *
     * @summary Move all users from one tenant to another
     */
    usersControllerV1_moveAllUsersTenants(body: types.UsersControllerV1MoveAllUsersTenantsBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets an invitation for a specific user to join a tenant. Send the user’s ID
     * in the **`frontegg-user-id`** header and the tenant’s ID in the **`frontegg-tenant-id`**
     * header.
     *
     * @summary Get tenant invite of user
     */
    tenantInvitesController_getTenantInviteForUser(metadata: types.TenantInvitesControllerGetTenantInviteForUserMetadataParam): Promise<FetchResponse<200, types.TenantInvitesControllerGetTenantInviteForUserResponse200>>;
    /**
     * This route creates an invitation for a specific user to join a tenant. Send the user’s
     * ID in the **`frontegg-user-id`** header and the tenant’s ID in the
     * **`frontegg-tenant-id`** header. To create a general invitation, use the general
     * invitation route.
     *
     * @summary Create tenant invite for user
     */
    tenantInvitesController_createTenantInviteForUser(body: types.TenantInvitesControllerCreateTenantInviteForUserBodyParam, metadata: types.TenantInvitesControllerCreateTenantInviteForUserMetadataParam): Promise<FetchResponse<201, types.TenantInvitesControllerCreateTenantInviteForUserResponse201>>;
    /**
     * This route deletes an invitation for a specific user to join a tenant. Send the user’s
     * ID in the **`frontegg-user-id`** header and the tenant’s ID in the
     * **`frontegg-tenant-id`** header. To delete a general invitation, use the general
     * invitation route.
     *
     * @summary Delete tenant invite of user
     */
    tenantInvitesController_deleteTenantInviteForUser(metadata: types.TenantInvitesControllerDeleteTenantInviteForUserMetadataParam): Promise<FetchResponse<number, unknown>>;
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
    tenantInvitesController_updateTenantInviteForUser(body: types.TenantInvitesControllerUpdateTenantInviteForUserBodyParam, metadata: types.TenantInvitesControllerUpdateTenantInviteForUserMetadataParam): Promise<FetchResponse<200, types.TenantInvitesControllerUpdateTenantInviteForUserResponse200>>;
    /**
     * This route verifies a tenant invitation. Pass the invitation token as the token param. A
     * vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Verify tenant invite
     */
    tenantInvitesController_verifyTenantInvite(body: types.TenantInvitesControllerVerifyTenantInviteBodyParam): Promise<FetchResponse<200, types.TenantInvitesControllerVerifyTenantInviteResponse200>>;
    /**
     * This route checks if the vendor allows tenant invitations and if notifications are
     * active. A vendor token is required for this route, it can be obtained from the vendor
     * authentication route.
     *
     * @summary Get tenant invite configuration
     */
    getInvitationConfiguration(): Promise<FetchResponse<200, types.GetInvitationConfigurationResponse200>>;
    /**
     * This route creates a new domain restriction for a tenant. Send values in the POST body
     * as objects. See the dropdowns for available values for each object param.
     *
     * @summary Create domain restriction
     */
    domainRestrictionsController_createDomainRestriction(body: types.DomainRestrictionsControllerCreateDomainRestrictionBodyParam): Promise<FetchResponse<201, types.DomainRestrictionsControllerCreateDomainRestrictionResponse201>>;
    /**
     * This route gets the domain restrictions for a tenant.
     *
     * @summary Get domain restrictions
     */
    domainRestrictionsController_getDomainRestrictions(): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets the domain restrictions for a tenant.
     *
     * @summary Get domain restrictions
     */
    domainRestrictionsController_getDomainRestrictionsConfig(): Promise<FetchResponse<200, types.DomainRestrictionsControllerGetDomainRestrictionsConfigResponse200>>;
    /**
     * This route updates domain restrictions config, can toggle check on/off.
     *
     * @summary Change domain restrictions config list type and toggle it off/on
     */
    domainRestrictionsController_updateDomainRestrictionsConfig(body: types.DomainRestrictionsControllerUpdateDomainRestrictionsConfigBodyParam): Promise<FetchResponse<201, types.DomainRestrictionsControllerUpdateDomainRestrictionsConfigResponse201>>;
    /**
     * This route deletes domain restriction.
     *
     * @summary Delete domain restriction
     */
    domainRestrictionsController_deleteDomainRestriction(metadata: types.DomainRestrictionsControllerDeleteDomainRestrictionMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route replaces all domains from the incoming request
     *
     * @summary Replace bulk domain restriction
     */
    domainRestrictionsController_createBulkDomainsRestriction(body: types.DomainRestrictionsControllerCreateBulkDomainsRestrictionBodyParam): Promise<FetchResponse<201, types.DomainRestrictionsControllerCreateBulkDomainsRestrictionResponse201>>;
    /**
     * This route gets all user groups for a tenant.
     *
     * @summary Get all groups
     */
    groupsControllerV1_getAllGroups(metadata?: types.GroupsControllerV1GetAllGroupsMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route creates user group for a tenant.
     *
     * @summary Create group
     */
    groupsControllerV1_createGroup(body: types.GroupsControllerV1CreateGroupBodyParam): Promise<FetchResponse<201, types.GroupsControllerV1CreateGroupResponse201>>;
    /**
     * This route gets user group by given IDs for a tenant.
     *
     * @summary Get groups by ids
     */
    groupsControllerV1_getGroupsByIds(body: types.GroupsControllerV1GetGroupsByIdsBodyParam, metadata?: types.GroupsControllerV1GetGroupsByIdsMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route updates user group by id for a tenant.
     *
     * @summary Update group
     */
    groupsControllerV1_updateGroup(body: types.GroupsControllerV1UpdateGroupBodyParam, metadata: types.GroupsControllerV1UpdateGroupMetadataParam): Promise<FetchResponse<200, types.GroupsControllerV1UpdateGroupResponse200>>;
    /**
     * This route deletes user group by id for a tenant.
     *
     * @summary Delete group
     */
    groupsControllerV1_deleteGroup(metadata: types.GroupsControllerV1DeleteGroupMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets user group by given ID for a tenant.
     *
     * @summary Get group by ID
     */
    groupsControllerV1_getGroupById(metadata: types.GroupsControllerV1GetGroupByIdMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets the user group configuration for a vendor.
     *
     * @summary Get groups configuration
     */
    groupsControllerV1_getGroupsConfiguration(): Promise<FetchResponse<number, unknown>>;
    /**
     * This route creates or updates the user group configuration for a vendor.
     *
     * @summary Create or update groups configuration
     */
    groupsControllerV1_createOrUpdateGroupsConfiguration(body: types.GroupsControllerV1CreateOrUpdateGroupsConfigurationBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route adds requested roles to existing group. User can assign only roles that are
     * lower then his own.
     *
     * @summary Add roles to group
     */
    groupsControllerV1_addRolesToGroup(body: types.GroupsControllerV1AddRolesToGroupBodyParam, metadata: types.GroupsControllerV1AddRolesToGroupMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route removes requested roles from existing group.
     *
     * @summary Remove roles from group
     */
    groupsControllerV1_removeRolesFromGroup(body: types.GroupsControllerV1RemoveRolesFromGroupBodyParam, metadata: types.GroupsControllerV1RemoveRolesFromGroupMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route adds requested users to existing group. Only allowed for users that have
     * higher roles then group roles.
     *
     * @summary Add users to group
     */
    groupsControllerV1_addUsersToGroup(body: types.GroupsControllerV1AddUsersToGroupBodyParam, metadata: types.GroupsControllerV1AddUsersToGroupMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route removes requested users from existing group.
     *
     * @summary Remove users from group
     */
    groupsControllerV1_removeUsersFromGroup(body: types.GroupsControllerV1RemoveUsersFromGroupBodyParam, metadata: types.GroupsControllerV1RemoveUsersFromGroupMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets all user groups for a tenant.
     *
     * @summary Get all groups paginated
     */
    groupsControllerV2_getAllGroupsPaginated(metadata?: types.GroupsControllerV2GetAllGroupsPaginatedMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route creates or updates ip restrictions config.
     *
     * @summary Create or update IP restriction configuration (ALLOW/BLOCK)
     */
    iPRestrictionsControllerV1_createDomainRestriction(body: types.IPRestrictionsControllerV1CreateDomainRestrictionBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets the ip restrictions config for a tenant.
     *
     * @summary Get IP restriction configuration (ALLOW/BLOCK)
     */
    iPRestrictionsControllerV1_getIpRestrictionConfig(): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets the ip restrictions for a tenant.
     *
     * @summary Get all IP restrictions
     */
    iPRestrictionsControllerV1_getAllIpRestrictions(metadata?: types.IPRestrictionsControllerV1GetAllIpRestrictionsMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route creates or updates ip restriction for a tenant. Send values in the POST body
     * as objects. See the dropdowns for available values for each object param.
     *
     * @summary Create IP restriction
     */
    iPRestrictionsControllerV1_createIpRestriction(body: types.IPRestrictionsControllerV1CreateIpRestrictionBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route checks if current ip is allowed.
     *
     * @summary Test Current IP
     */
    iPRestrictionsControllerV1_testCurrentIp(): Promise<FetchResponse<number, unknown>>;
    /**
     * This route checks if current ip is active in the allow list.
     *
     * @summary Test current IP is in allow list
     */
    testCurrentIpInAllowList(): Promise<FetchResponse<number, unknown>>;
    /**
     * This route deletes ip restriction.
     *
     * @summary Delete IP restriction by IP
     */
    iPRestrictionsControllerV1_deleteIpRestrictionById(metadata: types.IPRestrictionsControllerV1DeleteIpRestrictionByIdMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route creates a lockout policy for all tenants. To create a lockout policy for a
     * specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header. To enable
     * the Lockout Policy, make sure to set the enabled variable to true and the maximum
     * attempts to a number of your preference.
     *
     * @summary Create lockout policy
     */
    lockoutPolicyController_createLockoutPolicy(body: types.LockoutPolicyControllerCreateLockoutPolicyBodyParam, metadata?: types.LockoutPolicyControllerCreateLockoutPolicyMetadataParam): Promise<FetchResponse<201, types.LockoutPolicyControllerCreateLockoutPolicyResponse201>>;
    /**
     * This route updates a lockout policy for all tenants. To update a lockout policy for a
     * specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header. To disable
     * the lockout policy, make sure to set the enabled variable to false. The maximum attempts
     * variable can also be changed to a number of your preference
     *
     * @summary Update lockout policy
     */
    lockoutPolicyController_updateLockoutPolicy(body: types.LockoutPolicyControllerUpdateLockoutPolicyBodyParam, metadata?: types.LockoutPolicyControllerUpdateLockoutPolicyMetadataParam): Promise<FetchResponse<200, types.LockoutPolicyControllerUpdateLockoutPolicyResponse200>>;
    /**
     * This route gets the lockout policy for all tenants or one tenant specifically. To get
     * the lockout policy for a specific tenant, send the tenant’s ID in the
     * **`frontegg-tenant-id`** header.
     *
     * @summary Get lockout policy
     */
    lockoutPolicyController_getLockoutPolicy(metadata?: types.LockoutPolicyControllerGetLockoutPolicyMetadataParam): Promise<FetchResponse<200, types.LockoutPolicyControllerGetLockoutPolicyResponse200>>;
    /**
     * This route creates the MFA policy globally or for a specific tenant. To create an MFA
     * policy for a specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`**
     * header.
     *
     * @summary Create MFA policy
     */
    securityPolicyController_createMfaPolicy(body: types.SecurityPolicyControllerCreateMfaPolicyBodyParam, metadata?: types.SecurityPolicyControllerCreateMfaPolicyMetadataParam): Promise<FetchResponse<201, types.SecurityPolicyControllerCreateMfaPolicyResponse201>>;
    /**
     * This route updates the MFA policy for all tenants. To update an MFA policy for a
     * specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header.
     *
     * @summary Update security policy
     */
    securityPolicyController_updateSecurityPolicy(body: types.SecurityPolicyControllerUpdateSecurityPolicyBodyParam, metadata?: types.SecurityPolicyControllerUpdateSecurityPolicyMetadataParam): Promise<FetchResponse<200, types.SecurityPolicyControllerUpdateSecurityPolicyResponse200>>;
    /**
     * This route creates or updates the MFA policy for all tenants. To create or update an MFA
     * policy for a specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`**
     * header.
     *
     * @summary Upsert security policy
     */
    securityPolicyController_upsertSecurityPolicy(body: types.SecurityPolicyControllerUpsertSecurityPolicyBodyParam, metadata?: types.SecurityPolicyControllerUpsertSecurityPolicyMetadataParam): Promise<FetchResponse<200, types.SecurityPolicyControllerUpsertSecurityPolicyResponse200>>;
    /**
     * This route gets the MFA policy for all tenants. To get the MFA policy for a specific
     * tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header.
     *
     * @summary Get security policy
     */
    securityPolicyController_getSecurityPolicy(metadata?: types.SecurityPolicyControllerGetSecurityPolicyMetadataParam): Promise<FetchResponse<200, types.SecurityPolicyControllerGetSecurityPolicyResponse200>>;
    /**
     * Get MFA strategies
     *
     */
    mFAStrategiesControllerV1_getMFAStrategies(): Promise<FetchResponse<number, unknown>>;
    /**
     * Create or update MFA strategy
     *
     */
    mFAStrategiesControllerV1_createOrUpdateMFAStrategy(body: types.MFaStrategiesControllerV1CreateOrUpdateMfaStrategyBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route updates the password policy for all tenants. To update the password policy
     * for a specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header. Send
     * the updated values as POST body params.
     *
     * @summary Update password configuration
     */
    passwordPolicyController_addOrUpdatePasswordConfig(body: types.PasswordPolicyControllerAddOrUpdatePasswordConfigBodyParam, metadata?: types.PasswordPolicyControllerAddOrUpdatePasswordConfigMetadataParam): Promise<FetchResponse<201, types.PasswordPolicyControllerAddOrUpdatePasswordConfigResponse201>>;
    /**
     * This route gets the password policy for all tenants. To get the password policy for a
     * specific tenant, send the tenant’s ID in the **`frontegg-tenant-id`** header.
     *
     * @summary Gets password policy configuration
     */
    passwordPolicyController_getPasswordConfig(metadata?: types.PasswordPolicyControllerGetPasswordConfigMetadataParam): Promise<FetchResponse<200, types.PasswordPolicyControllerGetPasswordConfigResponse200>>;
    /**
     * This route creates the password history policy for all tenants. To create a password
     * history policy for a specific tenant, send the tenant’s ID in the
     * **`frontegg-tenant-id`** header. To enable the Password History, make sure to set the
     * enabled variable to true and the password history size to a number between 1 to 10.
     *
     * @summary Create password history policy
     */
    passwordHistoryPolicyController_createPolicy(body: types.PasswordHistoryPolicyControllerCreatePolicyBodyParam, metadata?: types.PasswordHistoryPolicyControllerCreatePolicyMetadataParam): Promise<FetchResponse<201, types.PasswordHistoryPolicyControllerCreatePolicyResponse201>>;
    /**
     * This route updates the password history policy for all tenants. To update a password
     * history policy for a specific tenant, send the tenant’s ID in the
     * **`frontegg-tenant-id`** header. To disable the password history policy, make sure to
     * set the enabled variable to false. The password history size can also be changed to a
     * number between 1 to 10
     *
     * @summary Update password history policy
     */
    passwordHistoryPolicyController_updatePolicy(body: types.PasswordHistoryPolicyControllerUpdatePolicyBodyParam, metadata?: types.PasswordHistoryPolicyControllerUpdatePolicyMetadataParam): Promise<FetchResponse<200, types.PasswordHistoryPolicyControllerUpdatePolicyResponse200>>;
    /**
     * This route gets the password history policy for all tenants or one tenant specifically.
     * To create a password history policy for a specific tenant, send the tenant’s ID in the
     * **`frontegg-tenant-id`** header.
     *
     * @summary Get password history policy
     */
    passwordHistoryPolicyController_getPolicy(metadata?: types.PasswordHistoryPolicyControllerGetPolicyMetadataParam): Promise<FetchResponse<200, types.PasswordHistoryPolicyControllerGetPolicyResponse200>>;
    /**
     * This route sends a reset password email to the user. Send the user’s email in the POST
     * body. If your email template uses metadata, send email metadata in the POST body, too.
     *
     * @summary Reset password
     */
    usersPasswordControllerV1_resetPassword(body: types.UsersPasswordControllerV1ResetPasswordBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route verifies a user’s password using a verification token. Send the userId,
     * token, and password in the POST body. For the token, see the route under users for
     * generating user password reset token.
     *
     * @summary Verify password
     */
    usersPasswordControllerV1_verifyResetPassword(body: types.UsersPasswordControllerV1VerifyResetPasswordBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route changes the password for a logged-in user. Send the **`frontegg-user-id`**
     * and **`frontegg-tenant-id`** headers to declare which user and which tenant. Send the
     * current and new passwords in the POST body.
     *
     * @summary Change password
     */
    usersPasswordControllerV1_changePassword(body: types.UsersPasswordControllerV1ChangePasswordBodyParam, metadata: types.UsersPasswordControllerV1ChangePasswordMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets the user’s hardest password configuration. This is useful when a user
     * belongs to multiple tenants and does not have the same password complexity for all of
     * them. The route returns the strictest setting the user is subject to.
     *
     * @summary Get strictest password configuration
     */
    usersPasswordControllerV1_getUserPasswordConfig(metadata?: types.UsersPasswordControllerV1GetUserPasswordConfigMetadataParam): Promise<FetchResponse<200, types.UsersPasswordControllerV1GetUserPasswordConfigResponse200>>;
    /**
     * Create user access token
     *
     */
    userAccessTokensV1Controller_createUserAccessToken(body: types.UserAccessTokensV1ControllerCreateUserAccessTokenBodyParam, metadata: types.UserAccessTokensV1ControllerCreateUserAccessTokenMetadataParam): Promise<FetchResponse<201, types.UserAccessTokensV1ControllerCreateUserAccessTokenResponse201>>;
    /**
     * Get user access tokens
     *
     */
    userAccessTokensV1Controller_getUserAccessTokens(metadata: types.UserAccessTokensV1ControllerGetUserAccessTokensMetadataParam): Promise<FetchResponse<200, types.UserAccessTokensV1ControllerGetUserAccessTokensResponse200>>;
    /**
     * Delete user access token by token ID
     *
     */
    userAccessTokensV1Controller_deleteUserAccessToken(metadata: types.UserAccessTokensV1ControllerDeleteUserAccessTokenMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route creates a user-specific API token. Send the user’s ID in the
     * **`frontegg-user-id`** header and the tenant’s ID in the **`frontegg-tenant-id`**
     * header. Optionally, send as POST body params values for metadata and description.
     *
     * @summary Create user client credentials token
     */
    userApiTokensV1Controller_createTenantApiToken(body: types.UserApiTokensV1ControllerCreateTenantApiTokenBodyParam, metadata: types.UserApiTokensV1ControllerCreateTenantApiTokenMetadataParam): Promise<FetchResponse<201, types.UserApiTokensV1ControllerCreateTenantApiTokenResponse201>>;
    /**
     * This route gets a user-specific API token. Send the user’s ID in the
     * **`frontegg-user-id`** header and the tenant’s ID in the **`frontegg-tenant-id`**
     * header.
     *
     * @summary Get user client credentials tokens
     */
    userApiTokensV1Controller_getApiTokens(metadata: types.UserApiTokensV1ControllerGetApiTokensMetadataParam): Promise<FetchResponse<200, types.UserApiTokensV1ControllerGetApiTokensResponse200>>;
    /**
     * This route deletes a user-specific API token. Send the token as the ID path param. Send
     * the user’s ID in the **`frontegg-user-id`** header and the tenant’s ID in the
     * **`frontegg-tenant-id`** header. Optionally, send as POST body params values for
     * metadata and description.
     *
     * @summary Delete user client credentials token by token ID
     */
    userApiTokensV1Controller_deleteApiToken(metadata: types.UserApiTokensV1ControllerDeleteApiTokenMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route returns all roles for vendor. Each role is an object containing the name,
     * permissions, and other defining information.
     *
     * @summary Get roles v2
     */
    permissionsControllerV2_getAllRoles(metadata: types.PermissionsControllerV2GetAllRolesMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route adds a new role for a specific tenant. Send the tenant ID in the
     * **`frontegg-tenant-id`** header. Add the required permissions within the request body to
     * customize the role.
     *
     * @summary Create a new role
     */
    rolesControllerV2_addRole(body: types.RolesControllerV2AddRoleBodyParam, metadata?: types.RolesControllerV2AddRoleMetadataParam): Promise<FetchResponse<200, types.RolesControllerV2AddRoleResponse200>>;
    /**
     * This route returns all levels from roles for vendor.
     *
     * @summary Get distinct levels of roles
     */
    rolesControllerV2_getDistinctLevels(metadata?: types.RolesControllerV2GetDistinctLevelsMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route returns all assigned tenant ids from roles for vendor.
     *
     * @summary Get distinct assigned tenants of roles
     */
    rolesControllerV2_getDistinctTenants(metadata?: types.RolesControllerV2GetDistinctTenantsMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets the Session configuration for the entire environment or a specific
     * tenant. To get the Session configuration for a specific tenant, send the tenant’s id in
     * the **`frontegg-tenant-id`** header
     *
     * @summary Get tenant or vendor default session configuration
     */
    sessionConfigurationControllerV1_getSessionConfiguration(metadata?: types.SessionConfigurationControllerV1GetSessionConfigurationMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route creates or updates Session configuration for the entire environment or a
     * specific tenant. To update the Session configuration for a specific tenant, send the
     * tenant’s ID in the **`frontegg-tenant-id`** header
     *
     * @summary Create or update tenant or vendor default session configuration
     */
    sessionConfigurationControllerV1_createSessionConfiguration(body: types.SessionConfigurationControllerV1CreateSessionConfigurationBodyParam, metadata?: types.SessionConfigurationControllerV1CreateSessionConfigurationMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Create tenant access token
     *
     */
    tenantAccessTokensV1Controller_createTenantAccessToken(body: types.TenantAccessTokensV1ControllerCreateTenantAccessTokenBodyParam, metadata: types.TenantAccessTokensV1ControllerCreateTenantAccessTokenMetadataParam): Promise<FetchResponse<201, types.TenantAccessTokensV1ControllerCreateTenantAccessTokenResponse201>>;
    /**
     * Get tenant access tokens
     *
     */
    tenantAccessTokensV1Controller_getTenantAccessTokens(metadata: types.TenantAccessTokensV1ControllerGetTenantAccessTokensMetadataParam): Promise<FetchResponse<200, types.TenantAccessTokensV1ControllerGetTenantAccessTokensResponse200>>;
    /**
     * Delete tenant access token
     *
     */
    tenantAccessTokensV1Controller_deleteTenantAccessToken(metadata: types.TenantAccessTokensV1ControllerDeleteTenantAccessTokenMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * Do not use. Instead, use v2 of this route.
     *
     * @summary Create client credentials token
     */
    tenantApiTokensV1Controller_createTenantApiToken(body: types.TenantApiTokensV1ControllerCreateTenantApiTokenBodyParam, metadata: types.TenantApiTokensV1ControllerCreateTenantApiTokenMetadataParam): Promise<FetchResponse<201, types.TenantApiTokensV1ControllerCreateTenantApiTokenResponse201>>;
    /**
     * This route gets all API tokens for a specific tenant. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header.
     *
     * @summary Get client credentials tokens
     */
    tenantApiTokensV1Controller_getTenantsApiTokens(metadata: types.TenantApiTokensV1ControllerGetTenantsApiTokensMetadataParam): Promise<FetchResponse<200, types.TenantApiTokensV1ControllerGetTenantsApiTokensResponse200>>;
    /**
     * This route deletes a tenant API token. Send the token ID as the path param. Send the
     * tenant’s ID in the **`frontegg-tenant-id`** header.
     *
     * @summary Delete client credentials token
     */
    tenantApiTokensV1Controller_deleteTenantApiToken(metadata: types.TenantApiTokensV1ControllerDeleteTenantApiTokenMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route updates a tenant API token. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header. Optionally, send as POST body params values for
     * description, roles, and permissions for the token.
     *
     * @summary Update client credentials token
     */
    tenantApiTokensV1Controller_updateTenantApiToken(body: types.TenantApiTokensV1ControllerUpdateTenantApiTokenBodyParam, metadata: types.TenantApiTokensV1ControllerUpdateTenantApiTokenMetadataParam): Promise<FetchResponse<200, types.TenantApiTokensV1ControllerUpdateTenantApiTokenResponse200>>;
    /**
     * This route creates a tenant API token. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header. Optionally, send as POST body params values for
     * metadata, description, roles, and permissions for the token.</br></br>You can get roles
     * & permissions via API
     *
     * @summary Create client credentials token
     */
    tenantApiTokensV2Controller_createTenantApiToken(body: types.TenantApiTokensV2ControllerCreateTenantApiTokenBodyParam, metadata: types.TenantApiTokensV2ControllerCreateTenantApiTokenMetadataParam): Promise<FetchResponse<201, types.TenantApiTokensV2ControllerCreateTenantApiTokenResponse201>>;
    /**
     * This route updates the settings for temporary users, use it to enable or disable it for
     * an environment
     *
     * @summary Sets a permanent user to temporary
     */
    temporaryUsersV1Controller_editTimeLimit(body: types.TemporaryUsersV1ControllerEditTimeLimitBodyParam, metadata: types.TemporaryUsersV1ControllerEditTimeLimitMetadataParam): Promise<FetchResponse<201, types.TemporaryUsersV1ControllerEditTimeLimitResponse201>>;
    /**
     * This route sets an existing temporary user as permanent. Send the user’s ID as a path
     * params.
     *
     * @summary Sets a temporary user to permanent
     */
    temporaryUsersV1Controller_setUserPermanent(metadata: types.TemporaryUsersV1ControllerSetUserPermanentMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route resets the activation token for a user and triggers a new activation email
     * being sent to the user’s email.
     *
     * @summary Reset user activation token
     */
    usersActivationControllerV1_resetActivationToken(body: types.UsersActivationControllerV1ResetActivationTokenBodyParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route resets an invitation for a user to join a specific tenant. Send the tenant’s
     * ID in the **`frontegg-tenant-id`** header and the user's email in the POST body. It
     * returns a new invitation link with a new token.
     *
     * @summary Reset invitation
     */
    usersTenantManagementControllerV1_resetTenantInvitationToken(body: types.UsersTenantManagementControllerV1ResetTenantInvitationTokenBodyParam, metadata: types.UsersTenantManagementControllerV1ResetTenantInvitationTokenMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route resets all invitation for a user to join all sub tenants which currently have
     * invitation token. Send the tenant’s ID in the **`frontegg-tenant-id`** header and the
     * user's email in the POST body. It returns a new invitation link with a new token.
     *
     * @summary Reset all invitation tokens
     */
    usersTenantManagementControllerV1_resetAllTenantsInvitationToken(body: types.UsersTenantManagementControllerV1ResetAllTenantsInvitationTokenBodyParam, metadata: types.UsersTenantManagementControllerV1ResetAllTenantsInvitationTokenMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route gets all users for a tenant/vendor. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header to declare which tenant or leave it empty for all
     * tenants' users
     *
     * @summary Get users
     */
    usersControllerV3_getUsers(metadata?: types.UsersControllerV3GetUsersMetadataParam): Promise<FetchResponse<200, types.UsersControllerV3GetUsersResponse200>>;
    /**
     * This route gets all users roles for a tenant. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header to declare which tenant.
     *
     * @summary Get users roles
     */
    usersControllerV3_getUsersRoles(metadata: types.UsersControllerV3GetUsersRolesMetadataParam): Promise<FetchResponse<200, types.UsersControllerV3GetUsersRolesResponse200>>;
    /**
     * This route gets all users groups for a tenant. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header to declare which tenant.
     *
     * @summary Get users groups
     */
    usersControllerV3_getUsersGroups(metadata: types.UsersControllerV3GetUsersGroupsMetadataParam): Promise<FetchResponse<200, types.UsersControllerV3GetUsersGroupsResponse200>>;
    /**
     * This route creates a user for a specific tenant. Send the tenant’s ID in the
     * **`frontegg-tenant-id`** header to declare to what tenant this user is assigned. Send
     * the user's information in the POST body. The user's email and metadata are required. The
     * metadata can be empty, like `{}`.
     *
     * @summary Invite user
     */
    usersControllerV2_createUser(body: types.UsersControllerV2CreateUserBodyParam, metadata: types.UsersControllerV2CreateUserMetadataParam): Promise<FetchResponse<201, types.UsersControllerV2CreateUserResponse201>>;
    /**
     * This route updates a logged-in user's profile. Send the updated values in the PUT body.
     * Mind to use your Frontegg subdomain/custom domain as a host. A user token is required
     * for this route. A user token can be obtained after user authentication.
     *
     * @summary Update user profile
     */
    usersControllerV2_updateUserProfile(body: types.UsersControllerV2UpdateUserProfileBodyParam): Promise<FetchResponse<200, types.UsersControllerV2UpdateUserProfileResponse200>>;
    /**
     * This route gets a logged-in user's profile. No params required. Mind to use your
     * Frontegg subdomain/custom domain as a host. A user token is required for this route. A
     * user token can be obtained after user authentication.
     *
     * @summary Get user profile
     */
    usersControllerV2_getUserProfile(): Promise<FetchResponse<200, types.UsersControllerV2GetUserProfileResponse200>>;
    /**
     * Use the V2 route for Invite User. This route is no longer relevant.
     *
     * @summary Create user
     */
    usersControllerV1_createUser(body: types.UsersControllerV1CreateUserBodyParam, metadata: types.UsersControllerV1CreateUserMetadataParam): Promise<FetchResponse<201, types.UsersControllerV1CreateUserResponse201>>;
    /**
     * Get Users v1
     *
     */
    usersControllerV1_getUsers(metadata?: types.UsersControllerV1GetUsersMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route updates a user’s information for a specific tenant. Send the
     * **`frontegg-user-id`** and **`frontegg-tenant-id`** headers to declare which user and
     * which tenant.
     *
     * @summary Update user
     */
    usersControllerV1_updateUser(body: types.UsersControllerV1UpdateUserBodyParam, metadata: types.UsersControllerV1UpdateUserMetadataParam): Promise<FetchResponse<200, types.UsersControllerV1UpdateUserResponse200>>;
    /**
     * This route associates roles to a specific user for a specific tenant. Send the tenant’s
     * ID in the **`frontegg-tenant-id`** header to declare which tenant. Send the role IDs in
     * the POST body. The role IDs need to be an array of strings. Also send the user's ID as a
     * path params.
     *
     * @summary Assign roles to user
     */
    usersControllerV1_addRolesToUser(body: types.UsersControllerV1AddRolesToUserBodyParam, metadata: types.UsersControllerV1AddRolesToUserMetadataParam): Promise<FetchResponse<201, types.UsersControllerV1AddRolesToUserResponse201>>;
    /**
     * This route disassociates roles from a specific user for a specific tenant. Send the
     * tenant’s ID in the **`frontegg-tenant-id`** header to declare which tenant. Send the
     * role IDs in the POST body. The role IDs need to be an array of strings. Also send the
     * user's ID as a path params.
     *
     * @summary Unassign roles from user
     */
    usersControllerV1_deleteRolesFromUser(body: types.UsersControllerV1DeleteRolesFromUserBodyParam, metadata: types.UsersControllerV1DeleteRolesFromUserMetadataParam): Promise<FetchResponse<200, types.UsersControllerV1DeleteRolesFromUserResponse200>>;
    /**
     * This route updates the logged in user’s tenant . The user uses it when they have
     * multiple tenants and they want to change the current tenant they log in to. Send the
     * **`frontegg-user-id`** and **`frontegg-tenant-id`** headers to declare which user and
     * which tenant. Send the tenant ID in the POST body.
     *
     * @summary Update user's active tenant
     */
    usersControllerV1_updateUserTenant(body: types.UsersControllerV1UpdateUserTenantBodyParam, metadata: types.UsersControllerV1UpdateUserTenantMetadataParam): Promise<FetchResponse<200, types.UsersControllerV1UpdateUserTenantResponse200>>;
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
    usersActivationControllerV1_activateUser(body: types.UsersActivationControllerV1ActivateUserBodyParam, metadata: types.UsersActivationControllerV1ActivateUserMetadataParam): Promise<FetchResponse<200, types.UsersActivationControllerV1ActivateUserResponse200>>;
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
    usersActivationControllerV1_getActivationStrategy(metadata: types.UsersActivationControllerV1GetActivationStrategyMetadataParam): Promise<FetchResponse<200, types.UsersActivationControllerV1GetActivationStrategyResponse200>>;
    /**
     * This route accepts an invitation for a user to join a specific tenant. Send the required
     * userId and activation token in the POST body. The userId and activation token appear as
     * a query params in the url Frontegg sends to the user in the activation email.
     *
     * @summary Accept invitation
     */
    usersTenantManagementControllerV1_acceptInvitation(body: types.UsersTenantManagementControllerV1AcceptInvitationBodyParam): Promise<FetchResponse<number, unknown>>;
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
    usersControllerV1_signUpUser(body: types.UsersControllerV1SignUpUserBodyParam, metadata: types.UsersControllerV1SignUpUserMetadataParam): Promise<FetchResponse<201, types.UsersControllerV1SignUpUserResponse201>>;
    /**
     * This route gets a logged-in user's profile. No params required. Mind to use your
     * Frontegg subdomain/custom domain as a host. A user token is required for this route. A
     * user token can be obtained after user authentication.
     *
     * @summary Get user profile
     */
    usersControllerV3_getUserProfile(): Promise<FetchResponse<200, types.UsersControllerV3GetUserProfileResponse200>>;
    /**
     * This route gets the list of tenants that a logged-in user belongs to. No params
     * required. Mind to use your Frontegg subdomain/custom domain as a host. A user token is
     * required for this route. A user token can be obtained after user authentication.
     *
     * @summary Get user tenants
     */
    usersControllerV2_getUserTenants(metadata: types.UsersControllerV2GetUserTenantsMetadataParam): Promise<FetchResponse<200, types.UsersControllerV2GetUserTenantsResponse200>>;
    /**
     * This route gets the list of tenants with hierarchy metadata that a logged-in user
     * belongs to. If the user is a member of several tenants in a tree some might be reduced.
     * No params required. Mind to use your Frontegg subdomain/custom domain as a host. A user
     * token is required for this route. A user token can be obtained after user
     * authentication.
     *
     * @summary Get user tenants' hierarchy
     */
    usersControllerV2_getUserTenantsHierarchy(): Promise<FetchResponse<200, types.UsersControllerV2GetUserTenantsHierarchyResponse200>>;
    /**
     * This route gets the list of permissions and roles that a logged-in user has. No params
     * required. Mind to use your Frontegg subdomain/custom domain as a host. A user token is
     * required for this route. A user token can be obtained after user authentication.
     *
     * @summary Get user permissions and roles
     */
    usersControllerV1_getMeAuthorization(): Promise<FetchResponse<200, types.UsersControllerV1GetMeAuthorizationResponse200>>;
    /**
     * This route gets the list of tenants that a logged-in user belongs to. No params
     * required. Mind to use your Frontegg subdomain/custom domain as a host. A user token is
     * required for this route. A user token can be obtained after user authentication.
     *
     * @summary Get user tenants
     */
    usersControllerV1_getUserTenants(): Promise<FetchResponse<200, types.UsersControllerV1GetUserTenantsResponse200>>;
    /**
     * This route returns all the user's active sessions. Specify the user by sending its ID in
     * frontegg-user-id header.
     *
     * @summary Get user's active sessions
     */
    userSessionsControllerV1_getActiveSessions(metadata: types.UserSessionsControllerV1GetActiveSessionsMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route deletes all user's session. Specify the user by sending its ID in
     * frontegg-user-id header.
     *
     * @summary Delete all user sessions
     */
    userSessionsControllerV1_deleteAllUserActiveSessions(metadata: types.UserSessionsControllerV1DeleteAllUserActiveSessionsMetadataParam): Promise<FetchResponse<number, unknown>>;
    /**
     * This route deletes user's session. Specify the user by sending its ID in
     * frontegg-user-id header and the session ID in the url param.
     *
     * @summary Delete single user's session
     */
    userSessionsControllerV1_deleteUserSession(metadata: types.UserSessionsControllerV1DeleteUserSessionMetadataParam): Promise<FetchResponse<number, unknown>>;
}
declare const createSDK: SDK;
export = createSDK;
