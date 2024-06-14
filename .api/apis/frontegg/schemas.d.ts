declare const $Get: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "User IDs";
                };
                readonly userTenantStatuses: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                        readonly enum: readonly ["PendingInvitation", "PendingLogin", "Activated", "NotActivated"];
                    };
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "Tenant Statuses";
                };
            };
            readonly required: readonly ["userIds"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                };
                readonly tenantsStatuses: {
                    readonly description: "Tenants Statuses";
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly status: {
                                readonly type: "string";
                                readonly enum: readonly ["PendingInvitation", "PendingLogin", "Activated", "NotActivated"];
                                readonly description: "`PendingInvitation` `PendingLogin` `Activated` `NotActivated`";
                            };
                        };
                        readonly required: readonly ["tenantId", "status"];
                    };
                };
            };
            readonly required: readonly ["userId", "tenantsStatuses"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const ApplicationsActiveUserTenantsControllerV1GetUserApplicationActiveTenants: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly applicationActiveTenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly applicationId: {
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "applicationId"];
                    };
                };
            };
            readonly required: readonly ["applicationActiveTenants"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const ApplicationsActiveUserTenantsControllerV1SwitchUserApplicationActiveTenant: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly activeApplicationTenants: {
                readonly description: "List of applications and tenants to set as active, for user";
                readonly type: "array";
                readonly items: {
                    readonly type: "object";
                    readonly properties: {
                        readonly applicationId: {
                            readonly type: "string";
                            readonly description: "Desired application to set active tenant in";
                        };
                        readonly tenantId: {
                            readonly type: "string";
                            readonly description: "Desired tenant to set as active tenant for user in application";
                        };
                    };
                    readonly required: readonly ["applicationId", "tenantId"];
                };
            };
        };
        readonly required: readonly ["activeApplicationTenants"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
};
declare const ApplicationsControllerV1AssignUserToMultipleApplications: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly userId: {
                readonly type: "string";
            };
            readonly tenantId: {
                readonly type: "string";
            };
            readonly appIds: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["userId", "tenantId", "appIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly appId: {
                        readonly type: "string";
                    };
                    readonly userTenantId: {
                        readonly type: "string";
                    };
                    readonly createdAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["appId", "userTenantId", "createdAt"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "201": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly appId: {
                        readonly type: "string";
                    };
                    readonly userTenantId: {
                        readonly type: "string";
                    };
                    readonly createdAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["appId", "userTenantId", "createdAt"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const ApplicationsControllerV1AssignUsersToApplication: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly appId: {
                readonly type: "string";
            };
            readonly tenantId: {
                readonly type: "string";
            };
            readonly userIds: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["appId", "tenantId", "userIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly appId: {
                        readonly type: "string";
                    };
                    readonly userTenantId: {
                        readonly type: "string";
                    };
                    readonly createdAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["appId", "userTenantId", "createdAt"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "201": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly appId: {
                        readonly type: "string";
                    };
                    readonly userTenantId: {
                        readonly type: "string";
                    };
                    readonly createdAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["appId", "userTenantId", "createdAt"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const ApplicationsControllerV1GetApplicationsForMultipleUsers: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userIds"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly userId: {
                        readonly type: "string";
                    };
                    readonly appIds: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "string";
                        };
                    };
                };
                readonly required: readonly ["userId", "appIds"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const ApplicationsControllerV1GetApplicationsForUser: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "string";
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const ApplicationsControllerV1GetUsersForApplication: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly appId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["appId"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "string";
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const ApplicationsControllerV1GetUsersForMultipleApplications: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly appIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["appIds"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly appId: {
                        readonly type: "string";
                    };
                    readonly userIds: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "string";
                        };
                    };
                };
                readonly required: readonly ["appId", "userIds"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const ApplicationsControllerV1UnassignUserFromMultipleApplications: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly userId: {
                readonly type: "string";
            };
            readonly tenantId: {
                readonly type: "string";
            };
            readonly appIds: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["userId", "tenantId", "appIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const ApplicationsControllerV1UnassignUsersFromApplication: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly appId: {
                readonly type: "string";
            };
            readonly tenantId: {
                readonly type: "string";
            };
            readonly userIds: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["appId", "tenantId", "userIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticatioAuthenticationControllerV1AuthenticateLocalUser: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly email: {
                readonly type: "string";
            };
            readonly password: {
                readonly type: "string";
            };
            readonly recaptchaToken: {
                readonly type: "string";
            };
            readonly invitationToken: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["email", "password"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-vendor-host": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The vendor host domain";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly tokenType: {
                    readonly type: "string";
                    readonly default: "bearer";
                };
                readonly mfaRequired: {
                    readonly type: "boolean";
                };
                readonly mfaToken: {
                    readonly type: "string";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaDevices: {
                    readonly type: "object";
                    readonly properties: {
                        readonly webauthn: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly deviceType: {
                                        readonly type: "string";
                                        readonly enum: readonly ["Platform", "CrossPlatform"];
                                        readonly description: "`Platform` `CrossPlatform`";
                                    };
                                    readonly name: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "deviceType", "name"];
                            };
                        };
                        readonly phones: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly phoneNumber: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "phoneNumber"];
                            };
                        };
                        readonly authenticators: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id"];
                            };
                        };
                        readonly emails: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly email: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["email"];
                            };
                        };
                    };
                    readonly required: readonly ["webauthn", "phones", "authenticators", "emails"];
                };
                readonly mfaStrategies: {
                    readonly type: "object";
                    readonly additionalProperties: true;
                };
                readonly qrCode: {
                    readonly type: "string";
                };
                readonly recoveryCode: {
                    readonly type: "string";
                };
                readonly accessToken: {
                    readonly type: "string";
                };
                readonly refreshToken: {
                    readonly type: "string";
                };
                readonly expiresIn: {
                    readonly type: "number";
                };
                readonly expires: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly userEmail: {
                    readonly type: "string";
                };
                readonly emailVerified: {
                    readonly type: "boolean";
                };
                readonly isBreachedPassword: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["mfaRequired", "accessToken", "refreshToken", "expiresIn", "expires"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const AuthenticatioAuthenticationControllerV1Logout: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-vendor-host": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["frontegg-vendor-host"];
        }];
    };
};
declare const AuthenticatioAuthenticationControllerV1RefreshToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {};
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-vendor-host": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["frontegg-vendor-host"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly tokenType: {
                    readonly type: "string";
                    readonly default: "bearer";
                };
                readonly mfaRequired: {
                    readonly type: "boolean";
                };
                readonly mfaToken: {
                    readonly type: "string";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaDevices: {
                    readonly type: "object";
                    readonly properties: {
                        readonly webauthn: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly deviceType: {
                                        readonly type: "string";
                                        readonly enum: readonly ["Platform", "CrossPlatform"];
                                        readonly description: "`Platform` `CrossPlatform`";
                                    };
                                    readonly name: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "deviceType", "name"];
                            };
                        };
                        readonly phones: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly phoneNumber: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "phoneNumber"];
                            };
                        };
                        readonly authenticators: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id"];
                            };
                        };
                        readonly emails: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly email: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["email"];
                            };
                        };
                    };
                    readonly required: readonly ["webauthn", "phones", "authenticators", "emails"];
                };
                readonly mfaStrategies: {
                    readonly type: "object";
                    readonly additionalProperties: true;
                };
                readonly qrCode: {
                    readonly type: "string";
                };
                readonly recoveryCode: {
                    readonly type: "string";
                };
                readonly accessToken: {
                    readonly type: "string";
                };
                readonly refreshToken: {
                    readonly type: "string";
                };
                readonly expiresIn: {
                    readonly type: "number";
                };
                readonly expires: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly userEmail: {
                    readonly type: "string";
                };
                readonly emailVerified: {
                    readonly type: "boolean";
                };
                readonly isBreachedPassword: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["mfaRequired", "accessToken", "refreshToken", "expiresIn", "expires"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const AuthenticationApiTokenControllerV2AuthApiToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly clientId: {
                readonly type: "string";
            };
            readonly secret: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["clientId", "secret"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly access_token: {
                    readonly type: "string";
                };
                readonly refresh_token: {
                    readonly type: "string";
                };
                readonly expires_in: {
                    readonly type: "number";
                };
                readonly expires: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["access_token", "refresh_token", "expires_in", "expires"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const AuthenticationApiTokenControllerV2RefreshToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly refreshToken: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["refreshToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly access_token: {
                    readonly type: "string";
                };
                readonly refresh_token: {
                    readonly type: "string";
                };
                readonly expires_in: {
                    readonly type: "number";
                };
                readonly expires: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["access_token", "refresh_token", "expires_in", "expires"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const AuthenticationMfaControllerV1EnrollAuthenticatorMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly token: {
                readonly type: "string";
            };
            readonly mfaToken: {
                readonly type: "string";
            };
            readonly rememberDevice: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["token", "mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationMfaControllerV1EnrollSmsMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly otcToken: {
                readonly type: "string";
            };
            readonly code: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["otcToken", "code"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationMfaControllerV1EnrollWebauthnMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly deviceType: {
                readonly type: "string";
                readonly enum: readonly ["Platform", "CrossPlatform"];
            };
            readonly webauthnToken: {
                readonly type: "string";
            };
            readonly options: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly response: {
                        readonly type: "object";
                        readonly properties: {
                            readonly clientDataJSON: {
                                readonly type: "string";
                            };
                            readonly attestationObject: {
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["clientDataJSON", "attestationObject"];
                    };
                    readonly deviceType: {
                        readonly type: "string";
                        readonly enum: readonly ["Platform", "CrossPlatform"];
                    };
                };
                readonly required: readonly ["id", "response"];
            };
            readonly mfaToken: {
                readonly type: "string";
            };
            readonly rememberDevice: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["deviceType", "webauthnToken", "options", "mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationMfaControllerV1PreEnrollAuthenticatorMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly mfaToken: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationMfaControllerV1PreEnrollSmsMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly phoneNumber: {
                readonly type: "string";
                readonly pattern: "phoneNumberRegexp";
            };
        };
        readonly required: readonly ["phoneNumber"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationMfaControllerV1PreEnrollWebauthnMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly mfaToken: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationMfaControllerV1PreVerifyEmailOtcMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly mfaToken: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationMfaControllerV1PreVerifySmsMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly mfaToken: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly deviceId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["deviceId"];
        }];
    };
};
declare const AuthenticationMfaControllerV1PreVerifyWebauthnMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly mfaToken: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly deviceId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["deviceId"];
        }];
    };
};
declare const AuthenticationMfaControllerV1RecoverMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly recoveryCode: {
                readonly type: "string";
            };
            readonly email: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["recoveryCode", "email"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationMfaControllerV1VerifyAuthenticatorMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly value: {
                readonly type: "string";
            };
            readonly mfaToken: {
                readonly type: "string";
            };
            readonly rememberDevice: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["value", "mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly deviceId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["deviceId"];
        }];
    };
};
declare const AuthenticationMfaControllerV1VerifyAuthenticatorMfaCode: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly value: {
                readonly type: "string";
            };
            readonly mfaToken: {
                readonly type: "string";
            };
            readonly rememberDevice: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["value", "mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationMfaControllerV1VerifyEmailOtcMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly otcToken: {
                readonly type: "string";
            };
            readonly code: {
                readonly type: "string";
            };
            readonly mfaToken: {
                readonly type: "string";
            };
            readonly rememberDevice: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["otcToken", "code", "mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationMfaControllerV1VerifySmsMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly otcToken: {
                readonly type: "string";
            };
            readonly code: {
                readonly type: "string";
            };
            readonly mfaToken: {
                readonly type: "string";
            };
            readonly rememberDevice: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["otcToken", "code", "mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly deviceId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["deviceId"];
        }];
    };
};
declare const AuthenticationMfaControllerV1VerifyWebauthnMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly webauthnToken: {
                readonly type: "string";
            };
            readonly options: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly response: {
                        readonly type: "object";
                        readonly properties: {
                            readonly clientDataJSON: {
                                readonly type: "string";
                            };
                            readonly authenticatorData: {
                                readonly type: "string";
                            };
                            readonly signature: {
                                readonly type: "string";
                            };
                            readonly userHandle: {
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["clientDataJSON", "authenticatorData", "signature", "userHandle"];
                    };
                    readonly recaptchaToken: {
                        readonly type: "string";
                    };
                    readonly invitationToken: {
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["id", "response"];
            };
            readonly mfaToken: {
                readonly type: "string";
            };
            readonly rememberDevice: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["webauthnToken", "options", "mfaToken"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly deviceId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["deviceId"];
        }];
    };
};
declare const AuthenticationPasswordlessControllerV1EmailCodePostLogin: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly token: {
                readonly type: "string";
                readonly description: "One time code to login with - get it from the email sent after prelogin request";
            };
            readonly recaptchaToken: {
                readonly type: "string";
            };
            readonly invitationToken: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["token"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly tokenType: {
                    readonly type: "string";
                    readonly default: "bearer";
                };
                readonly mfaRequired: {
                    readonly type: "boolean";
                };
                readonly mfaToken: {
                    readonly type: "string";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaDevices: {
                    readonly type: "object";
                    readonly properties: {
                        readonly webauthn: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly deviceType: {
                                        readonly type: "string";
                                        readonly enum: readonly ["Platform", "CrossPlatform"];
                                        readonly description: "`Platform` `CrossPlatform`";
                                    };
                                    readonly name: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "deviceType", "name"];
                            };
                        };
                        readonly phones: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly phoneNumber: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "phoneNumber"];
                            };
                        };
                        readonly authenticators: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id"];
                            };
                        };
                        readonly emails: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly email: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["email"];
                            };
                        };
                    };
                    readonly required: readonly ["webauthn", "phones", "authenticators", "emails"];
                };
                readonly mfaStrategies: {
                    readonly type: "object";
                    readonly additionalProperties: true;
                };
                readonly qrCode: {
                    readonly type: "string";
                };
                readonly recoveryCode: {
                    readonly type: "string";
                };
                readonly accessToken: {
                    readonly type: "string";
                };
                readonly refreshToken: {
                    readonly type: "string";
                };
                readonly expiresIn: {
                    readonly type: "number";
                };
                readonly expires: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly userEmail: {
                    readonly type: "string";
                };
                readonly emailVerified: {
                    readonly type: "boolean";
                };
                readonly isBreachedPassword: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["mfaRequired", "accessToken", "refreshToken", "expiresIn", "expires"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const AuthenticationPasswordlessControllerV1EmailCodePrelogin: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly recaptchaToken: {
                readonly type: "string";
            };
            readonly invitationToken: {
                readonly type: "string";
            };
            readonly email: {
                readonly type: "string";
            };
            readonly userId: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["email", "userId"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationPasswordlessControllerV1MagicLinkPostLogin: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly token: {
                readonly type: "string";
                readonly description: "One time code to login with - get it from the email sent after prelogin request";
            };
            readonly recaptchaToken: {
                readonly type: "string";
            };
            readonly invitationToken: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["token"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly tokenType: {
                    readonly type: "string";
                    readonly default: "bearer";
                };
                readonly mfaRequired: {
                    readonly type: "boolean";
                };
                readonly mfaToken: {
                    readonly type: "string";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaDevices: {
                    readonly type: "object";
                    readonly properties: {
                        readonly webauthn: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly deviceType: {
                                        readonly type: "string";
                                        readonly enum: readonly ["Platform", "CrossPlatform"];
                                        readonly description: "`Platform` `CrossPlatform`";
                                    };
                                    readonly name: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "deviceType", "name"];
                            };
                        };
                        readonly phones: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly phoneNumber: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "phoneNumber"];
                            };
                        };
                        readonly authenticators: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id"];
                            };
                        };
                        readonly emails: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly email: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["email"];
                            };
                        };
                    };
                    readonly required: readonly ["webauthn", "phones", "authenticators", "emails"];
                };
                readonly mfaStrategies: {
                    readonly type: "object";
                    readonly additionalProperties: true;
                };
                readonly qrCode: {
                    readonly type: "string";
                };
                readonly recoveryCode: {
                    readonly type: "string";
                };
                readonly accessToken: {
                    readonly type: "string";
                };
                readonly refreshToken: {
                    readonly type: "string";
                };
                readonly expiresIn: {
                    readonly type: "number";
                };
                readonly expires: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly userEmail: {
                    readonly type: "string";
                };
                readonly emailVerified: {
                    readonly type: "boolean";
                };
                readonly isBreachedPassword: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["mfaRequired", "accessToken", "refreshToken", "expiresIn", "expires"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const AuthenticationPasswordlessControllerV1MagicLinkPrelogin: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly recaptchaToken: {
                readonly type: "string";
            };
            readonly invitationToken: {
                readonly type: "string";
            };
            readonly email: {
                readonly type: "string";
            };
            readonly userId: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["email", "userId"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const AuthenticationPasswordlessControllerV1SmsCodePostLogin: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly token: {
                readonly type: "string";
                readonly description: "One time code to login with - get it from the email sent after prelogin request";
            };
            readonly recaptchaToken: {
                readonly type: "string";
            };
            readonly invitationToken: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["token"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly tokenType: {
                    readonly type: "string";
                    readonly default: "bearer";
                };
                readonly mfaRequired: {
                    readonly type: "boolean";
                };
                readonly mfaToken: {
                    readonly type: "string";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaDevices: {
                    readonly type: "object";
                    readonly properties: {
                        readonly webauthn: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly deviceType: {
                                        readonly type: "string";
                                        readonly enum: readonly ["Platform", "CrossPlatform"];
                                        readonly description: "`Platform` `CrossPlatform`";
                                    };
                                    readonly name: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "deviceType", "name"];
                            };
                        };
                        readonly phones: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly phoneNumber: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "phoneNumber"];
                            };
                        };
                        readonly authenticators: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id"];
                            };
                        };
                        readonly emails: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly email: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["email"];
                            };
                        };
                    };
                    readonly required: readonly ["webauthn", "phones", "authenticators", "emails"];
                };
                readonly mfaStrategies: {
                    readonly type: "object";
                    readonly additionalProperties: true;
                };
                readonly qrCode: {
                    readonly type: "string";
                };
                readonly recoveryCode: {
                    readonly type: "string";
                };
                readonly accessToken: {
                    readonly type: "string";
                };
                readonly refreshToken: {
                    readonly type: "string";
                };
                readonly expiresIn: {
                    readonly type: "number";
                };
                readonly expires: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly userEmail: {
                    readonly type: "string";
                };
                readonly emailVerified: {
                    readonly type: "boolean";
                };
                readonly isBreachedPassword: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["mfaRequired", "accessToken", "refreshToken", "expiresIn", "expires"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const AuthenticationPasswordlessControllerV1SmsCodePreLogin: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly recaptchaToken: {
                readonly type: "string";
            };
            readonly invitationToken: {
                readonly type: "string";
            };
            readonly email: {
                readonly type: "string";
            };
            readonly userId: {
                readonly type: "string";
            };
            readonly phoneNumber: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["email", "userId", "phoneNumber"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly resetPhoneNumberToken: {
                    readonly type: "string";
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const CaptchaPolicyControllerCreateCaptchaPolicy: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enabled: {
                readonly type: "boolean";
            };
            readonly siteKey: {
                readonly type: "string";
            };
            readonly secretKey: {
                readonly type: "string";
            };
            readonly minScore: {
                readonly type: "number";
            };
            readonly ignoredEmails: {
                readonly description: "Captcha validation will be skipped for those emails.";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["enabled", "siteKey", "secretKey", "minScore"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly siteKey: {
                    readonly type: "string";
                };
                readonly secretKey: {
                    readonly type: "string";
                };
                readonly enabled: {
                    readonly type: "boolean";
                };
                readonly minScore: {
                    readonly type: "number";
                };
                readonly ignoredEmails: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "siteKey", "secretKey", "enabled", "minScore", "ignoredEmails", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const CaptchaPolicyControllerGetCaptchaPolicy: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly siteKey: {
                    readonly type: "string";
                };
                readonly secretKey: {
                    readonly type: "string";
                };
                readonly enabled: {
                    readonly type: "boolean";
                };
                readonly minScore: {
                    readonly type: "number";
                };
                readonly ignoredEmails: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "siteKey", "secretKey", "enabled", "minScore", "ignoredEmails", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const CaptchaPolicyControllerUpdateCaptchaPolicy: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enabled: {
                readonly type: "boolean";
            };
            readonly siteKey: {
                readonly type: "string";
            };
            readonly secretKey: {
                readonly type: "string";
            };
            readonly minScore: {
                readonly type: "number";
            };
            readonly ignoredEmails: {
                readonly description: "Captcha validation will be skipped for those emails.";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["enabled", "siteKey", "secretKey", "minScore"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly siteKey: {
                    readonly type: "string";
                };
                readonly secretKey: {
                    readonly type: "string";
                };
                readonly enabled: {
                    readonly type: "boolean";
                };
                readonly minScore: {
                    readonly type: "number";
                };
                readonly ignoredEmails: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "siteKey", "secretKey", "enabled", "minScore", "ignoredEmails", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const DelegationConfigurationControllerV1CreateOrUpdateDelegationConfiguration: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enabled: {
                readonly type: "boolean";
                readonly description: "Used to enable or disable delegation for access tokens created using Token Exchange.";
                readonly examples: readonly ["true"];
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const DelegationConfigurationControllerV1GetDelegationConfiguration: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly enabled: {
                    readonly type: "boolean";
                    readonly description: "Indicates whether delegation has been enabled or disabled.";
                    readonly examples: readonly ["true"];
                };
            };
            readonly required: readonly ["enabled"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const DomainRestrictionsControllerCreateBulkDomainsRestriction: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly type: {
                readonly type: "string";
                readonly enum: readonly ["ALLOW", "BLOCK"];
            };
            readonly domains: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                    readonly pattern: "domainRegexString";
                };
            };
        };
        readonly required: readonly ["type", "domains"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly domain: {
                        readonly type: "string";
                    };
                    readonly type: {
                        readonly enum: readonly ["ALLOW", "BLOCK"];
                        readonly type: "string";
                        readonly description: "`ALLOW` `BLOCK`";
                    };
                };
                readonly required: readonly ["id", "domain", "type"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const DomainRestrictionsControllerCreateDomainRestriction: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly domain: {
                readonly type: "string";
                readonly pattern: "domainRegex";
            };
            readonly type: {
                readonly type: "string";
                readonly enum: readonly ["ALLOW", "BLOCK"];
            };
        };
        readonly required: readonly ["domain", "type"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly domain: {
                    readonly type: "string";
                };
                readonly type: {
                    readonly enum: readonly ["ALLOW", "BLOCK"];
                    readonly type: "string";
                    readonly description: "`ALLOW` `BLOCK`";
                };
            };
            readonly required: readonly ["id", "domain", "type"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const DomainRestrictionsControllerDeleteDomainRestriction: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const DomainRestrictionsControllerGetDomainRestrictionsConfig: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly active: {
                    readonly type: "boolean";
                };
                readonly listType: {
                    readonly enum: readonly ["ALLOW", "BLOCK"];
                    readonly type: "string";
                    readonly description: "`ALLOW` `BLOCK`";
                };
                readonly blockPublicDomains: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["active", "listType", "blockPublicDomains"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const DomainRestrictionsControllerUpdateDomainRestrictionsConfig: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly active: {
                readonly type: "boolean";
            };
            readonly blockPublicDomains: {
                readonly type: "boolean";
            };
            readonly type: {
                readonly type: "string";
                readonly enum: readonly ["ALLOW", "BLOCK"];
            };
        };
        readonly required: readonly ["active"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly active: {
                    readonly type: "boolean";
                };
                readonly listType: {
                    readonly enum: readonly ["ALLOW", "BLOCK"];
                    readonly type: "string";
                    readonly description: "`ALLOW` `BLOCK`";
                };
                readonly blockPublicDomains: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["active", "listType", "blockPublicDomains"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const GetInvitationConfiguration: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly tenantInvitationsAllowed: {
                    readonly type: "boolean";
                };
                readonly emailsEnabled: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["tenantInvitationsAllowed", "emailsEnabled"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const GroupsControllerV1AddRolesToGroup: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly roleIds: {
                readonly description: "Will add / remove requested roles from the group";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
                readonly examples: readonly ["5fbae0d3-a3b7-4b1e-8d64-6c9428f84aae", "8b2d0f9a-f39e-49b3-98ca-93c85c06d1a7"];
            };
        };
        readonly required: readonly ["roleIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly groupId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["groupId"];
        }];
    };
};
declare const GroupsControllerV1AddUsersToGroup: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly userIds: {
                readonly description: "An array of User IDs to add / remove existing users to / from the group.";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
                readonly examples: readonly ["262io276-3c5v-9y31-ba03-281674a89d4c", "eeooc819-87dd-1cdd-b81d-e8829vm9d684"];
            };
        };
        readonly required: readonly ["userIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly groupId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["groupId"];
        }];
    };
};
declare const GroupsControllerV1CreateGroup: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly color: {
                readonly type: "string";
                readonly description: "Color for group display";
            };
            readonly description: {
                readonly type: "string";
                readonly description: "Group description";
            };
            readonly metadata: {
                readonly type: "string";
                readonly description: "Stringified JSON object";
                readonly examples: readonly ["{}"];
            };
            readonly name: {
                readonly type: "string";
                readonly description: "Group unique name";
            };
        };
        readonly required: readonly ["name"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly color: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt"];
                    };
                };
                readonly users: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly email: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly profilePictureUrl: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly activatedForTenant: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "email", "name", "profilePictureUrl", "createdAt", "activatedForTenant"];
                    };
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2`";
                };
            };
            readonly required: readonly ["id", "name", "color", "description", "metadata", "roles", "users", "managedBy"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const GroupsControllerV1CreateOrUpdateGroupsConfiguration: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enabled: {
                readonly type: "boolean";
                readonly description: "Determine whether groups are enabled/disabled. Default value is true.";
                readonly default: true;
            };
            readonly rolesEnabled: {
                readonly type: "boolean";
                readonly description: "Determine whether groups can have roles or not. Default value is true.";
                readonly default: true;
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const GroupsControllerV1DeleteGroup: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const GroupsControllerV1GetAllGroups: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly _groupsRelations: {
                    readonly enum: readonly ["roles", "users", "rolesAndUsers"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const GroupsControllerV1GetGroupById: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly _groupsRelations: {
                    readonly enum: readonly ["roles", "users", "rolesAndUsers"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const GroupsControllerV1GetGroupsByIds: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly groupsIds: {
                readonly description: "Group IDs";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["groupsIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly _groupsRelations: {
                    readonly enum: readonly ["roles", "users", "rolesAndUsers"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const GroupsControllerV1RemoveRolesFromGroup: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly roleIds: {
                readonly description: "Will add / remove requested roles from the group";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
                readonly examples: readonly ["5fbae0d3-a3b7-4b1e-8d64-6c9428f84aae", "8b2d0f9a-f39e-49b3-98ca-93c85c06d1a7"];
            };
        };
        readonly required: readonly ["roleIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly groupId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["groupId"];
        }];
    };
};
declare const GroupsControllerV1RemoveUsersFromGroup: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly userIds: {
                readonly description: "An array of User IDs to add / remove existing users to / from the group.";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
                readonly examples: readonly ["262io276-3c5v-9y31-ba03-281674a89d4c", "eeooc819-87dd-1cdd-b81d-e8829vm9d684"];
            };
        };
        readonly required: readonly ["userIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly groupId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["groupId"];
        }];
    };
};
declare const GroupsControllerV1UpdateGroup: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly color: {
                readonly type: "string";
                readonly description: "Color for group display";
            };
            readonly description: {
                readonly type: "string";
                readonly description: "Group description";
            };
            readonly metadata: {
                readonly type: "string";
                readonly description: "Stringified JSON object";
                readonly examples: readonly ["{}"];
            };
            readonly name: {
                readonly type: "string";
                readonly description: "Group unique name";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly color: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt"];
                    };
                };
                readonly users: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly email: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly profilePictureUrl: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly activatedForTenant: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "email", "name", "profilePictureUrl", "createdAt", "activatedForTenant"];
                    };
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2`";
                };
            };
            readonly required: readonly ["id", "name", "color", "description", "metadata", "roles", "users", "managedBy"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const GroupsControllerV2GetAllGroupsPaginated: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly _groupsRelations: {
                    readonly enum: readonly ["roles", "users", "rolesAndUsers"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _limit: {
                    readonly minimum: 1;
                    readonly type: "number";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _offset: {
                    readonly minimum: 0;
                    readonly type: "number";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _sortBy: {
                    readonly enum: readonly ["id", "name", "createdAt", "updatedAt"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _order: {
                    readonly enum: readonly ["ASC", "DESC"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const IPRestrictionsControllerV1CreateDomainRestriction: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly strategy: {
                readonly enum: readonly ["ALLOW", "BLOCK"];
                readonly type: "string";
            };
            readonly isActive: {
                readonly type: "boolean";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const IPRestrictionsControllerV1CreateIpRestriction: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly ip: {
                readonly type: "string";
                readonly description: "IP or CIDR (v4 and v6 are supported)";
            };
            readonly description: {
                readonly type: "string";
            };
            readonly strategy: {
                readonly type: "string";
                readonly enum: readonly ["ALLOW", "BLOCK"];
            };
            readonly isActive: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["ip", "strategy"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const IPRestrictionsControllerV1DeleteIpRestrictionById: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const IPRestrictionsControllerV1GetAllIpRestrictions: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly _limit: {
                    readonly minimum: 1;
                    readonly type: "number";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _offset: {
                    readonly minimum: 0;
                    readonly type: "number";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _filter: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const LockoutPolicyControllerCreateLockoutPolicy: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enabled: {
                readonly type: "boolean";
                readonly description: "Determine whether the Lockout Policy is enabled";
            };
            readonly maxAttempts: {
                readonly type: "number";
                readonly description: "The number of the maximum login attempts user can do";
                readonly minimum: 1;
            };
        };
        readonly required: readonly ["enabled", "maxAttempts"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly enabled: {
                    readonly type: "boolean";
                };
                readonly maxAttempts: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "enabled", "maxAttempts", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const LockoutPolicyControllerGetLockoutPolicy: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly enabled: {
                    readonly type: "boolean";
                };
                readonly maxAttempts: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "enabled", "maxAttempts", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const LockoutPolicyControllerUpdateLockoutPolicy: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enabled: {
                readonly type: "boolean";
                readonly description: "Determine whether the Lockout Policy is enabled";
            };
            readonly maxAttempts: {
                readonly type: "number";
                readonly description: "The number of the maximum login attempts user can do";
                readonly minimum: 1;
            };
        };
        readonly required: readonly ["enabled", "maxAttempts"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly enabled: {
                    readonly type: "boolean";
                };
                readonly maxAttempts: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "enabled", "maxAttempts", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const MFaStrategiesControllerV1CreateOrUpdateMfaStrategy: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly isActive: {
                readonly type: "boolean";
            };
            readonly strategy: {
                readonly type: "string";
                readonly enum: readonly ["AuthenticatorApp", "WebAuthnPlatform", "WebAuthnCrossPlatform", "SMS"];
            };
        };
        readonly required: readonly ["isActive", "strategy"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const MailConfigControllerCreateOrUpdateMailConfig: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly secret: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["secret"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const MailConfigControllerGetMailConfig: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly secret: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["secret", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const MailV1ControllerAddOrUpdateTemplate: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly type: {
                readonly type: "string";
                readonly enum: readonly ["ResetPassword", "ActivateUser", "InviteToTenant", "PwnedPassword", "MagicLink", "OTC", "ConnectNewDevice", "UserUsedInvitation", "ResetPhoneNumber", "BulkInvitesToTenant", "MFAEnroll", "MFAUnenroll", "NewMFAMethod", "MFARecoveryCode", "RemoveMFAMethod", "EmailVerification", "BruteForceProtection", "SuspiciousIP", "MFAOTC", "ImpossibleTravel", "BotDetection", "SmsAuthenticationEnabled"];
            };
            readonly senderEmail: {
                readonly type: "string";
            };
            readonly redirectURL: {
                readonly type: "string";
                readonly description: "Only required for: ResetPassword, ActivateUser, InviteToTenant, MagicLink, BulkInvitesToTenant";
            };
            readonly htmlTemplate: {
                readonly type: "string";
                readonly maxLength: 100000;
            };
            readonly subject: {
                readonly type: "string";
            };
            readonly fromName: {
                readonly type: "string";
            };
            readonly successRedirectUrl: {
                readonly type: "string";
            };
            readonly active: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["type"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly additionalProperties: true;
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const MailV1ControllerDeleteTemplate: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly templateId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["templateId"];
        }];
    };
};
declare const MailV1ControllerGetDefaultTemplateConfiguration: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly type: {
                    readonly enum: readonly ["ResetPassword", "ActivateUser", "InviteToTenant", "PwnedPassword", "MagicLink", "OTC", "ConnectNewDevice", "UserUsedInvitation", "ResetPhoneNumber", "BulkInvitesToTenant", "MFAEnroll", "MFAUnenroll", "NewMFAMethod", "MFARecoveryCode", "RemoveMFAMethod", "EmailVerification", "BruteForceProtection", "SuspiciousIP", "MFAOTC", "ImpossibleTravel", "BotDetection", "SmsAuthenticationEnabled"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The email template type";
                };
            };
            readonly required: readonly ["type"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly htmlTemplate: {
                    readonly type: "string";
                };
                readonly senderEmail: {
                    readonly type: "string";
                };
                readonly redirectURL: {
                    readonly type: "string";
                };
                readonly successRedirectUrl: {
                    readonly type: "string";
                };
                readonly subject: {
                    readonly type: "string";
                };
                readonly fromName: {
                    readonly type: "string";
                };
                readonly active: {
                    readonly type: "boolean";
                };
                readonly type: {
                    readonly type: "object";
                    readonly additionalProperties: true;
                };
                readonly redirectURLPattern: {
                    readonly type: "string";
                };
                readonly successRedirectUrlPattern: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["htmlTemplate", "senderEmail", "redirectURL", "successRedirectUrl", "subject", "fromName", "active", "type"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const MailV1ControllerGetTemplateConfiguration: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly type: {
                    readonly enum: readonly ["ResetPassword", "ActivateUser", "InviteToTenant", "PwnedPassword", "MagicLink", "OTC", "ConnectNewDevice", "UserUsedInvitation", "ResetPhoneNumber", "BulkInvitesToTenant", "MFAEnroll", "MFAUnenroll", "NewMFAMethod", "MFARecoveryCode", "RemoveMFAMethod", "EmailVerification", "BruteForceProtection", "SuspiciousIP", "MFAOTC", "ImpossibleTravel", "BotDetection", "SmsAuthenticationEnabled"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly htmlTemplate: {
                        readonly type: "string";
                    };
                    readonly senderEmail: {
                        readonly type: "string";
                    };
                    readonly redirectURL: {
                        readonly type: "string";
                    };
                    readonly successRedirectUrl: {
                        readonly type: "string";
                    };
                    readonly subject: {
                        readonly type: "string";
                    };
                    readonly fromName: {
                        readonly type: "string";
                    };
                    readonly active: {
                        readonly type: "boolean";
                    };
                    readonly type: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                    readonly redirectURLPattern: {
                        readonly type: "string";
                    };
                    readonly successRedirectUrlPattern: {
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["htmlTemplate", "senderEmail", "redirectURL", "successRedirectUrl", "subject", "fromName", "active", "type"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const MfaControllerGetMfaConfig: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly authenticationApp: {
                    readonly type: "object";
                    readonly properties: {
                        readonly active: {
                            readonly type: "boolean";
                        };
                        readonly serviceName: {
                            readonly type: "string";
                        };
                    };
                    readonly required: readonly ["active", "serviceName"];
                };
                readonly sms: {
                    readonly type: "object";
                    readonly properties: {
                        readonly active: {
                            readonly type: "boolean";
                        };
                        readonly tokenLifetimeSeconds: {
                            readonly type: "number";
                        };
                    };
                    readonly required: readonly ["active", "tokenLifetimeSeconds"];
                };
                readonly email: {
                    readonly type: "object";
                    readonly properties: {
                        readonly active: {
                            readonly type: "boolean";
                        };
                        readonly tokenLifetimeSeconds: {
                            readonly type: "number";
                        };
                        readonly sender: {
                            readonly type: "string";
                        };
                    };
                    readonly required: readonly ["active", "tokenLifetimeSeconds", "sender"];
                };
            };
            readonly required: readonly ["authenticationApp", "sms", "email"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const MfaControllerUpsertMfaConfig: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly authenticationApp: {
                readonly type: "object";
                readonly properties: {
                    readonly active: {
                        readonly type: "boolean";
                    };
                    readonly serviceName: {
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["active", "serviceName"];
            };
            readonly sms: {
                readonly type: "object";
                readonly properties: {
                    readonly active: {
                        readonly type: "boolean";
                    };
                    readonly tokenLifetimeSeconds: {
                        readonly type: "number";
                        readonly minimum: 300;
                    };
                };
                readonly required: readonly ["active", "tokenLifetimeSeconds"];
            };
            readonly email: {
                readonly type: "object";
                readonly properties: {
                    readonly active: {
                        readonly type: "boolean";
                    };
                    readonly tokenLifetimeSeconds: {
                        readonly type: "number";
                        readonly minimum: 300;
                    };
                    readonly sender: {
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["active", "tokenLifetimeSeconds", "sender"];
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly authenticationApp: {
                    readonly type: "object";
                    readonly properties: {
                        readonly active: {
                            readonly type: "boolean";
                        };
                        readonly serviceName: {
                            readonly type: "string";
                        };
                    };
                    readonly required: readonly ["active", "serviceName"];
                };
                readonly sms: {
                    readonly type: "object";
                    readonly properties: {
                        readonly active: {
                            readonly type: "boolean";
                        };
                        readonly tokenLifetimeSeconds: {
                            readonly type: "number";
                        };
                    };
                    readonly required: readonly ["active", "tokenLifetimeSeconds"];
                };
                readonly email: {
                    readonly type: "object";
                    readonly properties: {
                        readonly active: {
                            readonly type: "boolean";
                        };
                        readonly tokenLifetimeSeconds: {
                            readonly type: "number";
                        };
                        readonly sender: {
                            readonly type: "string";
                        };
                    };
                    readonly required: readonly ["active", "tokenLifetimeSeconds", "sender"];
                };
            };
            readonly required: readonly ["authenticationApp", "sms", "email"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PasswordHistoryPolicyControllerCreatePolicy: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enabled: {
                readonly type: "boolean";
                readonly description: "Detemine whether the history policy is enbaled.";
                readonly default: false;
            };
            readonly historySize: {
                readonly type: "number";
                readonly description: "Number of passwords per user to remember in the history.";
                readonly maximum: 10;
                readonly minimum: 1;
                readonly default: 1;
            };
        };
        readonly required: readonly ["enabled", "historySize"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly enabled: {
                    readonly type: "boolean";
                };
                readonly historySize: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "enabled", "historySize", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PasswordHistoryPolicyControllerGetPolicy: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly enabled: {
                    readonly type: "boolean";
                };
                readonly historySize: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "enabled", "historySize", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PasswordHistoryPolicyControllerUpdatePolicy: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enabled: {
                readonly type: "boolean";
                readonly description: "Detemine whether the history policy is enbaled.";
                readonly default: false;
            };
            readonly historySize: {
                readonly type: "number";
                readonly description: "Number of passwords per user to remember in the history.";
                readonly maximum: 10;
                readonly minimum: 1;
                readonly default: 1;
            };
        };
        readonly required: readonly ["enabled", "historySize"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly enabled: {
                    readonly type: "boolean";
                };
                readonly historySize: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "enabled", "historySize", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PasswordPolicyControllerAddOrUpdatePasswordConfig: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly allowPassphrases: {
                readonly type: "boolean";
            };
            readonly maxLength: {
                readonly type: "number";
            };
            readonly minLength: {
                readonly type: "number";
            };
            readonly minPhraseLength: {
                readonly type: "number";
            };
            readonly minOptionalTestsToPass: {
                readonly type: "number";
            };
            readonly blockPwnedPasswords: {
                readonly type: "boolean";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly allowPassphrases: {
                    readonly type: "boolean";
                };
                readonly maxLength: {
                    readonly type: "number";
                };
                readonly minLength: {
                    readonly type: "number";
                };
                readonly minPhraseLength: {
                    readonly type: "number";
                };
                readonly minOptionalTestsToPass: {
                    readonly type: "number";
                };
                readonly blockPwnedPasswords: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["blockPwnedPasswords"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PasswordPolicyControllerGetPasswordConfig: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly allowPassphrases: {
                    readonly type: "boolean";
                };
                readonly maxLength: {
                    readonly type: "number";
                };
                readonly minLength: {
                    readonly type: "number";
                };
                readonly minPhraseLength: {
                    readonly type: "number";
                };
                readonly minOptionalTestsToPass: {
                    readonly type: "number";
                };
                readonly blockPwnedPasswords: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["blockPwnedPasswords"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsCategoriesControllerCreatePermissionCategory: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly name: {
                readonly type: "string";
            };
            readonly description: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["name"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: readonly ["string", "null"];
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly feCategory: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["id", "name", "description", "createdAt", "feCategory"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsCategoriesControllerDeleteCategory: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly categoryId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["categoryId"];
        }];
    };
};
declare const PermissionsCategoriesControllerGetAllCategoriesWithPermissions: {
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly name: {
                        readonly type: "string";
                    };
                    readonly description: {
                        readonly type: readonly ["string", "null"];
                    };
                    readonly createdAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly feCategory: {
                        readonly type: "boolean";
                    };
                };
                readonly required: readonly ["id", "name", "description", "createdAt", "feCategory"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsCategoriesControllerUpdateCategory: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly name: {
                readonly type: "string";
            };
            readonly description: {
                readonly type: "string";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly categoryId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["categoryId"];
        }];
    };
};
declare const PermissionsControllerV1AddPermissions: {
    readonly body: {
        readonly type: "array";
        readonly items: {
            readonly type: "object";
            readonly properties: {
                readonly key: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly categoryId: {
                    readonly type: "string";
                };
                readonly assignmentType: {
                    readonly type: "string";
                    readonly enum: readonly ["NEVER", "ALWAYS", "ASSIGNABLE"];
                };
            };
            readonly required: readonly ["key", "name"];
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly key: {
                        readonly type: "string";
                    };
                    readonly name: {
                        readonly type: "string";
                    };
                    readonly description: {
                        readonly type: "string";
                    };
                    readonly createdAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly updatedAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly roleIds: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "string";
                        };
                    };
                    readonly categoryId: {
                        readonly type: "string";
                    };
                    readonly fePermission: {
                        readonly type: "boolean";
                    };
                };
                readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsControllerV1AddRoles: {
    readonly body: {
        readonly type: "array";
        readonly items: {
            readonly type: "object";
            readonly properties: {
                readonly key: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly isDefault: {
                    readonly type: "boolean";
                    readonly description: "This role will be assigned for every user that will be added without specified roles";
                };
                readonly migrateRole: {
                    readonly type: "boolean";
                    readonly description: "Set this property to `true` together with `isDefault` in order to assign this role to all users";
                };
                readonly firstUserRole: {
                    readonly type: "boolean";
                    readonly description: "This role will be assigned to the first user of a tenant (new tenants only)";
                };
                readonly level: {
                    readonly type: "number";
                    readonly minimum: 0;
                    readonly maximum: 32767;
                    readonly description: "Role level for roles elevation, lower level means stronger role.";
                };
            };
            readonly required: readonly ["key", "name", "level"];
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "For relating a role to a specific tenant, use `get tenants` API to find the tenant ids";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly vendorId: {
                        readonly type: "string";
                    };
                    readonly tenantId: {
                        readonly type: "string";
                    };
                    readonly key: {
                        readonly type: "string";
                    };
                    readonly name: {
                        readonly type: "string";
                    };
                    readonly description: {
                        readonly type: "string";
                    };
                    readonly isDefault: {
                        readonly type: "boolean";
                    };
                    readonly firstUserRole: {
                        readonly type: "boolean";
                    };
                    readonly level: {
                        readonly type: "number";
                    };
                    readonly createdAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly updatedAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly permissions: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "string";
                        };
                    };
                };
                readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsControllerV1DeletePermission: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly permissionId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["permissionId"];
        }];
    };
};
declare const PermissionsControllerV1DeleteRole: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly roleId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["roleId"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "For relating a role to a specific tenant, use `get tenants` API to find the tenant ids";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const PermissionsControllerV1GetAllPermissions: {
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly key: {
                        readonly type: "string";
                    };
                    readonly name: {
                        readonly type: "string";
                    };
                    readonly description: {
                        readonly type: "string";
                    };
                    readonly createdAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly updatedAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly roleIds: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "string";
                        };
                    };
                    readonly categoryId: {
                        readonly type: "string";
                    };
                    readonly fePermission: {
                        readonly type: "boolean";
                    };
                };
                readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsControllerV1GetAllRoles: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "For relating a role to a specific tenant, use `get tenants` API to find the tenant ids";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly vendorId: {
                        readonly type: "string";
                    };
                    readonly tenantId: {
                        readonly type: "string";
                    };
                    readonly key: {
                        readonly type: "string";
                    };
                    readonly name: {
                        readonly type: "string";
                    };
                    readonly description: {
                        readonly type: "string";
                    };
                    readonly isDefault: {
                        readonly type: "boolean";
                    };
                    readonly firstUserRole: {
                        readonly type: "boolean";
                    };
                    readonly level: {
                        readonly type: "number";
                    };
                    readonly createdAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly updatedAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly permissions: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "string";
                        };
                    };
                };
                readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsControllerV1SetPermissionsToRole: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly permissionIds: {
                readonly description: "Set permission ids to attach to the role";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["permissionIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly roleId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["roleId"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "For relating a role to a specific tenant, use `get tenants` API to find the tenant ids";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly vendorId: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly key: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly isDefault: {
                    readonly type: "boolean";
                };
                readonly firstUserRole: {
                    readonly type: "boolean";
                };
                readonly level: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
            };
            readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsControllerV1SetRolesToPermission: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly roleIds: {
                readonly description: "The permission will be assigned to the specified roles";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["roleIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly permissionId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["permissionId"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly key: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly roleIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly categoryId: {
                    readonly type: "string";
                };
                readonly fePermission: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsControllerV1UpdatePermission: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly key: {
                readonly type: "string";
            };
            readonly name: {
                readonly type: "string";
            };
            readonly description: {
                readonly type: "string";
            };
            readonly categoryId: {
                readonly type: "string";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly permissionId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["permissionId"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly key: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly roleIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly categoryId: {
                    readonly type: "string";
                };
                readonly fePermission: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsControllerV1UpdatePermissionsAssignmentType: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly permissionIds: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly type: {
                readonly type: "string";
                readonly enum: readonly ["NEVER", "ALWAYS", "ASSIGNABLE"];
            };
        };
        readonly required: readonly ["permissionIds", "type"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly key: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly roleIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly categoryId: {
                    readonly type: "string";
                };
                readonly fePermission: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsControllerV1UpdateRole: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly isDefault: {
                readonly type: "boolean";
                readonly description: "This role will be assigned for every user that will be added without specified roles";
            };
            readonly firstUserRole: {
                readonly type: "boolean";
                readonly description: "This role will be assigned to the first user of a tenant (new tenants only)";
            };
            readonly migrateRole: {
                readonly type: "boolean";
                readonly description: "Set this property to `true` together with `isDefault` in order to assign this role to all users";
            };
            readonly level: {
                readonly type: "number";
                readonly minimum: 0;
                readonly maximum: 32767;
                readonly description: "Role level for roles elevation, lower level means stronger role.";
            };
            readonly key: {
                readonly type: "string";
            };
            readonly name: {
                readonly type: "string";
            };
            readonly description: {
                readonly type: "string";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly roleId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["roleId"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "For relating a role to a specific tenant, use `get tenants` API to find the tenant ids";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly vendorId: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly key: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly isDefault: {
                    readonly type: "boolean";
                };
                readonly firstUserRole: {
                    readonly type: "boolean";
                };
                readonly level: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
            };
            readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const PermissionsControllerV2GetAllRoles: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly _limit: {
                    readonly minimum: 1;
                    readonly maximum: 2000;
                    readonly default: 50;
                    readonly type: "number";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _sortBy: {
                    readonly enum: readonly ["key", "name", "description", "isDefault", "firstUserRole", "level", "updatedAt", "createdAt", "permissions", "userTenants", "groups"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _levels: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "number";
                    };
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _offset: {
                    readonly minimum: 0;
                    readonly default: 0;
                    readonly type: "number";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _order: {
                    readonly enum: readonly ["ASC", "DESC"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _filter: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["_sortBy"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "For relating a role to a specific tenant, use `get tenants` API to find the tenant ids";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const RolesControllerV2AddRole: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly key: {
                readonly type: "string";
            };
            readonly name: {
                readonly type: "string";
            };
            readonly description: {
                readonly type: "string";
            };
            readonly isDefault: {
                readonly type: "boolean";
                readonly description: "This role will be assigned for every user that will be added without specified roles";
            };
            readonly baseRoleId: {
                readonly type: "string";
                readonly description: "Role level of the new role will be based on this parameter";
            };
            readonly permissionIds: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["key", "name", "baseRoleId", "permissionIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "For relating a role to a specific tenant, use `get tenants` API to find the tenant ids";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly vendorId: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly key: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly isDefault: {
                    readonly type: "boolean";
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
            };
            readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "permissions"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const RolesControllerV2GetDistinctLevels: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "For relating a role to a specific tenant, use `get tenants` API to find the tenant ids";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const RolesControllerV2GetDistinctTenants: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "For relating a role to a specific tenant, use `get tenants` API to find the tenant ids";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const SecurityPolicyControllerCheckIfAllowToRememberDevice: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly mfaToken: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "MFA token from the response body of the first factor authentication";
                };
            };
            readonly required: readonly ["mfaToken"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const SecurityPolicyControllerCreateMfaPolicy: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enforceMFAType: {
                readonly type: "string";
                readonly enum: readonly ["DontForce", "Force", "ForceExceptSAML"];
                readonly description: "Determine whether MFA should be enforced.\n\nDefault: `Force`";
                readonly default: "Force";
            };
            readonly allowRememberMyDevice: {
                readonly type: "boolean";
                readonly description: "Determine whether devices can be remembered and authentication can be skipped.";
                readonly default: false;
            };
            readonly mfaDeviceExpiration: {
                readonly type: "number";
                readonly description: "Expiration time of device in seconds";
                readonly default: 1209600;
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly enforceMFAType: {
                    readonly type: "string";
                };
                readonly allowRememberMyDevice: {
                    readonly type: "boolean";
                };
                readonly mfaDeviceExpiration: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "allowRememberMyDevice", "mfaDeviceExpiration", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const SecurityPolicyControllerGetSecurityPolicy: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly enforceMFAType: {
                    readonly type: "string";
                };
                readonly allowRememberMyDevice: {
                    readonly type: "boolean";
                };
                readonly mfaDeviceExpiration: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "allowRememberMyDevice", "mfaDeviceExpiration", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const SecurityPolicyControllerUpdateSecurityPolicy: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enforceMFAType: {
                readonly type: "string";
                readonly enum: readonly ["DontForce", "Force", "ForceExceptSAML"];
                readonly description: "Determine whether MFA should be enforced.\n\nDefault: `Force`";
                readonly default: "Force";
            };
            readonly allowRememberMyDevice: {
                readonly type: "boolean";
                readonly description: "Determine whether devices can be remembered and authentication can be skipped.";
                readonly default: false;
            };
            readonly mfaDeviceExpiration: {
                readonly type: "number";
                readonly description: "Expiration time of device in seconds";
                readonly default: 1209600;
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly enforceMFAType: {
                    readonly type: "string";
                };
                readonly allowRememberMyDevice: {
                    readonly type: "boolean";
                };
                readonly mfaDeviceExpiration: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "allowRememberMyDevice", "mfaDeviceExpiration", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const SecurityPolicyControllerUpsertSecurityPolicy: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enforceMFAType: {
                readonly type: "string";
                readonly enum: readonly ["DontForce", "Force", "ForceExceptSAML"];
                readonly description: "Determine whether MFA should be enforced.\n\nDefault: `Force`";
                readonly default: "Force";
            };
            readonly allowRememberMyDevice: {
                readonly type: "boolean";
                readonly description: "Determine whether devices can be remembered and authentication can be skipped.";
                readonly default: false;
            };
            readonly mfaDeviceExpiration: {
                readonly type: "number";
                readonly description: "Expiration time of device in seconds";
                readonly default: 1209600;
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly enforceMFAType: {
                    readonly type: "string";
                };
                readonly allowRememberMyDevice: {
                    readonly type: "boolean";
                };
                readonly mfaDeviceExpiration: {
                    readonly type: "number";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly updatedAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "allowRememberMyDevice", "mfaDeviceExpiration", "createdAt", "updatedAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const SessionConfigurationControllerV1CreateSessionConfiguration: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly sessionIdleTimeoutConfiguration: {
                readonly type: "object";
                readonly properties: {
                    readonly isActive: {
                        readonly type: "boolean";
                    };
                    readonly timeout: {
                        readonly type: "number";
                        readonly minimum: 60;
                        readonly maximum: 2073600;
                    };
                };
                readonly required: readonly ["isActive", "timeout"];
            };
            readonly sessionTimeoutConfiguration: {
                readonly type: "object";
                readonly properties: {
                    readonly isActive: {
                        readonly type: "boolean";
                    };
                    readonly timeout: {
                        readonly type: "number";
                        readonly minimum: 60;
                    };
                };
                readonly required: readonly ["isActive", "timeout"];
            };
            readonly sessionConcurrentConfiguration: {
                readonly type: "object";
                readonly properties: {
                    readonly isActive: {
                        readonly type: "boolean";
                    };
                    readonly maxSessions: {
                        readonly type: "number";
                        readonly minimum: 1;
                    };
                };
                readonly required: readonly ["isActive", "maxSessions"];
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const SessionConfigurationControllerV1GetSessionConfiguration: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const SsoV2ControllerCreateSsoProvider: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly type: {
                readonly type: "string";
            };
            readonly clientId: {
                readonly type: "string";
            };
            readonly secret: {
                readonly type: "string";
            };
            readonly redirectUrl: {
                readonly type: "string";
            };
            readonly authorizationUrl: {
                readonly type: "string";
            };
            readonly tokenUrl: {
                readonly type: "string";
            };
            readonly userInfoUrl: {
                readonly type: "string";
            };
            readonly scopes: {
                readonly type: "string";
            };
            readonly ssoLogoUrl: {
                readonly type: "string";
            };
            readonly displayName: {
                readonly type: "string";
            };
            readonly active: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["type", "clientId", "secret", "redirectUrl", "authorizationUrl", "tokenUrl", "userInfoUrl", "scopes", "ssoLogoUrl", "displayName", "active"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const SsoV2ControllerDeleteSsoProvider: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const SsoV2ControllerUpdateSsoProvider: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly type: {
                readonly type: "string";
            };
            readonly clientId: {
                readonly type: "string";
            };
            readonly secret: {
                readonly type: "string";
            };
            readonly redirectUrl: {
                readonly type: "string";
            };
            readonly authorizationUrl: {
                readonly type: "string";
            };
            readonly tokenUrl: {
                readonly type: "string";
            };
            readonly userInfoUrl: {
                readonly type: "string";
            };
            readonly scopes: {
                readonly type: "string";
            };
            readonly ssoLogoUrl: {
                readonly type: "string";
            };
            readonly displayName: {
                readonly type: "string";
            };
            readonly active: {
                readonly type: "boolean";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const TemporaryUsersV1ControllerEditTimeLimit: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly expirationInSeconds: {
                readonly type: "number";
                readonly minimum: 300;
            };
        };
        readonly required: readonly ["expirationInSeconds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly expirationInSeconds: {
                    readonly type: "number";
                    readonly minimum: 300;
                };
            };
            readonly required: readonly ["expirationInSeconds"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TemporaryUsersV1ControllerGetConfiguration: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly enabled: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["enabled"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TemporaryUsersV1ControllerSetUserPermanent: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
};
declare const TemporaryUsersV1ControllerUpdateConfiguration: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly enabled: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["enabled"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly enabled: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["enabled"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantAccessTokensV1ControllerCreateTenantAccessToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly description: {
                readonly type: "string";
            };
            readonly expiresInMinutes: {
                readonly type: "number";
                readonly minimum: 1;
                readonly description: "Token expiration time in minutes. In case of undefined, the token won't be expired";
            };
            readonly roleIds: {
                readonly description: "Array of role IDs to attach to the token";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly secret: {
                    readonly type: "string";
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly roleIds: {
                    readonly description: "Array of role ids";
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly createdByUserId: {
                    readonly type: readonly ["string", "null"];
                };
            };
            readonly required: readonly ["id", "createdAt", "roleIds", "createdByUserId"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantAccessTokensV1ControllerDeleteTenantAccessToken: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
};
declare const TenantAccessTokensV1ControllerGetTenantAccessTokens: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly accessTokens: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly secret: {
                                readonly type: "string";
                            };
                            readonly expires: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly description: "Array of role ids";
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly createdByUserId: {
                                readonly type: readonly ["string", "null"];
                            };
                        };
                        readonly required: readonly ["id", "createdAt", "roleIds", "createdByUserId"];
                    };
                };
            };
            readonly required: readonly ["accessTokens"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantApiTokensV1ControllerCreateTenantApiToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly metadata: {
                readonly type: "object";
                readonly description: "Extra data that will be encoded as part of the JWT";
                readonly additionalProperties: true;
            };
            readonly description: {
                readonly type: "string";
            };
            readonly roleIds: {
                readonly description: "Array of role ids";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly permissionIds: {
                readonly description: "Array of permission ids";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly clientId: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: readonly ["string", "null"];
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly secret: {
                    readonly type: "string";
                };
                readonly createdByUserId: {
                    readonly type: readonly ["string", "null"];
                };
                readonly metadata: {
                    readonly type: "object";
                    readonly description: "Extra data that will be encoded as part of the JWT";
                    readonly additionalProperties: true;
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly permissionIds: {
                    readonly description: "Array of permission ids";
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly roleIds: {
                    readonly description: "Array of role ids";
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["clientId", "description", "tenantId", "secret", "createdByUserId", "metadata", "createdAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantApiTokensV1ControllerDeleteTenantApiToken: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
};
declare const TenantApiTokensV1ControllerGetTenantsApiTokens: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly clientId: {
                        readonly type: "string";
                    };
                    readonly description: {
                        readonly type: readonly ["string", "null"];
                    };
                    readonly tenantId: {
                        readonly type: "string";
                    };
                    readonly createdByUserId: {
                        readonly type: readonly ["string", "null"];
                    };
                    readonly metadata: {
                        readonly type: "object";
                        readonly description: "Extra data that will be encoded as part of the JWT";
                        readonly additionalProperties: true;
                    };
                    readonly createdAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly permissionIds: {
                        readonly description: "Array of permission ids";
                        readonly type: "array";
                        readonly items: {
                            readonly type: "string";
                        };
                    };
                    readonly roleIds: {
                        readonly description: "Array of role ids";
                        readonly type: "array";
                        readonly items: {
                            readonly type: "string";
                        };
                    };
                    readonly expires: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["clientId", "description", "tenantId", "createdByUserId", "metadata", "createdAt", "permissionIds", "roleIds", "expires"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantApiTokensV1ControllerUpdateTenantApiToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly description: {
                readonly type: "string";
            };
            readonly roleIds: {
                readonly description: "Array of role ids";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly permissionIds: {
                readonly description: "Array of permission ids";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly clientId: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: readonly ["string", "null"];
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly createdByUserId: {
                    readonly type: readonly ["string", "null"];
                };
                readonly metadata: {
                    readonly type: "object";
                    readonly description: "Extra data that will be encoded as part of the JWT";
                    readonly additionalProperties: true;
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly permissionIds: {
                    readonly description: "Array of permission ids";
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly roleIds: {
                    readonly description: "Array of role ids";
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["clientId", "description", "tenantId", "createdByUserId", "metadata", "createdAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantApiTokensV2ControllerCreateTenantApiToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly metadata: {
                readonly type: "object";
                readonly description: "Extra data that will be encoded as part of the JWT";
                readonly additionalProperties: true;
            };
            readonly description: {
                readonly type: "string";
            };
            readonly roleIds: {
                readonly description: "Array of role ids";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly permissionIds: {
                readonly description: "Array of permission ids";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly clientId: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: readonly ["string", "null"];
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly secret: {
                    readonly type: "string";
                };
                readonly createdByUserId: {
                    readonly type: readonly ["string", "null"];
                };
                readonly metadata: {
                    readonly type: "object";
                    readonly description: "Extra data that will be encoded as part of the JWT";
                    readonly additionalProperties: true;
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly permissionIds: {
                    readonly description: "Array of permission ids";
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly roleIds: {
                    readonly description: "Array of role ids";
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["clientId", "description", "tenantId", "secret", "createdByUserId", "metadata", "createdAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantInvitesControllerCreateTenantInvite: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly tenantId: {
                readonly type: "string";
            };
            readonly userId: {
                readonly type: "string";
            };
            readonly expiresInMinutes: {
                readonly type: "number";
            };
            readonly shouldSendEmail: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["tenantId"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly vendorId: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly token: {
                    readonly type: "string";
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly shouldSendEmail: {
                    readonly type: "boolean";
                };
                readonly name: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "vendorId", "tenantId", "token", "expires", "shouldSendEmail"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantInvitesControllerCreateTenantInviteForUser: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly expiresInMinutes: {
                readonly type: "number";
            };
            readonly shouldSendEmail: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["expiresInMinutes", "shouldSendEmail"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id", "frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly vendorId: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly token: {
                    readonly type: "string";
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly shouldSendEmail: {
                    readonly type: "boolean";
                };
                readonly name: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "vendorId", "tenantId", "token", "expires", "shouldSendEmail"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantInvitesControllerDeleteTenantInvite: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const TenantInvitesControllerDeleteTenantInviteForUser: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id", "frontegg-tenant-id"];
        }];
    };
};
declare const TenantInvitesControllerGetAllInvites: {
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly vendorId: {
                        readonly type: "string";
                    };
                    readonly tenantId: {
                        readonly type: "string";
                    };
                    readonly userId: {
                        readonly type: "string";
                    };
                    readonly token: {
                        readonly type: "string";
                    };
                    readonly expires: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly shouldSendEmail: {
                        readonly type: "boolean";
                    };
                    readonly name: {
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["id", "vendorId", "tenantId", "token", "expires", "shouldSendEmail"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantInvitesControllerGetTenantInviteForUser: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id", "frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly vendorId: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly token: {
                    readonly type: "string";
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly shouldSendEmail: {
                    readonly type: "boolean";
                };
                readonly name: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "vendorId", "tenantId", "token", "expires", "shouldSendEmail"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantInvitesControllerUpdateTenantInviteForUser: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly expiresInMinutes: {
                readonly type: "number";
            };
            readonly shouldSendEmail: {
                readonly type: "boolean";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id", "frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly vendorId: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly token: {
                    readonly type: "string";
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly shouldSendEmail: {
                    readonly type: "boolean";
                };
                readonly name: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "vendorId", "tenantId", "token", "expires", "shouldSendEmail"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const TenantInvitesControllerVerifyTenantInvite: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly token: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["token"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly vendorId: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly token: {
                    readonly type: "string";
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly shouldSendEmail: {
                    readonly type: "boolean";
                };
                readonly name: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "vendorId", "tenantId", "token", "expires", "shouldSendEmail"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UserAccessTokensV1ControllerCreateUserAccessToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly description: {
                readonly type: "string";
            };
            readonly expiresInMinutes: {
                readonly type: "number";
                readonly minimum: 1;
                readonly description: "Token expiration time in minutes. In case of undefined, the token won't be expired";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id", "frontegg-user-id"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly secret: {
                    readonly type: "string";
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "createdAt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UserAccessTokensV1ControllerDeleteUserAccessToken: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id", "frontegg-user-id"];
        }];
    };
};
declare const UserAccessTokensV1ControllerGetUserAccessTokens: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id", "frontegg-user-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly accessTokens: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly secret: {
                                readonly type: "string";
                            };
                            readonly expires: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["id", "createdAt"];
                    };
                };
            };
            readonly required: readonly ["accessTokens"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UserApiTokensV1ControllerCreateTenantApiToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly metadata: {
                readonly type: "object";
                readonly description: "Extra data that will be encoded as part of the JWT";
                readonly additionalProperties: true;
            };
            readonly description: {
                readonly type: "string";
            };
            readonly expiresInMinutes: {
                readonly type: "number";
                readonly minimum: 1;
                readonly maximum: 5256000;
                readonly description: "Token expiration time in minutes. In case of undefined, the token won't be expired";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id", "frontegg-user-id"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly clientId: {
                    readonly type: "string";
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly metadata: {
                    readonly type: "object";
                    readonly description: "Extra data that will be encoded as part of the JWT";
                    readonly additionalProperties: true;
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly secret: {
                    readonly type: "string";
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["clientId", "description", "metadata", "createdAt", "secret"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UserApiTokensV1ControllerDeleteApiToken: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id", "frontegg-user-id"];
        }];
    };
};
declare const UserApiTokensV1ControllerGetApiTokens: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id", "frontegg-user-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly clientId: {
                        readonly type: "string";
                    };
                    readonly description: {
                        readonly type: "string";
                    };
                    readonly metadata: {
                        readonly type: "object";
                        readonly description: "Extra data that will be encoded as part of the JWT";
                        readonly additionalProperties: true;
                    };
                    readonly createdAt: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                    readonly expires: {
                        readonly format: "date-time";
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["clientId", "description", "metadata", "createdAt"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UserSessionsControllerV1DeleteAllUserActiveSessions: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
};
declare const UserSessionsControllerV1DeleteUserSession: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
};
declare const UserSessionsControllerV1GetActiveSessions: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
};
declare const UserSourcesControllerV1AssignUserSource: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly appIds: {
                readonly description: "The application ids to assign to this user source";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly userSourceId: {
                readonly type: "string";
                readonly description: "The user source id";
            };
        };
        readonly required: readonly ["appIds", "userSourceId"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const UserSourcesControllerV1CreateAuth0ExternalUserSource: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly name: {
                readonly type: "string";
                readonly description: "The user source name";
            };
            readonly configuration: {
                readonly description: "User source configuration";
                readonly type: "object";
                readonly required: readonly ["syncOnLogin", "isMigrated", "domain", "clientId", "secret", "tenantIdFieldName"];
                readonly properties: {
                    readonly syncOnLogin: {
                        readonly type: "boolean";
                        readonly description: "Whether to sync user profile attributes on each login";
                    };
                    readonly isMigrated: {
                        readonly type: "boolean";
                        readonly description: "Whether to migrate the users";
                    };
                    readonly domain: {
                        readonly type: "string";
                        readonly description: "the auth0 domain";
                    };
                    readonly clientId: {
                        readonly type: "string";
                        readonly description: "the auth0 application clientId";
                    };
                    readonly secret: {
                        readonly type: "string";
                        readonly description: "the auth0 application secret";
                    };
                    readonly tenantIdFieldName: {
                        readonly type: "string";
                        readonly description: "the tenant id field name in the user's app_metadata";
                    };
                };
            };
            readonly appIds: {
                readonly description: "The application ids to assign to this user source";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly index: {
                readonly type: "number";
                readonly description: "The user source index";
            };
            readonly description: {
                readonly type: "string";
                readonly description: "The user source description";
            };
        };
        readonly required: readonly ["name", "configuration", "index"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly type: {
                    readonly type: "string";
                };
                readonly appIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly index: {
                    readonly type: "number";
                };
            };
            readonly required: readonly ["id", "name", "type", "appIds", "description", "index"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UserSourcesControllerV1CreateCognitoExternalUserSource: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly name: {
                readonly type: "string";
                readonly description: "The user source name";
            };
            readonly configuration: {
                readonly description: "User source configuration";
                readonly type: "object";
                readonly required: readonly ["syncOnLogin", "isMigrated", "region", "clientId", "userPoolId", "accessKeyId", "secretAccessKey", "tenantIdFieldName"];
                readonly properties: {
                    readonly syncOnLogin: {
                        readonly type: "boolean";
                        readonly description: "Whether to sync user profile attributes on each login";
                    };
                    readonly isMigrated: {
                        readonly type: "boolean";
                        readonly description: "Whether to migrate the users";
                    };
                    readonly region: {
                        readonly type: "string";
                        readonly description: "The aws region of the cognito user pool";
                    };
                    readonly clientId: {
                        readonly type: "string";
                        readonly description: "The cognito app client id";
                    };
                    readonly userPoolId: {
                        readonly type: "string";
                        readonly description: "The id of the cognito user pool";
                    };
                    readonly accessKeyId: {
                        readonly type: "string";
                        readonly description: "The access key of the aws account";
                    };
                    readonly secretAccessKey: {
                        readonly type: "string";
                        readonly description: "The secret of the aws account";
                    };
                    readonly tenantIdFieldName: {
                        readonly type: "string";
                    };
                    readonly clientSecret: {
                        readonly type: "string";
                        readonly description: "The cognito application client secret, required if the app client is configured with a client secret";
                    };
                };
            };
            readonly appIds: {
                readonly description: "The application ids to assign to this user source";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly index: {
                readonly type: "number";
                readonly description: "The user source index";
            };
            readonly description: {
                readonly type: "string";
                readonly description: "The user source description";
            };
        };
        readonly required: readonly ["name", "configuration", "index"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly type: {
                    readonly type: "string";
                };
                readonly appIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly index: {
                    readonly type: "number";
                };
            };
            readonly required: readonly ["id", "name", "type", "appIds", "description", "index"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UserSourcesControllerV1CreateCustomCodeExternalUserSource: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly name: {
                readonly type: "string";
                readonly description: "The user source name";
            };
            readonly configuration: {
                readonly description: "User source configuration";
                readonly type: "object";
                readonly required: readonly ["syncOnLogin", "isMigrated", "codePayload"];
                readonly properties: {
                    readonly syncOnLogin: {
                        readonly type: "boolean";
                        readonly description: "Whether to sync user profile attributes on each login";
                    };
                    readonly isMigrated: {
                        readonly type: "boolean";
                        readonly description: "Whether to migrate the users";
                    };
                    readonly codePayload: {
                        readonly type: "string";
                    };
                };
            };
            readonly appIds: {
                readonly description: "The application ids to assign to this user source";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly index: {
                readonly type: "number";
                readonly description: "The user source index";
            };
            readonly description: {
                readonly type: "string";
                readonly description: "The user source description";
            };
        };
        readonly required: readonly ["name", "configuration", "index"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly type: {
                    readonly type: "string";
                };
                readonly appIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly index: {
                    readonly type: "number";
                };
            };
            readonly required: readonly ["id", "name", "type", "appIds", "description", "index"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UserSourcesControllerV1CreateFederationUserSource: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly name: {
                readonly type: "string";
                readonly description: "The user source name";
            };
            readonly configuration: {
                readonly description: "User source configuration";
                readonly type: "object";
                readonly required: readonly ["syncOnLogin", "wellknownUrl", "clientId", "secret", "tenantIdFieldName"];
                readonly properties: {
                    readonly syncOnLogin: {
                        readonly type: "boolean";
                        readonly description: "Whether to sync user profile attributes on each login";
                    };
                    readonly wellknownUrl: {
                        readonly type: "string";
                        readonly description: "The url of the service provider";
                    };
                    readonly clientId: {
                        readonly type: "string";
                        readonly description: "The client id from the service provider";
                    };
                    readonly secret: {
                        readonly type: "string";
                        readonly description: "The secret from the service provider";
                    };
                    readonly tenantIdFieldName: {
                        readonly type: "string";
                        readonly description: "The tenant id field name in the ID Token from the service provider";
                    };
                };
            };
            readonly appIds: {
                readonly description: "The application ids to assign to this user source";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly index: {
                readonly type: "number";
                readonly description: "The user source index";
            };
            readonly description: {
                readonly type: "string";
                readonly description: "The user source description";
            };
        };
        readonly required: readonly ["name", "configuration", "index"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly type: {
                    readonly type: "string";
                };
                readonly appIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly description: {
                    readonly type: "string";
                };
                readonly index: {
                    readonly type: "number";
                };
            };
            readonly required: readonly ["id", "name", "type", "appIds", "description", "index"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UserSourcesControllerV1DeleteUserSource: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const UserSourcesControllerV1GetUserSource: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const UserSourcesControllerV1GetUserSourceUsers: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const UserSourcesControllerV1GetUserSources: {
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly id: {
                        readonly type: "string";
                    };
                    readonly name: {
                        readonly type: "string";
                    };
                    readonly type: {
                        readonly type: "string";
                    };
                    readonly description: {
                        readonly type: "string";
                    };
                    readonly appIds: {
                        readonly type: "array";
                        readonly items: {
                            readonly type: "string";
                        };
                    };
                    readonly index: {
                        readonly type: "number";
                    };
                    readonly configuration: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                    readonly usersCount: {
                        readonly type: "number";
                    };
                };
                readonly required: readonly ["id", "name", "type", "description", "appIds", "index", "configuration", "usersCount"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UserSourcesControllerV1UnassignUserSource: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly appIds: {
                readonly description: "The application ids to assign to this user source";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly userSourceId: {
                readonly type: "string";
                readonly description: "The user source id";
            };
        };
        readonly required: readonly ["appIds", "userSourceId"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const UserSourcesControllerV1UpdateAuth0ExternalUserSource: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly name: {
                readonly type: "string";
                readonly description: "The user source name";
            };
            readonly configuration: {
                readonly description: "User source configuration";
                readonly type: "object";
                readonly required: readonly ["syncOnLogin", "isMigrated", "domain", "clientId", "secret", "tenantIdFieldName"];
                readonly properties: {
                    readonly syncOnLogin: {
                        readonly type: "boolean";
                        readonly description: "Whether to sync user profile attributes on each login";
                    };
                    readonly isMigrated: {
                        readonly type: "boolean";
                        readonly description: "Whether to migrate the users";
                    };
                    readonly domain: {
                        readonly type: "string";
                        readonly description: "the auth0 domain";
                    };
                    readonly clientId: {
                        readonly type: "string";
                        readonly description: "the auth0 application clientId";
                    };
                    readonly secret: {
                        readonly type: "string";
                        readonly description: "the auth0 application secret";
                    };
                    readonly tenantIdFieldName: {
                        readonly type: "string";
                        readonly description: "the tenant id field name in the user's app_metadata";
                    };
                };
            };
            readonly index: {
                readonly type: "number";
                readonly description: "The user source index";
            };
            readonly description: {
                readonly type: "string";
                readonly description: "The user source description";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const UserSourcesControllerV1UpdateCognitoExternalUserSource: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly name: {
                readonly type: "string";
                readonly description: "The user source name";
            };
            readonly configuration: {
                readonly description: "User source configuration";
                readonly type: "object";
                readonly required: readonly ["syncOnLogin", "isMigrated", "region", "clientId", "userPoolId", "accessKeyId", "secretAccessKey", "tenantIdFieldName"];
                readonly properties: {
                    readonly syncOnLogin: {
                        readonly type: "boolean";
                        readonly description: "Whether to sync user profile attributes on each login";
                    };
                    readonly isMigrated: {
                        readonly type: "boolean";
                        readonly description: "Whether to migrate the users";
                    };
                    readonly region: {
                        readonly type: "string";
                        readonly description: "The aws region of the cognito user pool";
                    };
                    readonly clientId: {
                        readonly type: "string";
                        readonly description: "The cognito app client id";
                    };
                    readonly userPoolId: {
                        readonly type: "string";
                        readonly description: "The id of the cognito user pool";
                    };
                    readonly accessKeyId: {
                        readonly type: "string";
                        readonly description: "The access key of the aws account";
                    };
                    readonly secretAccessKey: {
                        readonly type: "string";
                        readonly description: "The secret of the aws account";
                    };
                    readonly tenantIdFieldName: {
                        readonly type: "string";
                    };
                    readonly clientSecret: {
                        readonly type: "string";
                        readonly description: "The cognito application client secret, required if the app client is configured with a client secret";
                    };
                };
            };
            readonly index: {
                readonly type: "number";
                readonly description: "The user source index";
            };
            readonly description: {
                readonly type: "string";
                readonly description: "The user source description";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const UserSourcesControllerV1UpdateCustomCodeExternalUserSource: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly name: {
                readonly type: "string";
                readonly description: "The user source name";
            };
            readonly configuration: {
                readonly description: "User source configuration";
                readonly type: "object";
                readonly required: readonly ["syncOnLogin", "isMigrated", "codePayload"];
                readonly properties: {
                    readonly syncOnLogin: {
                        readonly type: "boolean";
                        readonly description: "Whether to sync user profile attributes on each login";
                    };
                    readonly isMigrated: {
                        readonly type: "boolean";
                        readonly description: "Whether to migrate the users";
                    };
                    readonly codePayload: {
                        readonly type: "string";
                    };
                };
            };
            readonly index: {
                readonly type: "number";
                readonly description: "The user source index";
            };
            readonly description: {
                readonly type: "string";
                readonly description: "The user source description";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const UserSourcesControllerV1UpdateFederationUserSource: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly name: {
                readonly type: "string";
                readonly description: "The user source name";
            };
            readonly configuration: {
                readonly description: "User source configuration";
                readonly type: "object";
                readonly required: readonly ["syncOnLogin", "wellknownUrl", "clientId", "secret", "tenantIdFieldName"];
                readonly properties: {
                    readonly syncOnLogin: {
                        readonly type: "boolean";
                        readonly description: "Whether to sync user profile attributes on each login";
                    };
                    readonly wellknownUrl: {
                        readonly type: "string";
                        readonly description: "The url of the service provider";
                    };
                    readonly clientId: {
                        readonly type: "string";
                        readonly description: "The client id from the service provider";
                    };
                    readonly secret: {
                        readonly type: "string";
                        readonly description: "The secret from the service provider";
                    };
                    readonly tenantIdFieldName: {
                        readonly type: "string";
                        readonly description: "The tenant id field name in the ID Token from the service provider";
                    };
                };
            };
            readonly index: {
                readonly type: "number";
                readonly description: "The user source index";
            };
            readonly description: {
                readonly type: "string";
                readonly description: "The user source description";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const UsersActivationControllerV1ActivateUser: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly userId: {
                readonly type: "string";
            };
            readonly token: {
                readonly type: "string";
            };
            readonly password: {
                readonly type: "string";
            };
            readonly recaptchaToken: {
                readonly type: "string";
            };
            readonly lastTermsCheck: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["userId", "token"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-vendor-host": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["frontegg-vendor-host"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly tokenType: {
                    readonly type: "string";
                    readonly default: "bearer";
                };
                readonly mfaRequired: {
                    readonly type: "boolean";
                };
                readonly mfaToken: {
                    readonly type: "string";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaDevices: {
                    readonly type: "object";
                    readonly properties: {
                        readonly webauthn: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly deviceType: {
                                        readonly type: "string";
                                        readonly enum: readonly ["Platform", "CrossPlatform"];
                                        readonly description: "`Platform` `CrossPlatform`";
                                    };
                                    readonly name: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "deviceType", "name"];
                            };
                        };
                        readonly phones: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                    readonly phoneNumber: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id", "phoneNumber"];
                            };
                        };
                        readonly authenticators: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly id: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["id"];
                            };
                        };
                        readonly emails: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "object";
                                readonly properties: {
                                    readonly email: {
                                        readonly type: "string";
                                    };
                                };
                                readonly required: readonly ["email"];
                            };
                        };
                    };
                    readonly required: readonly ["webauthn", "phones", "authenticators", "emails"];
                };
                readonly mfaStrategies: {
                    readonly type: "object";
                    readonly additionalProperties: true;
                };
                readonly qrCode: {
                    readonly type: "string";
                };
                readonly recoveryCode: {
                    readonly type: "string";
                };
                readonly accessToken: {
                    readonly type: "string";
                };
                readonly refreshToken: {
                    readonly type: "string";
                };
                readonly expiresIn: {
                    readonly type: "number";
                };
                readonly expires: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly userEmail: {
                    readonly type: "string";
                };
                readonly emailVerified: {
                    readonly type: "boolean";
                };
                readonly isBreachedPassword: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["mfaRequired", "accessToken", "refreshToken", "expiresIn", "expires"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersActivationControllerV1GetActivationStrategy: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly token: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId", "token"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly shouldSetPassword: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["shouldSetPassword"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersActivationControllerV1ResetActivationToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly email: {
                readonly type: "string";
                readonly format: "email";
            };
            readonly emailMetadata: {
                readonly type: "object";
                readonly additionalProperties: true;
            };
        };
        readonly required: readonly ["email", "emailMetadata"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const UsersBulkControllerV1BulkInviteUsers: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly users: {
                readonly type: "array";
                readonly items: {
                    readonly type: "object";
                    readonly properties: {
                        readonly email: {
                            readonly type: "string";
                            readonly format: "email";
                        };
                        readonly name: {
                            readonly type: "string";
                        };
                        readonly profilePictureUrl: {
                            readonly type: "string";
                            readonly maxLength: 4095;
                        };
                        readonly password: {
                            readonly type: "string";
                        };
                        readonly phoneNumber: {
                            readonly type: "string";
                        };
                        readonly provider: {
                            readonly type: "string";
                            readonly default: "local";
                            readonly enum: readonly ["local", "saml", "google", "github", "facebook", "microsoft", "scim2", "slack", "apple"];
                            readonly description: "Default: local";
                        };
                        readonly metadata: {
                            readonly type: "string";
                            readonly description: "Stringified JSON object";
                            readonly examples: readonly ["{}"];
                        };
                        readonly skipInviteEmail: {
                            readonly type: "boolean";
                        };
                        readonly roleIds: {
                            readonly type: "array";
                            readonly items: {
                                readonly type: "string";
                            };
                        };
                        readonly emailMetadata: {
                            readonly type: "object";
                            readonly additionalProperties: true;
                        };
                        readonly expirationInSeconds: {
                            readonly type: "number";
                            readonly minimum: 300;
                            readonly description: "Temporary user expiration in seconds";
                        };
                        readonly verified: {
                            readonly type: "boolean";
                        };
                    };
                    readonly required: readonly ["email"];
                };
            };
        };
        readonly required: readonly ["users"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "202": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersBulkControllerV1GetBulkInviteStatus: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }];
    };
};
declare const UsersControllerV1AddRolesToUser: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly roleIds: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["roleIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "isDefault", "level", "createdAt"];
                    };
                };
            };
            readonly required: readonly ["tenantId", "userId", "roles"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1AddUserToTenantForVendor: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly validateTenantExist: {
                readonly type: "boolean";
            };
            readonly tenantId: {
                readonly type: "string";
            };
            readonly skipInviteEmail: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["tenantId"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1BulkMigrateUserForVendor: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly users: {
                readonly type: "array";
                readonly items: {
                    readonly type: "object";
                    readonly properties: {
                        readonly passwordHash: {
                            readonly type: "string";
                            readonly description: "The password hash. For SCrypt should include the salt and key seperated by the salt separator";
                        };
                        readonly passwordHashType: {
                            readonly type: "string";
                            readonly enum: readonly ["bcrypt", "scrypt", "firebase-scrypt", "pbkdf2", "argon2"];
                        };
                        readonly passwordHashConfig: {
                            readonly type: "string";
                            readonly maxLength: 4095;
                            readonly description: "Stringified JSON Hashing config for the migrated password. For SCrypt should be formatted as { saltSeparator, N, r, p, keyLen }. For FirebaseScrypt should be formatted as { memCost, rounds, saltSeparator, signerKey }";
                        };
                        readonly phoneNumber: {
                            readonly type: "string";
                            readonly description: "phoneNumber can be used both for login with SMS and for MFAThis auto-enrolls the user in MFA, prompting them at first login (regardless of tenant/vendor MFA settings).The required format is an area code + number, no spaces. For example: \"+16037184056\"The number must be unique";
                        };
                        readonly provider: {
                            readonly type: "string";
                            readonly enum: readonly ["local", "saml", "google", "github", "facebook", "microsoft", "scim2", "slack", "apple"];
                            readonly default: "local";
                            readonly description: "Default: local";
                        };
                        readonly metadata: {
                            readonly type: "string";
                            readonly description: "Stringified JSON object";
                        };
                        readonly verifyUser: {
                            readonly type: "boolean";
                            readonly default: false;
                            readonly description: "Whether to verify the user as part of the migration process. If this is set to false, another call is required for the verify user API";
                        };
                        readonly roleIds: {
                            readonly default: readonly [];
                            readonly description: "Role ids of the migrated users. If not provided, the user will be assigned the default roles";
                            readonly type: "array";
                            readonly items: {
                                readonly type: "string";
                            };
                        };
                        readonly email: {
                            readonly type: "string";
                        };
                        readonly tenantId: {
                            readonly type: "string";
                        };
                        readonly name: {
                            readonly type: "string";
                        };
                        readonly profilePictureUrl: {
                            readonly type: "string";
                            readonly maxLength: 4095;
                        };
                        readonly authenticatorAppMfaSecret: {
                            readonly type: "string";
                        };
                    };
                    readonly required: readonly ["email", "tenantId"];
                };
            };
        };
        readonly required: readonly ["users"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "202": {
            readonly type: "object";
            readonly properties: {
                readonly migrationId: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["migrationId"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1CheckBulkMigrationStatus: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly migrationId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["migrationId"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1CreateUser: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly email: {
                readonly type: "string";
                readonly format: "email";
            };
            readonly name: {
                readonly type: "string";
            };
            readonly profilePictureUrl: {
                readonly type: "string";
                readonly maxLength: 4095;
            };
            readonly password: {
                readonly type: "string";
            };
            readonly phoneNumber: {
                readonly type: "string";
            };
            readonly provider: {
                readonly type: "string";
                readonly default: "local";
                readonly enum: readonly ["local", "saml", "google", "github", "facebook", "microsoft", "scim2", "slack", "apple"];
                readonly description: "Default: local";
            };
            readonly metadata: {
                readonly type: "string";
                readonly description: "Stringified JSON object";
                readonly examples: readonly ["{}"];
            };
            readonly skipInviteEmail: {
                readonly type: "boolean";
            };
            readonly roleIds: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly emailMetadata: {
                readonly type: "object";
                readonly additionalProperties: true;
            };
            readonly expirationInSeconds: {
                readonly type: "number";
                readonly minimum: 300;
                readonly description: "Temporary user expiration in seconds";
            };
        };
        readonly required: readonly ["email"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1DeleteRolesFromUser: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly roleIds: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
        };
        readonly required: readonly ["roleIds"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "isDefault", "level", "createdAt"];
                    };
                };
            };
            readonly required: readonly ["tenantId", "userId", "roles"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1GenerateUserActivationLink: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly link: {
                    readonly type: "string";
                };
                readonly token: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["link", "token", "userId"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1GenerateUserPasswordResetLink: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly link: {
                    readonly type: "string";
                };
                readonly token: {
                    readonly type: "string";
                };
                readonly userId: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["link", "token", "userId"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1GetMeAuthorization: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
            };
            readonly required: readonly ["roles", "permissions"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1GetUserByEmail: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly email: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["email"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly type: "string";
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1GetUserById: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1GetUserTenants: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1GetUsers: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly _limit: {
                    readonly minimum: 1;
                    readonly type: "number";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _offset: {
                    readonly minimum: 0;
                    readonly type: "number";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _filter: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly ids: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly metadata: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _sortBy: {
                    readonly enum: readonly ["createdAt", "name", "email", "id", "verified", "isLocked", "provider", "tenantId"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _order: {
                    readonly enum: readonly ["ASC", "DESC"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _includeSubTenants: {
                    readonly default: true;
                    readonly type: "boolean";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const UsersControllerV1LockUser: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
};
declare const UsersControllerV1MigrateUserForVendor: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly passwordHash: {
                readonly type: "string";
                readonly description: "The password hash. For SCrypt should include the salt and key seperated by the salt separator";
            };
            readonly passwordHashType: {
                readonly type: "string";
                readonly enum: readonly ["bcrypt", "scrypt", "firebase-scrypt", "pbkdf2", "argon2"];
            };
            readonly passwordHashConfig: {
                readonly type: "string";
                readonly maxLength: 4095;
                readonly description: "Stringified JSON Hashing config for the migrated password. For SCrypt should be formatted as { saltSeparator, N, r, p, keyLen }. For FirebaseScrypt should be formatted as { memCost, rounds, saltSeparator, signerKey }";
            };
            readonly phoneNumber: {
                readonly type: "string";
                readonly description: "phoneNumber can be used both for login with SMS and for MFAThis auto-enrolls the user in MFA, prompting them at first login (regardless of tenant/vendor MFA settings).The required format is an area code + number, no spaces. For example: \"+16037184056\"The number must be unique";
            };
            readonly provider: {
                readonly type: "string";
                readonly enum: readonly ["local", "saml", "google", "github", "facebook", "microsoft", "scim2", "slack", "apple"];
                readonly default: "local";
                readonly description: "Default: local";
            };
            readonly metadata: {
                readonly type: "string";
                readonly description: "Stringified JSON object";
            };
            readonly verifyUser: {
                readonly type: "boolean";
                readonly default: false;
                readonly description: "Whether to verify the user as part of the migration process. If this is set to false, another call is required for the verify user API";
            };
            readonly roleIds: {
                readonly default: readonly [];
                readonly description: "Role ids of the migrated users. If not provided, the user will be assigned the default roles";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly email: {
                readonly type: "string";
            };
            readonly tenantId: {
                readonly type: "string";
            };
            readonly name: {
                readonly type: "string";
            };
            readonly profilePictureUrl: {
                readonly type: "string";
                readonly maxLength: 4095;
            };
            readonly authenticatorAppMfaSecret: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["email", "tenantId"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1MigrateUserFromAuth0: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly domain: {
                readonly type: "string";
            };
            readonly clientId: {
                readonly type: "string";
            };
            readonly secret: {
                readonly type: "string";
            };
            readonly tenantIdFieldName: {
                readonly type: "string";
                readonly description: "The field name that the tenant ID will be taken from under app metadata";
            };
            readonly isTenantIdOnUserMetadata: {
                readonly type: "boolean";
                readonly description: "If you would like to take tenant ID from user metadata, set this field to true";
            };
        };
        readonly required: readonly ["domain", "clientId", "secret", "tenantIdFieldName"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const UsersControllerV1MoveAllUsersTenants: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly srcTenantId: {
                readonly type: "string";
            };
            readonly targetTenantId: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["srcTenantId", "targetTenantId"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const UsersControllerV1RemoveUserFromTenant: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier (optional)";
                };
            };
            readonly required: readonly [];
        }];
    };
};
declare const UsersControllerV1SetUserInvisibleMode: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly invisible: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["invisible"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1SetUserSuperuserMode: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly superUser: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["superUser"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1SignUpUser: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly provider: {
                readonly type: "string";
                readonly enum: readonly ["local", "saml", "google", "github", "facebook", "microsoft", "scim2", "slack", "apple"];
            };
            readonly metadata: {
                readonly type: "string";
                readonly description: "Stringified JSON object. Use the JSON.stringify() method.";
            };
            readonly email: {
                readonly type: "string";
            };
            readonly name: {
                readonly type: "string";
            };
            readonly profilePictureUrl: {
                readonly type: "string";
                readonly maxLength: 4095;
            };
            readonly password: {
                readonly type: "string";
            };
            readonly phoneNumber: {
                readonly type: "string";
            };
            readonly skipInviteEmail: {
                readonly type: "boolean";
            };
            readonly roleIds: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly emailMetadata: {
                readonly type: "object";
                readonly additionalProperties: true;
            };
            readonly companyName: {
                readonly type: "string";
            };
            readonly recaptchaToken: {
                readonly type: "string";
            };
            readonly invitationToken: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["provider", "email", "companyName"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-vendor-host": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["frontegg-vendor-host"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1UnlockUser: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
};
declare const UsersControllerV1UpdateUser: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly phoneNumber: {
                readonly type: "string";
                readonly pattern: "^\\+[1-9]{1}(\\-?)(([0-9])(\\-?)){5,13}(([0-9]$){1})";
            };
            readonly profilePictureUrl: {
                readonly type: readonly ["string", "null"];
                readonly maxLength: 4095;
            };
            readonly metadata: {
                readonly type: "string";
                readonly description: "Stringified JSON object";
                readonly examples: readonly ["{}"];
            };
            readonly name: {
                readonly type: "string";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id", "frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1UpdateUserEmail: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly email: {
                readonly type: "string";
                readonly format: "email";
            };
        };
        readonly required: readonly ["email"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1UpdateUserForVendor: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly phoneNumber: {
                readonly type: "string";
                readonly pattern: "^\\+[1-9]{1}(\\-?)(([0-9])(\\-?)){5,13}(([0-9]$){1})";
            };
            readonly profilePictureUrl: {
                readonly type: readonly ["string", "null"];
                readonly maxLength: 4095;
            };
            readonly metadata: {
                readonly type: "string";
                readonly description: "Stringified JSON object";
                readonly examples: readonly ["{}"];
            };
            readonly vendorMetadata: {
                readonly type: "string";
                readonly description: "Extra vendor-only data. stringified JSON object";
            };
            readonly mfaBypass: {
                readonly type: "boolean";
                readonly description: "Indicates whether MFA should be bypassed for this user";
            };
            readonly name: {
                readonly type: "string";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1UpdateUserTenant: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly tenantId: {
                readonly type: "string";
                readonly description: "Desired tenant to set as active tenant for user";
            };
        };
        readonly required: readonly ["tenantId"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id", "frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1UpdateUserTenantForVendor: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly tenantId: {
                readonly type: "string";
                readonly description: "Desired tenant to set as active tenant for user";
            };
            readonly validateTenantExist: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["tenantId"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV1VerifyUser: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
};
declare const UsersControllerV2CreateUser: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly email: {
                readonly type: "string";
                readonly format: "email";
            };
            readonly name: {
                readonly type: "string";
            };
            readonly profilePictureUrl: {
                readonly type: "string";
                readonly maxLength: 4095;
            };
            readonly password: {
                readonly type: "string";
            };
            readonly phoneNumber: {
                readonly type: "string";
            };
            readonly provider: {
                readonly type: "string";
                readonly default: "local";
                readonly enum: readonly ["local", "saml", "google", "github", "facebook", "microsoft", "scim2", "slack", "apple"];
                readonly description: "Default: local";
            };
            readonly metadata: {
                readonly type: "string";
                readonly description: "Stringified JSON object";
                readonly examples: readonly ["{}"];
            };
            readonly skipInviteEmail: {
                readonly type: "boolean";
            };
            readonly roleIds: {
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly emailMetadata: {
                readonly type: "object";
                readonly additionalProperties: true;
            };
            readonly expirationInSeconds: {
                readonly type: "number";
                readonly minimum: 300;
                readonly description: "Temporary user expiration in seconds";
            };
        };
        readonly required: readonly ["email"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV2GetUserProfile: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV2GetUserTenants: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "object";
                readonly properties: {
                    readonly tenantId: {
                        readonly type: "string";
                    };
                    readonly name: {
                        readonly type: "string";
                    };
                };
                readonly required: readonly ["tenantId", "name"];
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV2GetUserTenantsHierarchy: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV2UpdateUserProfile: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly phoneNumber: {
                readonly type: "string";
                readonly pattern: "^\\+[1-9]{1}(\\-?)(([0-9])(\\-?)){5,13}(([0-9]$){1})";
            };
            readonly profilePictureUrl: {
                readonly type: readonly ["string", "null"];
                readonly maxLength: 4095;
            };
            readonly metadata: {
                readonly type: "string";
                readonly description: "Stringified JSON object";
                readonly examples: readonly ["{}"];
            };
            readonly name: {
                readonly type: "string";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV3GetUserProfile: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV3GetUsers: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly _includeSubTenants: {
                    readonly default: true;
                    readonly type: "boolean";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "when passing a user id, gives the option to include or not include sub tenants when searching users";
                };
                readonly _limit: {
                    readonly minimum: 1;
                    readonly type: "number";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _offset: {
                    readonly minimum: 0;
                    readonly type: "number";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _email: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _tenantId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly ids: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _sortBy: {
                    readonly enum: readonly ["createdAt", "name", "email", "id", "verified", "isLocked", "provider", "tenantId"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
                readonly _order: {
                    readonly enum: readonly ["ASC", "DESC"];
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly [];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV3GetUsersGroups: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly ids: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["ids"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersControllerV3GetUsersRoles: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly ids: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["ids"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersMfaControllerV1DisableAuthAppMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly token: {
                readonly type: "string";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
};
declare const UsersMfaControllerV1DisableAuthenticatorMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly token: {
                readonly type: "string";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly deviceId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["deviceId"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
};
declare const UsersMfaControllerV1DisableSmsMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly otcToken: {
                readonly type: "string";
            };
            readonly code: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["otcToken", "code"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly deviceId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["deviceId"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
};
declare const UsersMfaControllerV1EnrollAuthAppMfa: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly qrCode: {
                    readonly type: "string";
                    readonly description: "QR code to be verified by authenticator app";
                };
            };
            readonly required: readonly ["qrCode"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersMfaControllerV1EnrollAuthenticatorMfa: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly qrCode: {
                    readonly type: "string";
                    readonly description: "QR code to be verified by authenticator app";
                };
            };
            readonly required: readonly ["qrCode"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersMfaControllerV1EnrollSmsMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly otcToken: {
                readonly type: "string";
            };
            readonly code: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["otcToken", "code"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
};
declare const UsersMfaControllerV1PreDisableSmsMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {};
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly deviceId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["deviceId"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id", "frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersMfaControllerV1PreEnrollSmsMfa: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly phoneNumber: {
                readonly type: "string";
                readonly pattern: "phoneNumberRegexp";
            };
        };
        readonly required: readonly ["phoneNumber"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
};
declare const UsersMfaControllerV1VerifyAuthAppMfaEnrollment: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly token: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["token"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly recoveryCode: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["recoveryCode"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersMfaControllerV1VerifyAuthenticatorMfaEnrollment: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly token: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["token"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly recoveryCode: {
                    readonly type: "string";
                };
            };
            readonly required: readonly ["recoveryCode"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersPasswordControllerV1ChangePassword: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly password: {
                readonly type: "string";
            };
            readonly newPassword: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["password", "newPassword"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-user-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The user ID identifier";
                };
            };
            readonly required: readonly ["frontegg-user-id"];
        }];
    };
};
declare const UsersPasswordControllerV1GetUserPasswordConfig: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly allowPassphrases: {
                    readonly type: "boolean";
                };
                readonly maxLength: {
                    readonly type: "number";
                };
                readonly minLength: {
                    readonly type: "number";
                };
                readonly minPhraseLength: {
                    readonly type: "number";
                };
                readonly minOptionalTestsToPass: {
                    readonly type: "number";
                };
                readonly blockPwnedPasswords: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["blockPwnedPasswords"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const UsersPasswordControllerV1ResetPassword: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly email: {
                readonly type: "string";
                readonly format: "email";
            };
            readonly emailMetadata: {
                readonly type: "object";
                readonly additionalProperties: true;
            };
        };
        readonly required: readonly ["email"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const UsersPasswordControllerV1VerifyResetPassword: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly userId: {
                readonly type: "string";
            };
            readonly token: {
                readonly type: "string";
            };
            readonly password: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["userId", "token", "password"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const UsersTenantManagementControllerV1AcceptInvitation: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly userId: {
                readonly type: "string";
            };
            readonly token: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["userId", "token"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
};
declare const UsersTenantManagementControllerV1ResetAllTenantsInvitationToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly email: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["email"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
};
declare const UsersTenantManagementControllerV1ResetTenantInvitationToken: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly email: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["email"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
};
declare const VendorConfigControllerAddOrUpdateConfig: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly defaultTokenExpiration: {
                readonly type: "number";
            };
            readonly defaultRefreshTokenExpiration: {
                readonly type: "number";
                readonly maximum: 15552000;
            };
            readonly cookieSameSite: {
                readonly enum: readonly ["STRICT", "LAX", "NONE"];
                readonly type: "string";
            };
            readonly machineToMachineAuthStrategy: {
                readonly enum: readonly ["ClientCredentials", "AccessToken"];
                readonly type: "string";
            };
            readonly allowSignups: {
                readonly type: "boolean";
            };
            readonly apiTokensEnabled: {
                readonly type: "boolean";
            };
            readonly allowOverridePasswordComplexity: {
                readonly type: "boolean";
            };
            readonly allowOverridePasswordExpiration: {
                readonly type: "boolean";
            };
            readonly allowOverrideEnforcePasswordHistory: {
                readonly type: "boolean";
            };
            readonly jwtAlgorithm: {
                readonly enum: readonly ["HS256", "RS256"];
                readonly type: "string";
            };
            readonly allowNotVerifiedUsersLogin: {
                readonly type: "boolean";
            };
            readonly forcePermissions: {
                readonly type: "boolean";
            };
            readonly addSamlAttributesToJwt: {
                readonly type: "boolean";
            };
            readonly authStrategy: {
                readonly enum: readonly ["Code", "EmailAndPassword", "MagicLink", "NoLocalAuthentication", "SmsCode"];
                readonly type: "string";
            };
            readonly defaultPasswordlessTokenExpiration: {
                readonly type: "number";
            };
            readonly forceSameDeviceOnAuth: {
                readonly type: "boolean";
            };
            readonly allowTenantInvitations: {
                readonly type: "boolean";
            };
            readonly rotateRefreshTokens: {
                readonly type: "boolean";
            };
            readonly skipTenantValidation: {
                readonly type: "boolean";
            };
            readonly addRolesToJwt: {
                readonly type: "boolean";
            };
            readonly addPermissionsToJwt: {
                readonly type: "boolean";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly defaultTokenExpiration: {
                    readonly type: "number";
                };
                readonly defaultRefreshTokenExpiration: {
                    readonly type: "number";
                };
                readonly publicKey: {
                    readonly type: "string";
                };
                readonly cookieSameSite: {
                    readonly enum: readonly ["STRICT", "LAX", "NONE"];
                    readonly type: "string";
                    readonly description: "`STRICT` `LAX` `NONE`";
                };
                readonly allowSignups: {
                    readonly type: "boolean";
                };
                readonly apiTokensEnabled: {
                    readonly type: "boolean";
                };
                readonly allowOverridePasswordComplexity: {
                    readonly type: "boolean";
                };
                readonly allowOverridePasswordExpiration: {
                    readonly type: "boolean";
                };
                readonly allowOverrideEnforcePasswordHistory: {
                    readonly type: "boolean";
                };
                readonly jwtAlgorithm: {
                    readonly enum: readonly ["RS256", "HS256"];
                    readonly type: "string";
                    readonly description: "`RS256` `HS256`";
                };
                readonly jwtSecret: {
                    readonly type: "string";
                };
                readonly allowNotVerifiedUsersLogin: {
                    readonly type: "boolean";
                };
                readonly forcePermissions: {
                    readonly type: "boolean";
                };
                readonly authStrategy: {
                    readonly enum: readonly ["EmailAndPassword", "MagicLink", "Code", "NoLocalAuthentication", "SmsCode"];
                    readonly type: "string";
                    readonly description: "`EmailAndPassword` `MagicLink` `Code` `NoLocalAuthentication` `SmsCode`";
                };
                readonly defaultPasswordlessTokenExpiration: {
                    readonly type: "number";
                };
                readonly forceSameDeviceOnAuth: {
                    readonly type: "boolean";
                };
                readonly allowTenantInvitations: {
                    readonly type: "boolean";
                };
                readonly rotateRefreshTokens: {
                    readonly type: "boolean";
                };
                readonly machineToMachineAuthStrategy: {
                    readonly enum: readonly ["ClientCredentials", "AccessToken"];
                    readonly type: "string";
                    readonly description: "`ClientCredentials` `AccessToken`";
                };
                readonly addRolesToJwt: {
                    readonly type: "boolean";
                };
                readonly addPermissionsToJwt: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["id", "defaultTokenExpiration", "defaultRefreshTokenExpiration", "publicKey", "cookieSameSite", "allowSignups", "apiTokensEnabled", "allowOverridePasswordComplexity", "allowOverridePasswordExpiration", "allowOverrideEnforcePasswordHistory", "jwtAlgorithm", "jwtSecret", "allowNotVerifiedUsersLogin", "forcePermissions", "authStrategy", "defaultPasswordlessTokenExpiration", "forceSameDeviceOnAuth", "allowTenantInvitations", "rotateRefreshTokens", "machineToMachineAuthStrategy", "addRolesToJwt", "addPermissionsToJwt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorConfigControllerGetVendorConfig: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly defaultTokenExpiration: {
                    readonly type: "number";
                };
                readonly defaultRefreshTokenExpiration: {
                    readonly type: "number";
                };
                readonly publicKey: {
                    readonly type: "string";
                };
                readonly cookieSameSite: {
                    readonly enum: readonly ["STRICT", "LAX", "NONE"];
                    readonly type: "string";
                    readonly description: "`STRICT` `LAX` `NONE`";
                };
                readonly allowSignups: {
                    readonly type: "boolean";
                };
                readonly apiTokensEnabled: {
                    readonly type: "boolean";
                };
                readonly allowOverridePasswordComplexity: {
                    readonly type: "boolean";
                };
                readonly allowOverridePasswordExpiration: {
                    readonly type: "boolean";
                };
                readonly allowOverrideEnforcePasswordHistory: {
                    readonly type: "boolean";
                };
                readonly jwtAlgorithm: {
                    readonly enum: readonly ["RS256", "HS256"];
                    readonly type: "string";
                    readonly description: "`RS256` `HS256`";
                };
                readonly jwtSecret: {
                    readonly type: "string";
                };
                readonly allowNotVerifiedUsersLogin: {
                    readonly type: "boolean";
                };
                readonly forcePermissions: {
                    readonly type: "boolean";
                };
                readonly authStrategy: {
                    readonly enum: readonly ["EmailAndPassword", "MagicLink", "Code", "NoLocalAuthentication", "SmsCode"];
                    readonly type: "string";
                    readonly description: "`EmailAndPassword` `MagicLink` `Code` `NoLocalAuthentication` `SmsCode`";
                };
                readonly defaultPasswordlessTokenExpiration: {
                    readonly type: "number";
                };
                readonly forceSameDeviceOnAuth: {
                    readonly type: "boolean";
                };
                readonly allowTenantInvitations: {
                    readonly type: "boolean";
                };
                readonly rotateRefreshTokens: {
                    readonly type: "boolean";
                };
                readonly machineToMachineAuthStrategy: {
                    readonly enum: readonly ["ClientCredentials", "AccessToken"];
                    readonly type: "string";
                    readonly description: "`ClientCredentials` `AccessToken`";
                };
                readonly addRolesToJwt: {
                    readonly type: "boolean";
                };
                readonly addPermissionsToJwt: {
                    readonly type: "boolean";
                };
            };
            readonly required: readonly ["id", "defaultTokenExpiration", "defaultRefreshTokenExpiration", "publicKey", "cookieSameSite", "allowSignups", "apiTokensEnabled", "allowOverridePasswordComplexity", "allowOverridePasswordExpiration", "allowOverrideEnforcePasswordHistory", "jwtAlgorithm", "jwtSecret", "allowNotVerifiedUsersLogin", "forcePermissions", "authStrategy", "defaultPasswordlessTokenExpiration", "forceSameDeviceOnAuth", "allowTenantInvitations", "rotateRefreshTokens", "machineToMachineAuthStrategy", "addRolesToJwt", "addPermissionsToJwt"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorOnlyTenantAccessTokensV1ControllerGetTenantAccessTokenData: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["id", "tenantId", "permissions", "roles"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorOnlyUserAccessTokensV1ControllerGetActiveAccessTokens: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "array";
            readonly items: {
                readonly type: "string";
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorOnlyUserAccessTokensV1ControllerGetUserAccessTokenData: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["id"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly "frontegg-tenant-id": {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The tenant ID identifier";
                };
            };
            readonly required: readonly ["frontegg-tenant-id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                };
                readonly id: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly expires: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
            };
            readonly required: readonly ["userId", "id", "tenantId", "permissions", "roles"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorOnlyUsersCreateUser: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly email: {
                readonly type: "string";
            };
            readonly name: {
                readonly type: "string";
            };
            readonly password: {
                readonly type: "string";
            };
            readonly metadata: {
                readonly type: "string";
                readonly description: "Stringified JSON object";
            };
            readonly vendorMetadata: {
                readonly type: "string";
                readonly description: "Extra vendor-only data. stringified JSON object";
            };
            readonly roleIds: {
                readonly description: "Role IDs to assign to the user";
                readonly type: "array";
                readonly items: {
                    readonly type: "string";
                };
            };
            readonly tenantId: {
                readonly type: "string";
            };
            readonly expirationInSeconds: {
                readonly type: "number";
                readonly description: "Temporary user expiration in seconds";
            };
            readonly mfaBypass: {
                readonly type: "boolean";
                readonly description: "Bypass MFA for this user";
            };
        };
        readonly required: readonly ["email", "tenantId"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "201": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorOnlyUsersGetUserById: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {
                readonly id: {
                    readonly type: "string";
                };
                readonly email: {
                    readonly type: "string";
                };
                readonly name: {
                    readonly type: "string";
                };
                readonly profilePictureUrl: {
                    readonly type: "string";
                };
                readonly sub: {
                    readonly type: "string";
                };
                readonly verified: {
                    readonly type: "boolean";
                };
                readonly mfaEnrolled: {
                    readonly type: "boolean";
                };
                readonly mfaBypass: {
                    readonly type: "boolean";
                };
                readonly phoneNumber: {
                    readonly type: "string";
                };
                readonly roles: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly vendorId: {
                                readonly type: "string";
                            };
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly isDefault: {
                                readonly type: "boolean";
                            };
                            readonly firstUserRole: {
                                readonly type: "boolean";
                            };
                            readonly level: {
                                readonly type: "number";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly permissions: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                        };
                        readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                    };
                };
                readonly permissions: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly id: {
                                readonly type: "string";
                            };
                            readonly key: {
                                readonly type: "string";
                            };
                            readonly name: {
                                readonly type: "string";
                            };
                            readonly description: {
                                readonly type: "string";
                            };
                            readonly createdAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly updatedAt: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                            readonly roleIds: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "string";
                                };
                            };
                            readonly categoryId: {
                                readonly type: "string";
                            };
                            readonly fePermission: {
                                readonly type: "boolean";
                            };
                        };
                        readonly required: readonly ["id", "key", "name", "description", "createdAt", "updatedAt", "roleIds", "categoryId", "fePermission"];
                    };
                };
                readonly provider: {
                    readonly type: "string";
                };
                readonly tenantId: {
                    readonly type: "string";
                };
                readonly tenantIds: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "string";
                    };
                };
                readonly activatedForTenant: {
                    readonly type: "boolean";
                };
                readonly isLocked: {
                    readonly type: "boolean";
                };
                readonly tenants: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly properties: {
                            readonly tenantId: {
                                readonly type: "string";
                            };
                            readonly roles: {
                                readonly type: "array";
                                readonly items: {
                                    readonly type: "object";
                                    readonly properties: {
                                        readonly id: {
                                            readonly type: "string";
                                        };
                                        readonly vendorId: {
                                            readonly type: "string";
                                        };
                                        readonly tenantId: {
                                            readonly type: "string";
                                        };
                                        readonly key: {
                                            readonly type: "string";
                                        };
                                        readonly name: {
                                            readonly type: "string";
                                        };
                                        readonly description: {
                                            readonly type: "string";
                                        };
                                        readonly isDefault: {
                                            readonly type: "boolean";
                                        };
                                        readonly firstUserRole: {
                                            readonly type: "boolean";
                                        };
                                        readonly level: {
                                            readonly type: "number";
                                        };
                                        readonly createdAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly updatedAt: {
                                            readonly format: "date-time";
                                            readonly type: "string";
                                        };
                                        readonly permissions: {
                                            readonly type: "array";
                                            readonly items: {
                                                readonly type: "string";
                                            };
                                        };
                                    };
                                    readonly required: readonly ["id", "vendorId", "tenantId", "key", "name", "description", "isDefault", "firstUserRole", "level", "createdAt", "updatedAt", "permissions"];
                                };
                            };
                            readonly temporaryExpirationDate: {
                                readonly format: "date-time";
                                readonly type: "string";
                            };
                        };
                        readonly required: readonly ["tenantId", "roles"];
                    };
                };
                readonly invisible: {
                    readonly type: "boolean";
                };
                readonly superUser: {
                    readonly type: "boolean";
                };
                readonly metadata: {
                    readonly type: "string";
                };
                readonly vendorMetadata: {
                    readonly type: "string";
                };
                readonly createdAt: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly lastLogin: {
                    readonly format: "date-time";
                    readonly type: "string";
                };
                readonly groups: {
                    readonly type: "array";
                    readonly items: {
                        readonly type: "object";
                        readonly additionalProperties: true;
                    };
                };
                readonly subAccountAccessAllowed: {
                    readonly type: "boolean";
                };
                readonly managedBy: {
                    readonly enum: readonly ["frontegg", "scim2", "external"];
                    readonly type: "string";
                    readonly description: "`frontegg` `scim2` `external`";
                };
            };
            readonly required: readonly ["id", "email", "sub", "verified", "mfaEnrolled", "roles", "permissions", "provider", "tenantId", "tenantIds", "tenants", "metadata", "vendorMetadata", "createdAt", "lastLogin", "subAccountAccessAllowed"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorOnlyUsersMfaUnenroll: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly userId: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["userId"];
        }];
    };
};
declare const VendorOnlyUsersVerifyUserPassword: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly email: {
                readonly type: "string";
            };
            readonly password: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["email", "password"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorSmsControllerCreateSmsTemplate: {
    readonly body: {
        readonly type: "object";
        readonly properties: {};
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly type: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["type"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "201": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorSmsControllerCreateSmsVendorConfig: {
    readonly body: {
        readonly type: "object";
        readonly properties: {
            readonly senderName: {
                readonly type: "string";
                readonly description: "The sender name will be used only when alphanumeric sender is supported in the recipient country. This is usually a phone number or the name of the sender, dependeing on what is configured on your Twilio account";
            };
            readonly accountId: {
                readonly type: "string";
                readonly description: "account ID";
            };
            readonly token: {
                readonly type: "string";
                readonly description: "token";
            };
        };
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "201": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorSmsControllerDeleteSmsTemplate: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly type: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["type"];
        }];
    };
};
declare const VendorSmsControllerGetAllSmsTemplates: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorSmsControllerGetSmsDefaultTemplate: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly type: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["type"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorSmsControllerGetSmsTemplate: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly type: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["type"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const VendorSmsControllerGetSmsVendorConfig: {
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly properties: {};
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
export { $Get, ApplicationsActiveUserTenantsControllerV1GetUserApplicationActiveTenants, ApplicationsActiveUserTenantsControllerV1SwitchUserApplicationActiveTenant, ApplicationsControllerV1AssignUserToMultipleApplications, ApplicationsControllerV1AssignUsersToApplication, ApplicationsControllerV1GetApplicationsForMultipleUsers, ApplicationsControllerV1GetApplicationsForUser, ApplicationsControllerV1GetUsersForApplication, ApplicationsControllerV1GetUsersForMultipleApplications, ApplicationsControllerV1UnassignUserFromMultipleApplications, ApplicationsControllerV1UnassignUsersFromApplication, AuthenticatioAuthenticationControllerV1AuthenticateLocalUser, AuthenticatioAuthenticationControllerV1Logout, AuthenticatioAuthenticationControllerV1RefreshToken, AuthenticationApiTokenControllerV2AuthApiToken, AuthenticationApiTokenControllerV2RefreshToken, AuthenticationMfaControllerV1EnrollAuthenticatorMfa, AuthenticationMfaControllerV1EnrollSmsMfa, AuthenticationMfaControllerV1EnrollWebauthnMfa, AuthenticationMfaControllerV1PreEnrollAuthenticatorMfa, AuthenticationMfaControllerV1PreEnrollSmsMfa, AuthenticationMfaControllerV1PreEnrollWebauthnMfa, AuthenticationMfaControllerV1PreVerifyEmailOtcMfa, AuthenticationMfaControllerV1PreVerifySmsMfa, AuthenticationMfaControllerV1PreVerifyWebauthnMfa, AuthenticationMfaControllerV1RecoverMfa, AuthenticationMfaControllerV1VerifyAuthenticatorMfa, AuthenticationMfaControllerV1VerifyAuthenticatorMfaCode, AuthenticationMfaControllerV1VerifyEmailOtcMfa, AuthenticationMfaControllerV1VerifySmsMfa, AuthenticationMfaControllerV1VerifyWebauthnMfa, AuthenticationPasswordlessControllerV1EmailCodePostLogin, AuthenticationPasswordlessControllerV1EmailCodePrelogin, AuthenticationPasswordlessControllerV1MagicLinkPostLogin, AuthenticationPasswordlessControllerV1MagicLinkPrelogin, AuthenticationPasswordlessControllerV1SmsCodePostLogin, AuthenticationPasswordlessControllerV1SmsCodePreLogin, CaptchaPolicyControllerCreateCaptchaPolicy, CaptchaPolicyControllerGetCaptchaPolicy, CaptchaPolicyControllerUpdateCaptchaPolicy, DelegationConfigurationControllerV1CreateOrUpdateDelegationConfiguration, DelegationConfigurationControllerV1GetDelegationConfiguration, DomainRestrictionsControllerCreateBulkDomainsRestriction, DomainRestrictionsControllerCreateDomainRestriction, DomainRestrictionsControllerDeleteDomainRestriction, DomainRestrictionsControllerGetDomainRestrictionsConfig, DomainRestrictionsControllerUpdateDomainRestrictionsConfig, GetInvitationConfiguration, GroupsControllerV1AddRolesToGroup, GroupsControllerV1AddUsersToGroup, GroupsControllerV1CreateGroup, GroupsControllerV1CreateOrUpdateGroupsConfiguration, GroupsControllerV1DeleteGroup, GroupsControllerV1GetAllGroups, GroupsControllerV1GetGroupById, GroupsControllerV1GetGroupsByIds, GroupsControllerV1RemoveRolesFromGroup, GroupsControllerV1RemoveUsersFromGroup, GroupsControllerV1UpdateGroup, GroupsControllerV2GetAllGroupsPaginated, IPRestrictionsControllerV1CreateDomainRestriction, IPRestrictionsControllerV1CreateIpRestriction, IPRestrictionsControllerV1DeleteIpRestrictionById, IPRestrictionsControllerV1GetAllIpRestrictions, LockoutPolicyControllerCreateLockoutPolicy, LockoutPolicyControllerGetLockoutPolicy, LockoutPolicyControllerUpdateLockoutPolicy, MFaStrategiesControllerV1CreateOrUpdateMfaStrategy, MailConfigControllerCreateOrUpdateMailConfig, MailConfigControllerGetMailConfig, MailV1ControllerAddOrUpdateTemplate, MailV1ControllerDeleteTemplate, MailV1ControllerGetDefaultTemplateConfiguration, MailV1ControllerGetTemplateConfiguration, MfaControllerGetMfaConfig, MfaControllerUpsertMfaConfig, PasswordHistoryPolicyControllerCreatePolicy, PasswordHistoryPolicyControllerGetPolicy, PasswordHistoryPolicyControllerUpdatePolicy, PasswordPolicyControllerAddOrUpdatePasswordConfig, PasswordPolicyControllerGetPasswordConfig, PermissionsCategoriesControllerCreatePermissionCategory, PermissionsCategoriesControllerDeleteCategory, PermissionsCategoriesControllerGetAllCategoriesWithPermissions, PermissionsCategoriesControllerUpdateCategory, PermissionsControllerV1AddPermissions, PermissionsControllerV1AddRoles, PermissionsControllerV1DeletePermission, PermissionsControllerV1DeleteRole, PermissionsControllerV1GetAllPermissions, PermissionsControllerV1GetAllRoles, PermissionsControllerV1SetPermissionsToRole, PermissionsControllerV1SetRolesToPermission, PermissionsControllerV1UpdatePermission, PermissionsControllerV1UpdatePermissionsAssignmentType, PermissionsControllerV1UpdateRole, PermissionsControllerV2GetAllRoles, RolesControllerV2AddRole, RolesControllerV2GetDistinctLevels, RolesControllerV2GetDistinctTenants, SecurityPolicyControllerCheckIfAllowToRememberDevice, SecurityPolicyControllerCreateMfaPolicy, SecurityPolicyControllerGetSecurityPolicy, SecurityPolicyControllerUpdateSecurityPolicy, SecurityPolicyControllerUpsertSecurityPolicy, SessionConfigurationControllerV1CreateSessionConfiguration, SessionConfigurationControllerV1GetSessionConfiguration, SsoV2ControllerCreateSsoProvider, SsoV2ControllerDeleteSsoProvider, SsoV2ControllerUpdateSsoProvider, TemporaryUsersV1ControllerEditTimeLimit, TemporaryUsersV1ControllerGetConfiguration, TemporaryUsersV1ControllerSetUserPermanent, TemporaryUsersV1ControllerUpdateConfiguration, TenantAccessTokensV1ControllerCreateTenantAccessToken, TenantAccessTokensV1ControllerDeleteTenantAccessToken, TenantAccessTokensV1ControllerGetTenantAccessTokens, TenantApiTokensV1ControllerCreateTenantApiToken, TenantApiTokensV1ControllerDeleteTenantApiToken, TenantApiTokensV1ControllerGetTenantsApiTokens, TenantApiTokensV1ControllerUpdateTenantApiToken, TenantApiTokensV2ControllerCreateTenantApiToken, TenantInvitesControllerCreateTenantInvite, TenantInvitesControllerCreateTenantInviteForUser, TenantInvitesControllerDeleteTenantInvite, TenantInvitesControllerDeleteTenantInviteForUser, TenantInvitesControllerGetAllInvites, TenantInvitesControllerGetTenantInviteForUser, TenantInvitesControllerUpdateTenantInviteForUser, TenantInvitesControllerVerifyTenantInvite, UserAccessTokensV1ControllerCreateUserAccessToken, UserAccessTokensV1ControllerDeleteUserAccessToken, UserAccessTokensV1ControllerGetUserAccessTokens, UserApiTokensV1ControllerCreateTenantApiToken, UserApiTokensV1ControllerDeleteApiToken, UserApiTokensV1ControllerGetApiTokens, UserSessionsControllerV1DeleteAllUserActiveSessions, UserSessionsControllerV1DeleteUserSession, UserSessionsControllerV1GetActiveSessions, UserSourcesControllerV1AssignUserSource, UserSourcesControllerV1CreateAuth0ExternalUserSource, UserSourcesControllerV1CreateCognitoExternalUserSource, UserSourcesControllerV1CreateCustomCodeExternalUserSource, UserSourcesControllerV1CreateFederationUserSource, UserSourcesControllerV1DeleteUserSource, UserSourcesControllerV1GetUserSource, UserSourcesControllerV1GetUserSourceUsers, UserSourcesControllerV1GetUserSources, UserSourcesControllerV1UnassignUserSource, UserSourcesControllerV1UpdateAuth0ExternalUserSource, UserSourcesControllerV1UpdateCognitoExternalUserSource, UserSourcesControllerV1UpdateCustomCodeExternalUserSource, UserSourcesControllerV1UpdateFederationUserSource, UsersActivationControllerV1ActivateUser, UsersActivationControllerV1GetActivationStrategy, UsersActivationControllerV1ResetActivationToken, UsersBulkControllerV1BulkInviteUsers, UsersBulkControllerV1GetBulkInviteStatus, UsersControllerV1AddRolesToUser, UsersControllerV1AddUserToTenantForVendor, UsersControllerV1BulkMigrateUserForVendor, UsersControllerV1CheckBulkMigrationStatus, UsersControllerV1CreateUser, UsersControllerV1DeleteRolesFromUser, UsersControllerV1GenerateUserActivationLink, UsersControllerV1GenerateUserPasswordResetLink, UsersControllerV1GetMeAuthorization, UsersControllerV1GetUserByEmail, UsersControllerV1GetUserById, UsersControllerV1GetUserTenants, UsersControllerV1GetUsers, UsersControllerV1LockUser, UsersControllerV1MigrateUserForVendor, UsersControllerV1MigrateUserFromAuth0, UsersControllerV1MoveAllUsersTenants, UsersControllerV1RemoveUserFromTenant, UsersControllerV1SetUserInvisibleMode, UsersControllerV1SetUserSuperuserMode, UsersControllerV1SignUpUser, UsersControllerV1UnlockUser, UsersControllerV1UpdateUser, UsersControllerV1UpdateUserEmail, UsersControllerV1UpdateUserForVendor, UsersControllerV1UpdateUserTenant, UsersControllerV1UpdateUserTenantForVendor, UsersControllerV1VerifyUser, UsersControllerV2CreateUser, UsersControllerV2GetUserProfile, UsersControllerV2GetUserTenants, UsersControllerV2GetUserTenantsHierarchy, UsersControllerV2UpdateUserProfile, UsersControllerV3GetUserProfile, UsersControllerV3GetUsers, UsersControllerV3GetUsersGroups, UsersControllerV3GetUsersRoles, UsersMfaControllerV1DisableAuthAppMfa, UsersMfaControllerV1DisableAuthenticatorMfa, UsersMfaControllerV1DisableSmsMfa, UsersMfaControllerV1EnrollAuthAppMfa, UsersMfaControllerV1EnrollAuthenticatorMfa, UsersMfaControllerV1EnrollSmsMfa, UsersMfaControllerV1PreDisableSmsMfa, UsersMfaControllerV1PreEnrollSmsMfa, UsersMfaControllerV1VerifyAuthAppMfaEnrollment, UsersMfaControllerV1VerifyAuthenticatorMfaEnrollment, UsersPasswordControllerV1ChangePassword, UsersPasswordControllerV1GetUserPasswordConfig, UsersPasswordControllerV1ResetPassword, UsersPasswordControllerV1VerifyResetPassword, UsersTenantManagementControllerV1AcceptInvitation, UsersTenantManagementControllerV1ResetAllTenantsInvitationToken, UsersTenantManagementControllerV1ResetTenantInvitationToken, VendorConfigControllerAddOrUpdateConfig, VendorConfigControllerGetVendorConfig, VendorOnlyTenantAccessTokensV1ControllerGetTenantAccessTokenData, VendorOnlyUserAccessTokensV1ControllerGetActiveAccessTokens, VendorOnlyUserAccessTokensV1ControllerGetUserAccessTokenData, VendorOnlyUsersCreateUser, VendorOnlyUsersGetUserById, VendorOnlyUsersMfaUnenroll, VendorOnlyUsersVerifyUserPassword, VendorSmsControllerCreateSmsTemplate, VendorSmsControllerCreateSmsVendorConfig, VendorSmsControllerDeleteSmsTemplate, VendorSmsControllerGetAllSmsTemplates, VendorSmsControllerGetSmsDefaultTemplate, VendorSmsControllerGetSmsTemplate, VendorSmsControllerGetSmsVendorConfig };
