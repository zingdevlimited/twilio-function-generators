import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import {
	Context,
	ServerlessEventObject,
	ResponseConstructor,
	TwilioResponse
} from "@twilio-labs/serverless-runtime-types/types";
import { Client, ClientAuth } from "oauth4webapi";
import { URL } from "node:url";
import { ulid } from "ulidx";
import z from "zod";
import { loginRedirectError, loginRedirectSuccess, authServiceCallback } from "./templates/compiled";
import {
	getQueryStringAndBodyAsUrlSearchParams,
	getTwilioRequestId,
	getValueFromEvent,
	isRunningLocally
} from "../../helpers";

const OidcConfigSchema = z.object({
	AUTH_OIDC_SERVER_ISSUER_IDENTIFIER_URL: z.string().url(),
	AUTH_OIDC_CLIENT_ID: z.string().min(1),
	AUTH_OIDC_CLIENT_SECRET: z.string().min(1),
	AUTH_OIDC_STATE_ENCRYPTION_KEY_HEX_ENCODED: z
		.string()
		.regex(
			/^[0-9A-Fa-f]{64}$/,
			"invalid key, should be 256 bit (32 byte) crypto random key encoded as 64 hexadecimal characters"
		),
	AUTH_OIDC_RESPONSE_REDIRECT_TO_FUNCTION_PATH: z.string().min(2).default("/auth/redirect"),
	AUTH_OIDC_RESPONSE_MODE: z.literal("query").or(z.literal("form_post")).default("query"),
	AUTH_OIDC_SESSION_MAX_AGE: z.number().int().positive().gte(60).default(3600),
	AUTH_OIDC_CLIENT_SECRET_AUTH_MODE: z
		.literal("client_secret_basic")
		.or(z.literal("client_secret_post"))
		.default("client_secret_basic")
});

const AuthStateSchema = z.object({
	id: z.string().ulid(),
	codeVerifier: z.string(),
	expiryEpochMs: z.number(),
	nonce: z.string()
});
type AuthState = z.infer<typeof AuthStateSchema>;

const AuthStateCookieSchema = z.object({
	authStateEncrypted: z.string(),
	authTag: z.string(),
	iv: z.string()
});
type AuthStateCookie = z.infer<typeof AuthStateCookieSchema>;

const ENCRYPTION_CIPHER_ALGORITHM = "aes-256-gcm";
const LOGIN_TIMEOUT_IN_SECONDS = 1800; //30 minutes
const AUTH_STATE_COOKIE_ENCODING = "base64";

const getAuthCookieName = (runningOnLocalhost: boolean): string => {
	return `${runningOnLocalhost ? "" : "__Host_"}z_tfg_oidc_as`;
};

const getAuthCookieAttributes = (runningOnLocalhost: boolean, sameSite: "Lax" | "None", maxAge: number): string[] => {
	if (runningOnLocalhost && sameSite === "None") {
		throw new Error("sameSite None not supported on insecure connections");
	}
	const attributes = ["HttpOnly", "Path=/", `SameSite=${sameSite}`, `Max-Age=${maxAge}`];
	if (!runningOnLocalhost) {
		attributes.push("Secure");
	}
	return attributes;
};

const getSessionCookieName = (runningOnLocalhost: boolean): string => {
	return `${runningOnLocalhost ? "" : "__Host_"}z_tfg_jwt_session`;
};

const getSessionCookieAttributes = (runningOnLocalhost: boolean, maxAge: number): string[] => {
	const attributes = ["HttpOnly", "Path=/", "SameSite=Strict", `Max-Age=${maxAge}`];
	if (!runningOnLocalhost) {
		attributes.push("Secure");
	}
	return attributes;
};

const generateRedirectToAuthServiceSuccessResponse = (
	Response: ResponseConstructor,
	runningOnLocalhost: boolean,
	twilioRequestSid: string,
	authorizationUrl: URL,
	authCookieValue: string,
	cookieSameSite: "Lax" | "None"
): TwilioResponse => {
	const res = new Response();
	res.setStatusCode(200);
	res.setCookie(
		getAuthCookieName(runningOnLocalhost),
		authCookieValue,
		getAuthCookieAttributes(runningOnLocalhost, cookieSameSite, LOGIN_TIMEOUT_IN_SECONDS)
	);
	res.setCookie(getSessionCookieName(runningOnLocalhost), "", getSessionCookieAttributes(runningOnLocalhost, 0));
	res.appendHeader("Content-Type", "text/html; charset=utf-8");
	const body = loginRedirectSuccess({
		twilioRequestSid,
		navLinkUrl: authorizationUrl.href
	});
	res.setBody(body);
	return res;
};

const generateRedirectToAuthServiceErrorResponse = (
	Response: ResponseConstructor,
	runningOnLocalhost: boolean,
	twilioRequestSid: string,
	message?: string
): TwilioResponse => {
	const res = new Response();
	res.setStatusCode(200);
	res.setCookie(getAuthCookieName(runningOnLocalhost), "", getAuthCookieAttributes(runningOnLocalhost, "Lax", 0));
	res.appendHeader("Content-Type", "text/html; charset=utf-8");
	const body = loginRedirectError({
		twilioRequestSid,
		message: message ?? "An unexpected error occurred, contact support for assistance."
	});
	res.setBody(body);
	return res;
};

const generateAuthServiceCallbackResponse = (
	Response: ResponseConstructor,
	runningOnLocalhost: boolean,
	twilioRequestSid: string,
	status: "SUCCESS" | "ERROR",
	message: string,
	jwt?: string,
	maxAge?: number
): TwilioResponse => {
	const res = new Response();
	res.setStatusCode(200);
	res.setCookie(getAuthCookieName(runningOnLocalhost), "", getAuthCookieAttributes(runningOnLocalhost, "Lax", 0));
	const sessionCookieValue = jwt ?? "";
	res.setCookie(
		getSessionCookieName(runningOnLocalhost),
		sessionCookieValue,
		getSessionCookieAttributes(runningOnLocalhost, jwt && maxAge ? maxAge : 0)
	);
	res.appendHeader("Content-Type", "text/html; charset=utf-8");
	const body = authServiceCallback({
		twilioRequestSid,
		message,
		status
	});
	res.setBody(body);
	return res;
};

/**
 * This method generates a full page response which will redirect the user to the configured OIDC provider on load,
 * if javascript is enabled, or provide a link to click if not. AuthState is encrypted and stored in a response cookie
 * ready to bounce back with the login callback response once the user has authenticated.
 * If an error occurs during generating the redirect URL or auth state, error message is displayed in the HTML page returned.
 * @param context current context of function execution
 * @param event current event of the function execution
 * @param Response Constructor for creating TwilioResponse object to be returned, pass the global: Twilio.Response property.
 * @returns On success a TwilioResponse object with HTML content to redirect to OIDC provider, and auth state for PKCE in cookies.
 * If error, HTML page with error message and link to home page (/).
 */
export const generateRedirectToAuthServiceFullPageResponse = async (
	context: Context<unknown>,
	event: ServerlessEventObject<unknown>,
	Response: ResponseConstructor
): Promise<TwilioResponse> => {
	const runningOnLocalhost = isRunningLocally(context);
	const twilioRequestSid = getTwilioRequestId(event);
	let onStep:
		| "ParseConfig"
		| "CheckResponseMode"
		| "FetchDiscovery"
		| "ValidateDiscovery"
		| "AuthorizationEndpointMissing"
		| "GenerateAuthState"
		| "GenerateAuthUrl"
		| "GenerateAuthResponse" = "ParseConfig";
	try {
		const env = OidcConfigSchema.parse(context);

		onStep = "CheckResponseMode";
		if (runningOnLocalhost && env.AUTH_OIDC_RESPONSE_MODE === "form_post") {
			throw new Error();
		}

		onStep = "FetchDiscovery";
		const {
			discoveryRequest,
			processDiscoveryResponse,
			generateRandomCodeVerifier,
			calculatePKCECodeChallenge,
			generateRandomNonce
		} = await import("oauth4webapi");

		const issuer = new URL(env.AUTH_OIDC_SERVER_ISSUER_IDENTIFIER_URL);
		const discoveryRequestResponse = await discoveryRequest(issuer, {
			algorithm: "oidc"
		});
		onStep = "ValidateDiscovery";
		const authServer = await processDiscoveryResponse(issuer, discoveryRequestResponse);
		if (!authServer.authorization_endpoint) {
			onStep = "AuthorizationEndpointMissing";
			throw new Error(onStep);
		}

		onStep = "GenerateAuthState";
		const codeVerifier = generateRandomCodeVerifier();
		const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
		const nonce = generateRandomNonce();

		const urlScheme = runningOnLocalhost ? "http" : "https";
		const cookieSameSite = env.AUTH_OIDC_RESPONSE_MODE === "query" ? "Lax" : "None";
		const path = env.AUTH_OIDC_RESPONSE_REDIRECT_TO_FUNCTION_PATH.trim();
		const redirectUrl = `${urlScheme}://${context.DOMAIN_NAME}${path.startsWith("/") ? "" : "/"}${path.endsWith("/") ? path.substring(0, path.length - 1) : path}`;
		const expiry = new Date();
		expiry.setSeconds(expiry.getSeconds() + LOGIN_TIMEOUT_IN_SECONDS);

		const authState: AuthState = {
			id: ulid(),
			codeVerifier,
			nonce,
			expiryEpochMs: expiry.valueOf()
		};

		const privateKey = Buffer.from(env.AUTH_OIDC_STATE_ENCRYPTION_KEY_HEX_ENCODED, "hex");
		const ivBuffer = randomBytes(12);
		const cipher = createCipheriv(ENCRYPTION_CIPHER_ALGORITHM, privateKey, ivBuffer);
		const authStateEncrypted =
			cipher.update(JSON.stringify(authState), "utf8", AUTH_STATE_COOKIE_ENCODING) +
			cipher.final(AUTH_STATE_COOKIE_ENCODING);
		const authTag = cipher.getAuthTag().toString(AUTH_STATE_COOKIE_ENCODING);

		const authorizationStateCookie: AuthStateCookie = {
			authStateEncrypted: authStateEncrypted,
			authTag,
			iv: ivBuffer.toString(AUTH_STATE_COOKIE_ENCODING)
		};
		const authorizationStateCookieEncodedString = Buffer.from(
			JSON.stringify(authorizationStateCookie),
			"utf8"
		).toString(AUTH_STATE_COOKIE_ENCODING);

		onStep = "GenerateAuthUrl";
		const authorizationUrl = new URL(authServer.authorization_endpoint);
		authorizationUrl.searchParams.set("client_id", env.AUTH_OIDC_CLIENT_ID);
		authorizationUrl.searchParams.set("redirect_uri", redirectUrl);
		authorizationUrl.searchParams.set("response_type", "code");
		authorizationUrl.searchParams.set("response_mode", env.AUTH_OIDC_RESPONSE_MODE);
		authorizationUrl.searchParams.set("scope", "openid");
		authorizationUrl.searchParams.set("code_challenge", codeChallenge);
		authorizationUrl.searchParams.set("code_challenge_method", "S256");
		authorizationUrl.searchParams.set("nonce", nonce);
		authorizationUrl.searchParams.set("state", authState.id);

		onStep = "GenerateAuthResponse";
		return generateRedirectToAuthServiceSuccessResponse(
			Response,
			runningOnLocalhost,
			twilioRequestSid,
			authorizationUrl,
			authorizationStateCookieEncodedString,
			cookieSameSite
		);
	} catch (err) {
		console.error("generateRedirectToAuthService", err);
		let messageDetail: string;
		switch (onStep) {
			case "ParseConfig":
				messageDetail = "Failed to parse OIDC Config from context";
				break;
			case "CheckResponseMode":
				messageDetail = "FATAL - form_post requested but not supported when running locally";
				break;
			case "FetchDiscovery":
				messageDetail = "Failed to fetch OIDC discovery document";
				break;
			case "ValidateDiscovery":
				messageDetail = "Failed to validate OIDC discovery document";
				break;
			case "AuthorizationEndpointMissing":
				messageDetail = "authorization_endpoint missing from discovery document";
				break;
			case "GenerateAuthState":
				messageDetail = "Failed to generate authState";
				break;
			case "GenerateAuthUrl":
				messageDetail = "Failed to generate auth URL";
				break;
			case "GenerateAuthResponse":
				messageDetail = "Failed to generate response object";
				break;
		}
		const message = `ERROR: ${onStep} - ${messageDetail}, please retry or contact support if the issue persists.`;
		return generateRedirectToAuthServiceErrorResponse(Response, runningOnLocalhost, twilioRequestSid, message);
	}
};

export const processAuthServiceCallbackAndReturnFullPageResponse = async (
	context: Context<unknown>,
	event: ServerlessEventObject<unknown>,
	Response: ResponseConstructor
): Promise<TwilioResponse> => {
	const twilioRequestSid = getTwilioRequestId(event);
	const runningOnLocalhost = isRunningLocally(context);
	let onStep:
		| "ParseConfig"
		| "GetCookie"
		| "ParseAuthCookie"
		| "DecryptAuthState"
		| "ParseAuthState"
		| "AuthStateExpired"
		| "FetchDiscovery"
		| "ValidateDiscovery"
		| "TokenEndpointMissing"
		| "SetClientAuth"
		| "ExtractEventParams"
		| "GenerateRedirectUrl"
		| "ValidateAuthResponse"
		| "AuthTokenRequest"
		| "ProcessAuthTokenResponse"
		| "GetValidatedIdTokenClaims"
		| "UserInfoRequest"
		| "ProcessUserInfoResponse" = "ParseConfig";
	try {
		const env = OidcConfigSchema.parse(context);

		onStep = "GetCookie";
		const cookieName = getAuthCookieName(runningOnLocalhost);
		const authCookieEncodedString = getValueFromEvent(
			{
				location: "Cookie",
				parameterName: cookieName
			},
			event
		);
		if (!authCookieEncodedString) {
			throw new Error(onStep);
		}

		onStep = "ParseAuthCookie";
		const authCookieJson = Buffer.from(authCookieEncodedString, AUTH_STATE_COOKIE_ENCODING).toString("utf8");
		const authCookieUnknownObj: unknown = JSON.parse(authCookieJson);
		const authStateCookie = AuthStateCookieSchema.parse(authCookieUnknownObj);
		const authTag = Buffer.from(authStateCookie.authTag, AUTH_STATE_COOKIE_ENCODING);

		onStep = "DecryptAuthState";
		const privateKey = Buffer.from(env.AUTH_OIDC_STATE_ENCRYPTION_KEY_HEX_ENCODED, "hex");
		const decipher = createDecipheriv(
			ENCRYPTION_CIPHER_ALGORITHM,
			privateKey,
			Buffer.from(authStateCookie.iv, AUTH_STATE_COOKIE_ENCODING)
		);
		decipher.setAuthTag(authTag);
		const authStateJson =
			decipher.update(authStateCookie.authStateEncrypted, AUTH_STATE_COOKIE_ENCODING, "utf8") +
			decipher.final("utf8");

		onStep = "ParseAuthState";
		const authStateUnknownObj: unknown = JSON.parse(authStateJson);
		const authState = AuthStateSchema.parse(authStateUnknownObj);

		const now = new Date();
		if (now.valueOf() > authState.expiryEpochMs) {
			onStep = "AuthStateExpired";
			throw new Error(onStep);
		}

		onStep = "FetchDiscovery";
		const {
			discoveryRequest,
			processDiscoveryResponse,
			validateAuthResponse,
			authorizationCodeGrantRequest,
			processAuthorizationCodeResponse,
			getValidatedIdTokenClaims,
			userInfoRequest,
			processUserInfoResponse,
			ClientSecretBasic,
			ClientSecretPost
		} = await import("oauth4webapi");
		const issuer = new URL(env.AUTH_OIDC_SERVER_ISSUER_IDENTIFIER_URL);
		const discoveryRequestResponse = await discoveryRequest(issuer, {
			algorithm: "oidc"
		});
		onStep = "ValidateDiscovery";
		const authServer = await processDiscoveryResponse(issuer, discoveryRequestResponse);
		if (!authServer.token_endpoint) {
			onStep = "TokenEndpointMissing";
			throw new Error(onStep);
		}

		onStep = "SetClientAuth";
		let clientAuth: ClientAuth;
		switch (env.AUTH_OIDC_CLIENT_SECRET_AUTH_MODE) {
			case "client_secret_basic":
				clientAuth = ClientSecretBasic(env.AUTH_OIDC_CLIENT_SECRET);
				break;
			case "client_secret_post":
				clientAuth = ClientSecretPost(env.AUTH_OIDC_CLIENT_SECRET);
				break;
			default:
				throw new Error(onStep);
		}

		const client: Client = {
			client_id: env.AUTH_OIDC_CLIENT_ID
		};

		onStep = "ExtractEventParams";
		const eventParams = getQueryStringAndBodyAsUrlSearchParams(event);

		onStep = "GenerateRedirectUrl";
		const urlScheme = runningOnLocalhost ? "http" : "https";
		const redirectUrl = `${urlScheme}://${context.DOMAIN_NAME}${context.PATH}`;

		onStep = "ValidateAuthResponse";
		//nonce, state also
		const callbackParams = validateAuthResponse(authServer, client, eventParams, authState.id);

		onStep = "AuthTokenRequest";
		const authCodeResponse = await authorizationCodeGrantRequest(
			authServer,
			client,
			clientAuth,
			callbackParams,
			redirectUrl,
			authState.codeVerifier
		);

		onStep = "ProcessAuthTokenResponse";
		const tokenEndpointResponse = await processAuthorizationCodeResponse(authServer, client, authCodeResponse, {
			expectedNonce: authState.nonce,
			requireIdToken: true
		});
		console.log("tokenEndpointResponse: ", tokenEndpointResponse);

		onStep = "GetValidatedIdTokenClaims";
		const idTokenClaims = getValidatedIdTokenClaims(tokenEndpointResponse);
		console.log("IDTokenClaims: ", idTokenClaims);
		const sub = idTokenClaims?.sub ?? "";

		//TODO: make optional, might not be required if ID Token is good enough
		onStep = "UserInfoRequest";
		const userInfoRequestRawResponse = await userInfoRequest(
			authServer,
			client,
			tokenEndpointResponse.access_token
		);

		onStep = "ProcessUserInfoResponse";
		const userInfoResponse = await processUserInfoResponse(authServer, client, sub, userInfoRequestRawResponse);
		console.log("userInfoResponse", userInfoResponse);

		//TODO: verify claims exist using ZodSchema

		//TODO: generate JWT
		return generateAuthServiceCallbackResponse(
			Response,
			runningOnLocalhost,
			twilioRequestSid,
			"SUCCESS",
			"ALL GOOD IN THE HOOD"
		);
	} catch (err) {
		console.error("processAuthServiceCallbackAndReturnFullPageResponse", err);
		let messageDetail: string;
		switch (onStep) {
			case "ParseConfig":
				messageDetail = "Failed to parse OIDC Config from context";
				break;
			case "GetCookie":
				messageDetail = "Failed to read authState cookie";
				break;
			case "ParseAuthCookie":
				messageDetail = "Failed to parse authState cookie";
				break;
			case "DecryptAuthState":
				messageDetail = "Failed to decrypt authState cookie";
				break;
			case "ParseAuthState":
				messageDetail = "Failed to parse authState value";
				break;
			case "AuthStateExpired":
				messageDetail = "Login Timeout";
				break;
			case "FetchDiscovery":
				messageDetail = "Failed to fetch OIDC discovery document";
				break;
			case "ValidateDiscovery":
				messageDetail = "Failed to validate OIDC discovery document";
				break;
			case "TokenEndpointMissing":
				messageDetail = "token_endpoint missing from discovery document";
				break;
			case "SetClientAuth":
				messageDetail = "Failed to setup OIDC client";
				break;
			case "ExtractEventParams":
				messageDetail = "Failed to extract event parameters";
				break;
			case "GenerateRedirectUrl":
				messageDetail = "Failed to generate redirect URL";
				break;
			case "ValidateAuthResponse":
				messageDetail = "Failed to validate auth response";
				break;
			case "AuthTokenRequest":
				messageDetail = "Failed to fetch access token";
				break;
			case "ProcessAuthTokenResponse":
				messageDetail = "Failed to process access token";
				break;
			case "GetValidatedIdTokenClaims":
				messageDetail = "Failed to validate ID Token claims";
				break;
			case "UserInfoRequest":
				messageDetail = "Failed to fetch user info endpoint";
				break;
			case "ProcessUserInfoResponse":
				messageDetail = "Failed to process user info endpoint";
				break;
		}
		const message = `ERROR: ${onStep} - ${messageDetail}, please retry or contact support if the issue persists.`;
		return generateAuthServiceCallbackResponse(Response, runningOnLocalhost, twilioRequestSid, "ERROR", message);
	}
};
