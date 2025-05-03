import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import {
	Context,
	ServerlessEventObject,
	ResponseConstructor,
	TwilioResponse
} from "@twilio-labs/serverless-runtime-types/types";
import { URL } from "node:url";
import z from "zod";
import { loginRedirectError, loginRedirectSuccess, authServiceCallback } from "./templates/compiled";
import { getValueFromEvent, isRunningLocally } from "../../helpers";

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
	AUTH_OIDC_SESSION_MAX_AGE: z.number().int().positive().gte(60).default(3600)
});

const AuthStateSchema = z.object({
	codeVerifier: z.string(),
	expiryEpochMs: z.number(),
	nonce: z.string()
});
type AuthState = z.infer<typeof AuthStateSchema>;

const AuthStateCookieSchema = z.object({
	authStateEncrypted: z.string(),
	iv: z.string()
});
type AuthStateCookie = z.infer<typeof AuthStateCookieSchema>;

const ENCRYPTION_CIPHER_ALGORITHM = "aes-256-gcm";
const LOGIN_TIMEOUT_IN_SECONDS = 1800; //30 minutes
const AUTH_STATE_COOKIE_ENCODING = "base64";
const AUTH_TAG_QUERY_STRING_PARAM_ENCODING = "hex";

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
		navLinkUrl: authorizationUrl.toString()
	});
	res.setBody(body);
	return res;
};

const generateRedirectToAuthServiceErrorResponse = (
	Response: ResponseConstructor,
	runningOnLocalhost: boolean,
	message?: string
): TwilioResponse => {
	const res = new Response();
	res.setStatusCode(200);
	res.setCookie(getAuthCookieName(runningOnLocalhost), "", getAuthCookieAttributes(runningOnLocalhost, "Lax", 0));
	res.appendHeader("Content-Type", "text/html; charset=utf-8");
	const body = loginRedirectError({
		message: message ?? "An unexpected error occurred, contact support for assistance."
	});
	res.setBody(body);
	return res;
};

const generateAuthServiceCallbackResponse = (
	Response: ResponseConstructor,
	runningOnLocalhost: boolean,
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
		message,
		status
	});
	res.setBody(body);
	return res;
};

/**
 *
 * @param context current context of function execution
 * @param Response Constructor for creating TwilioResponse object to be returned, pass the global: Twilio.Response property.
 * @returns On success a TwilioResponse object with HTML content to redirect to OIDC provider, and auth state for PKCE in cookies.
 * If error, HTML page with error message and link to home page (/).
 */
export const generateRedirectToAuthServiceFullPageResponse = async (
	context: Context<unknown>,
	Response: ResponseConstructor
): Promise<TwilioResponse> => {
	const runningOnLocalhost = isRunningLocally(context);
	let onStep:
		| "ParseConfig"
		| "CheckResponseMode"
		| "FetchDiscovery"
		| "ValidateDiscovery"
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
		const authServer = await processDiscoveryResponse(issuer, discoveryRequestResponse);

		onStep = "ValidateDiscovery";
		if (!authServer.authorization_endpoint) {
			throw new Error();
		}

		onStep = "GenerateAuthState";
		const codeVerifier = generateRandomCodeVerifier();
		const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
		const nonce = generateRandomNonce();

		const urlScheme = runningOnLocalhost ? "http" : "https";
		const cookieSameSite = env.AUTH_OIDC_RESPONSE_MODE === "query" ? "Lax" : "None";
		const path = env.AUTH_OIDC_RESPONSE_REDIRECT_TO_FUNCTION_PATH.trim();
		const redirectUrl = `${urlScheme}://${context.DOMAIN_NAME}${path.startsWith("/") ? "" : "/"}${path}`;
		const expiry = new Date();
		expiry.setSeconds(expiry.getSeconds() + LOGIN_TIMEOUT_IN_SECONDS);

		const authState: AuthState = {
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
		const authTag = cipher.getAuthTag().toString(AUTH_TAG_QUERY_STRING_PARAM_ENCODING);

		const authorizationStateCookie: AuthStateCookie = {
			authStateEncrypted: authStateEncrypted,
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
		authorizationUrl.searchParams.set("state", authTag);

		onStep = "GenerateAuthResponse";
		return generateRedirectToAuthServiceSuccessResponse(
			Response,
			runningOnLocalhost,
			authorizationUrl,
			authorizationStateCookieEncodedString,
			cookieSameSite
		);
	} catch (err) {
		console.error("generateRedirectToAuthService", err);
		let message: string | undefined;
		const retryNote = ", please retry or contact support if the issue persists.";
		switch (onStep) {
			case "ParseConfig":
				message = `ERROR: failed to parse OIDC Config from context${retryNote}`;
				break;
			case "CheckResponseMode":
				message = "ERROR: form_post requested but not supported when running locally.";
				break;
			case "FetchDiscovery":
				message = `ERROR: failed to fetch discovery document`;
				break;
			case "ValidateDiscovery":
				message = `ERROR: authorization_endpoint missing from discovery response${retryNote}`;
				break;
			case "GenerateAuthState":
				message = `ERROR: failed to generate auth state values${retryNote}`;
				break;
			case "GenerateAuthUrl":
				message = `ERROR: failed to generate auth url${retryNote}`;
				break;
			case "GenerateAuthResponse":
				message = `ERROR: failed to generate response object${retryNote}`;
				break;
			default:
				const exhaustiveCheck: never = onStep;
				message = `Unhandled case: ${exhaustiveCheck}${retryNote}`;
		}
		return generateRedirectToAuthServiceErrorResponse(Response, runningOnLocalhost, message);
	}
};

/**
 *
 * @param context
 * @param event
 * @param Response
 * @returns
 */
export const processAuthServiceCallbackAndReturnFullPageResponse = async (
	context: Context<unknown>,
	event: ServerlessEventObject<unknown>,
	Response: ResponseConstructor
): Promise<TwilioResponse> => {
	const runningOnLocalhost = isRunningLocally(context);
	let onStep: "ParseConfig" | "GetCookie" = "ParseConfig";
	try {
		const env = OidcConfigSchema.parse(context);

		onStep = "GetCookie";
		const cookieName = getAuthCookieName(runningOnLocalhost);
		const authorizationStateCookieEncodedString = getValueFromEvent(
			{
				location: "Cookie",
				parameterName: cookieName
			},
			event
		);

		if (!authorizationStateCookieEncodedString) {
		}

		const stateParam = getValueFromEvent(
			{
				location: "QueryStringOrBody",
				parameterName: "state"
			},
			event
		);

		if (!stateParam) {
			return generateAuthServiceCallbackResponse(
				Response,
				runningOnLocalhost,
				"ERROR",
				"state parameter missing from request"
			);
		}
		const authTag = Buffer.from(stateParam, AUTH_TAG_QUERY_STRING_PARAM_ENCODING);

		const cookieJson = Buffer.from(authorizationStateCookieEncodedString, AUTH_STATE_COOKIE_ENCODING).toString(
			"utf8"
		);
		const cookieUnknownObj = JSON.parse(cookieJson);
		const authStateCookie = AuthStateCookieSchema.parse(cookieUnknownObj);

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

		// const encryptedAuthStateString = authStateCookie.authState;

		// authState = AuthStateSchema.parse(authStateUnknownObj);

		// authState.
	} catch (err) {
		console.error("processAuthServiceCallbackAndReturnFullPageResponse", err);
		let message: string | undefined;
		const retryNote = ", please retry or contact support if the issue persists.";
		switch (onStep) {
			case "ParseConfig":
				message = `ERROR: failed to parse OIDC Config from context${retryNote}`;
				break;
		}
		return generateAuthServiceCallbackResponse(Response, runningOnLocalhost, "ERROR", message);
	}

	// const {
	//     discoveryRequest,
	//     processDiscoveryResponse,
	//     validateAuthResponse
	// } = await import('oauth4webapi');

	// const issuer = new URL(env.AUTH_OIDC_SERVER_ISSUER_IDENTIFIER_URL);
	// const discoveryRequestResponse = await discoveryRequest(issuer, {
	//     algorithm: "oidc"
	// });
	// const authServer = await processDiscoveryResponse(issuer, discoveryRequestResponse);
	// if(!authServer.token_endpoint){
	//     throw new Error("token_endpoint missing from discovery response");
	// }

	// validateAuthResponse(authServer, {
	//     client_id: env.AUTH_OIDC_CLIENT_ID
	// }, params, skipst )

	// //const clientAuth = ClientSecretPost(env.AUTH_OIDC_CLIENT_SECRET);
	// //validateAuthResponse(as, client,)
	// return Promise.resolve(false);
};
