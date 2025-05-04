import { NoAuthenticationHandler } from "./noAuthentication";
import { FlexTokenAuthenticationHandler } from "./flexToken";
import { ApiKeyAuthenticationHandler } from "./apiKey";
import { ServiceJwtAuthenticationHandler } from "./jwt";

export * from "./jwt";
export * from "./apiKey";
export * from "./flexToken";
export * from "./noAuthentication";

export type AuthenticationHandler =
	| ApiKeyAuthenticationHandler
	| FlexTokenAuthenticationHandler
	| ServiceJwtAuthenticationHandler
	| NoAuthenticationHandler;
