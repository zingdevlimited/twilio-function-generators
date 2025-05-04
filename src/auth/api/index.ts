import { ApiKeyAuthenticationHandler } from "./apiKey";
import { FlexTokenAuthenticationHandler } from "./flexToken";
import { ServiceJwtAuthenticationHandler } from "./jwt";

export * from "./apiKey";
export * from "./flexToken";
export * from "./jwt";

export type AuthenticationHandler =
	| ApiKeyAuthenticationHandler
	| FlexTokenAuthenticationHandler
	| ServiceJwtAuthenticationHandler;
