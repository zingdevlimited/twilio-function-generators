import { ApiKeyAuthenticationHandler } from "./apiKey";
import { FlexTokenAuthenticationHandler } from "./flexToken";

export type AuthenticationHandler = ApiKeyAuthenticationHandler | FlexTokenAuthenticationHandler;
