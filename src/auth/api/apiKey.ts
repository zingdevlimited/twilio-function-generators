import { Context, ServerlessEventObject } from "@twilio-labs/serverless-runtime-types/types";
import { createHash } from "node:crypto";
import { getValueFromEnv, getValueFromEvent } from "../../helpers";
import { RequestParameter } from "../../types";
import { AuthenticationHandlerResultBase } from "./base";

export interface ApiKeyAuthenticationHandlerResult extends AuthenticationHandlerResultBase {
    authenticationMethod: "ApiKey"
    forPrefix?: string
}

export type ApiKeyAuthenticationHandler = 
(context: Context<unknown>, event: ServerlessEventObject<unknown>, apiKeyRequestParameter: RequestParameter, envPrefix?: string) 
=> Promise<ApiKeyAuthenticationHandlerResult>;

/**
 * handler to process API Key authentication.
 * @param context context of the functions service
 * @param event event passed to the function running in the service
 * @param apiKeyRequestParameter how to fetch the api key from the incoming event
 * @param envPrefix optional. if set, prefix to add to env key when finding value to match.
 * any prefix given will be appended to "AUTH_API_KEY_SHA256_HASH_HEX_ENCODED".
 * @returns the result of the authentication check
 */
export const apiKeyAuthenticationHandler: ApiKeyAuthenticationHandler = (context, event, apiKeyRequestParameter, envPrefix) => {
    const res: ApiKeyAuthenticationHandlerResult = {
        isAuthenticated: false,
        authenticationMethod: "ApiKey"
    }

    const configKey = `${envPrefix ?? ""}AUTH_API_KEY_SHA256_HASH_HEX_ENCODED`;
    const keyFromConfig = getValueFromEnv(configKey, context, true);

    const apiKeyFromRequest = getValueFromEvent(apiKeyRequestParameter, event);
    if(!apiKeyFromRequest){
        return Promise.resolve(res);
    }
    const apiKeyFromRequestHashedAndHexEncoded = createHash("sha256").update(apiKeyFromRequest).digest("hex");
    
    res.isAuthenticated = apiKeyFromRequestHashedAndHexEncoded === keyFromConfig;
    res.forPrefix = envPrefix;
    return Promise.resolve(res);
}
