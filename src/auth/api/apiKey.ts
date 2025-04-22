import { Context, ServerlessEventObject } from "@twilio-labs/serverless-runtime-types/types";
import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";
import { getValueFromEnv, getValueFromEvent } from "../../helpers";
import { EnvironmentValue, RequestValue } from "../../types";
import { AuthenticationHandlerResultBase } from "./base";

export interface ApiKeyAuthenticationHandlerResult extends AuthenticationHandlerResultBase {
    authenticationMethod: "ApiKey"
}

export type ApiKeyAuthenticationHandler = 
(context: Context, event: ServerlessEventObject, apiKeyLocation: RequestValue, envValueToMatch: EnvironmentValue) 
=> Promise<ApiKeyAuthenticationHandlerResult>;

export const apiKeyAuthenticationHandler: ApiKeyAuthenticationHandler = 
(context: Context, event: ServerlessEventObject, apiKeyLocation: RequestValue, envValueToMatch: EnvironmentValue) => {
    const res: ApiKeyAuthenticationHandlerResult = {
        isAuthenticated: false,
        authenticationMethod: "ApiKey"
    }
    const valueToMatch = getValueFromEnv(envValueToMatch.key, context, true);

    const apiKeyFromRequest = getValueFromEvent(apiKeyLocation, event);
    if(!apiKeyFromRequest){
        return Promise.resolve(res);
    }
    
    let hashedAndEncodedRequestValue: string|undefined;
    switch(envValueToMatch.hashAlgorithm){
        case "sha256":
            hashedAndEncodedRequestValue = createHash("sha256").update(apiKeyFromRequest, "utf8").digest().toString(envValueToMatch.encoding);   
            break;
        case "none":
            hashedAndEncodedRequestValue = envValueToMatch.encoding === "utf8" ? apiKeyFromRequest : Buffer.from(apiKeyFromRequest, "utf8").toString(envValueToMatch.encoding);
    }

    res.isAuthenticated = valueToMatch === hashedAndEncodedRequestValue;
    return Promise.resolve(res);
}
