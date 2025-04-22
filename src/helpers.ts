import { Context, ServerlessEventObject } from "@twilio-labs/serverless-runtime-types/types";
import { z } from "zod";
import { RequestValue } from "./types";

/**
 * generates Zod Schema for Twilio Sid for given prefix.
 * @param prefix prefix of Twilio product SID is for
 * @returns Zod String Regex Schema to match Twilio SID with given prefix.
 */
export const generateTwilioSidSchema = (prefix: "WK"|"GO"|"FU"|"IS") => {
    return z.string().regex(new RegExp(`^${prefix}[0-9a-fA-F]{32}$/`), `Invalid SID. Must be 34 hex characters starting with ${prefix}`);
}

/**
 * This function attempts to extract a value from the event object at a given
 * location. The function also supports removing a prefix value, which can be useful for headers.
 * @param source the details of the parameter to fetch
 * @param event the event object to fetch the parameter value from 
 * @returns the value of the request parameter from the event if found, otherwise empty string.
 * If a prefix is specified and this does not match, then blank string returned. 
 */
export const getValueFromEvent = (source: RequestValue, event: ServerlessEventObject): string => {
    let sourceObj: Record<string, any> = {};
    switch(source.location){
        case "Header":
            sourceObj = event.request.headers;
            break;
        case "Cookie":
            sourceObj = event.request.cookies;
            break;
        case "QueryStringOrBody":
            sourceObj = event;
            break;
    }
    const key = source.location === "Header" ? source.parameterName.toLowerCase() : source.parameterName;
    const value = sourceObj[key];
    if(typeof(value) !== "string"){
        return "";
    }
    if(source.prefixCaseInsensitive){
        if(source.prefixCaseInsensitive.length >= value.length){
            return "";
        }
        const prefixValue = value.substring(0, source.prefixCaseInsensitive.length).toLowerCase();
        if(source.prefixCaseInsensitive.toLowerCase() !== prefixValue){
            return "";
        }
        return value.substring(source.prefixCaseInsensitive.length);
    }
    return value;
}

/**
 * 
 * @param sourceKey name of the value to fetch from the Environment 
 * @param context context holding the Environment values
 * @param throwIfMissing optional. if true, throw an error if Env value is blank or missing. 
 * defaults to false, returns empty string in this case.
 * @returns value of sourceKey from env if exists, blank string if it does not (or exception thrown).
 */
export const getValueFromEnv = (sourceKey: string, context: Context, throwIfMissing: boolean = false): string => {
    const env: Record<string, any> = context;
    const value = env[sourceKey];
    if(typeof(value) !== "string" || !value){
        if(throwIfMissing){
            throw new Error(`Key to find: ${sourceKey} is missing from env`);
        }
        return "";
    }
    return value;
}
