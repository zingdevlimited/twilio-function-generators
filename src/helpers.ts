import { Context, ServerlessEventObject } from "@twilio-labs/serverless-runtime-types/types";
import { z } from "zod";
import { RequestParameter } from "./types";

/**
 * generates Zod Schema for Twilio Sid for given prefix.
 * @param prefix prefix of Twilio product SID is for
 * @returns Zod String Regex Schema to match Twilio SID with given prefix.
 */
export const generateTwilioSidSchema = (prefix: "WK" | "GO" | "FU" | "IS") => {
	return z
		.string()
		.regex(
			new RegExp(`^${prefix}[0-9a-fA-F]{32}$/`),
			`Invalid SID. Must be 34 hex characters starting with ${prefix}`
		);
};

/**
 * This function attempts to extract a value from the event object at a given
 * location. The function also supports validating and removing a prefix value, which can be useful for headers.
 * @param source the details of the request parameter to fetch
 * @param event the event object to fetch the parameter value from
 * @returns the value of the request parameter from the event if found, otherwise empty string.
 * If a prefix is specified and this does not match, warning is logged and blank string returned.
 */
export const getValueFromEvent = (source: RequestParameter, event: ServerlessEventObject<unknown>): string => {
	let sourceObj: Record<string, unknown> = {};
	switch (source.location) {
		case "Header":
			sourceObj = event.request.headers;
			break;
		case "Cookie":
			sourceObj = event.request.cookies;
			break;
		case "QueryStringOrBody":
			sourceObj = event;
			break;
		default:
			console.error("Unhandled RequestParameterSourceLocation {0}", source);
	}
	//NOTE: Twilio lowercases all header keys, cookie, query string and body keys are left as is
	const key = source.location === "Header" ? source.parameterName.toLowerCase() : source.parameterName;
	const value = sourceObj[key];

	switch (typeof value) {
		case "undefined":
			return ""; //no env value found
		case "string":
			break; //continue, we have found a param (all params passed as strings)
		default:
			console.warn("Unexpected value type: {0} in event for RequestParameter: {1}", typeof value, source);
			return "";
	}

	if (!source.validateHasCaseInsensitivePrefix) {
		return value;
	}

	const prefixValue = value.substring(0, source.validateHasCaseInsensitivePrefix.length).toLowerCase();
	if (source.validateHasCaseInsensitivePrefix.toLowerCase() !== prefixValue) {
		console.warn("Event parameter found but missing required prefix. RequestParameter: {0}", source);
		return "";
	}
	return value.substring(source.validateHasCaseInsensitivePrefix.length);
};

/**
 * attempts to retrieve value from environment variables through context.
 * if value cant be found either blank is returned or error is thrown depending
 * on throwIfMissing arg (defaults to false)
 * @param key name of the value to fetch from the environment
 * @param context context holding the environment values
 * @param throwIfMissing optional. defaults to false. If true, throw an error if Env value is blank or missing.
 * If false (default), returns empty string in this case.
 * @returns value of sourceKey from env if exists, blank string if it does not (or exception thrown).
 */
export const getValueFromEnv = (key: string, context: Context<unknown>, throwIfMissing: boolean = false): string => {
	const env: Record<string, any> = context;
	const value = env[key];
	if (typeof value !== "string" || !value) {
		if (throwIfMissing) {
			throw new Error(`getValueFromEnv - Key to find: ${key} is missing from env`);
		}
		return "";
	}
	return value;
};

/**
 * checks if the given host context is running on localhost or not.
 * @param context context of the request
 * @returns true if context.DOMAIN_NAME starts with localhost:, otherwise false
 */
export const isRunningLocally = (context: Context<unknown>): boolean => {
	return context.DOMAIN_NAME.toLowerCase().startsWith("localhost:");
};
