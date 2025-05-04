import { Context, ServerlessEventObject } from "@twilio-labs/serverless-runtime-types/types";
import { Buffer } from "node:buffer";
import z from "zod";
import { generateTwilioSidSchema, getValueFromEnv, getValueFromEvent } from "../../helpers";
import { AuthenticationHandlerResultBase } from "./base";
import { RequestParameter } from "../../types";

const FlexTokenResultSchema = z.object({
	valid: z.boolean(),
	code: z.number().int(),
	message: z.string().nullable(),
	expiration: z.coerce.date().nullable(),
	identity: z.string().nullable(),
	realm_user_id: z.string().nullable(),
	worker_sid: generateTwilioSidSchema("WK").nullable(),
	roles: z.array(z.string()).nullable(),
	flex_instance_sid: generateTwilioSidSchema("GO").nullable(),
	flex_user_sid: generateTwilioSidSchema("FU").nullable()
});
type FlexTokenResult = z.infer<typeof FlexTokenResultSchema>;

export interface FlexTokenAuthenticationHandlerResult extends AuthenticationHandlerResultBase {
	authenticationMethod: "FlexToken";
	flexTokenResult?: FlexTokenResult;
}

export type FlexTokenAuthenticationHandler = (
	context: Context<unknown>,
	event: ServerlessEventObject<unknown>,
	flexTokenRequestParameter: RequestParameter
) => Promise<FlexTokenAuthenticationHandlerResult>;

export const flexTokenAuthenticationHandler: FlexTokenAuthenticationHandler = async (
	context,
	event,
	flexTokenRequestParameter
) => {
	const res: FlexTokenAuthenticationHandlerResult = {
		isAuthenticated: false,
		authenticationMethod: "FlexToken",
		flexTokenResult: undefined
	};

	const accountSid = getValueFromEnv("ACCOUNT_SID", context, true);
	const authToken = getValueFromEnv("AUTH_TOKEN", context, true);

	const flexTokenFromRequest = getValueFromEvent(flexTokenRequestParameter, event);
	if (!flexTokenFromRequest) {
		return res;
	}

	const authHeaderValue = Buffer.from(`${accountSid}:${authToken}`, "utf8").toString("base64");
	const url = `https://iam.twilio.com/v1/Accounts/${accountSid}/Tokens/validate`;
	const validateResponse = await fetch(url, {
		headers: {
			"Cache-Control": "no-cache",
			"Content-Type": "application/json",
			Authorization: `Basic ${authHeaderValue}`
		},
		method: "POST",
		body: JSON.stringify({
			token: flexTokenFromRequest
		})
	});

	if (validateResponse.ok) {
		const resObj = await validateResponse.json();
		const resObjParseResult = FlexTokenResultSchema.safeParse(resObj);
		if (resObjParseResult.success) {
			res.isAuthenticated = resObjParseResult.data.valid;
			res.flexTokenResult = resObjParseResult.data;
		}
	}
	return res;
};
