import { JsonWebTokenError, NotBeforeError, sign, TokenExpiredError, verify } from "jsonwebtoken";
import { Context, ServerlessEventObject } from "@twilio-labs/serverless-runtime-types/types";
import { Buffer } from "node:buffer";
import z, { ZodObject, ZodRawShape } from "zod";
import { ulid } from "ulidx";
import { AuthenticationHandlerResultBase } from "./base";
import { getValueFromEvent } from "../../helpers";
import { RequestParameter } from "../../types";

const JWT_ALGORITHM = "HS256";

export const JwtConfigSchema = z.object({
	AUTH_JWT_ISSUER: z.string().min(1),
	AUTH_JWT_AUDIENCE: z.string().min(1),
	AUTH_JWT_TTL_IN_MINUTES: z.coerce.number().int().gt(0).default(720),
	AUTH_JWT_ENCRYPTION_KEY_HEX_ENCODED: z
		.string()
		.regex(
			/^[0-9A-Fa-f]{64}$/,
			"invalid key, should be 256 bit (32 byte) crypto random key encoded as 64 hexadecimal characters"
		)
});
type JwtConfig = z.infer<typeof JwtConfigSchema>;

const parseJwtConfigFromEnv = (context: Context<unknown>): JwtConfig => {
	const envParseResult = JwtConfigSchema.safeParse(context);
	if (!envParseResult.success) {
		const errorMsg = "ERROR: failed to parse JwtConfig from context env";
		console.error(errorMsg, envParseResult.error.flatten());
		throw new Error(errorMsg);
	}
	return envParseResult.data;
};

/**
 * attempts to parse the given value into a Date using Zod.
 * @param value value that represents a date to parse
 * @returns on success, parsed Date is returned, on failure default date of 1st Jan 1970 at 00:00 is returned.
 */
const convertToDateOrDefault = (value: unknown): Date => {
	const parseResult = z.coerce.date().safeParse(value);
	if (parseResult.success) {
		return parseResult.data;
	}
	return new Date(0);
};

const JwtPayloadStandardPropsSchema = z.object({
	jti: z.string().optional(),
	iat: z.number().int().positive().optional(),
	iss: z.string().optional(),
	aud: z.string().optional(),
	nbf: z.number().int().positive().optional(),
	exp: z.number().int().positive().optional(),
	sub: z.string().optional()
});
type JwtPayloadStandardProps = z.infer<typeof JwtPayloadStandardPropsSchema>;

/**
 * Generate a fresh JWT for use with this service. Reads Env values from context
 * in order to generate and sign a JWT using subject and any additional claims passed in.
 * NOTE: requires specific JwtConfigSchema Environment variables to be set, see docs for details.
 * failure to set valid Environment variables will lead to an Error being thrown.
 * @param context Twilio function Context that holds the current Environment
 * @param event Twilio function Event, attempts to fetch Twilio Request (RQ) Sid from here to use as jti claim,
 * if Sid missing will use new ULID instead.
 * @param subject Subject (sub) to add to JWT
 * @param additionalJwtClaims Optional. If supplied, any additional claims to add to generated JWT payload.
 * @returns generate JWT as a string on success, throws an Error on any issue.
 */
export const generateServiceJwt = (
	context: Context<unknown>,
	event: ServerlessEventObject<unknown>,
	subject: string,
	additionalJwtClaims?: { [key: string]: unknown }
): string => {
	const config = parseJwtConfigFromEnv(context);

	//generate standard date claims
	const now = new Date();
	const iat = Math.floor(now.valueOf() / 1000); //now in seconds
	const nbf = iat - 10; //10 seconds ago (allow for clock skew)
	const exp = iat + config.AUTH_JWT_TTL_IN_MINUTES * 60; //convert to seconds

	//Twilio attaches this header to every request, is a RQ sid used to track logs
	//through each request to a serverless function. use this value as the jti
	const twilioRequestId = getValueFromEvent(
		{
			location: "Header",
			parameterName: "t-request-id"
		},
		event
	);

	const privateKey = Buffer.from(config.AUTH_JWT_ENCRYPTION_KEY_HEX_ENCODED, "hex");
	const jwt = sign(
		{
			...(additionalJwtClaims ?? {}),
			iat,
			nbf,
			exp
		},
		privateKey,
		{
			algorithm: JWT_ALGORITHM,
			jwtid: twilioRequestId || ulid(), //if sid is missing for some reason, backup to new ulid
			issuer: config.AUTH_JWT_ISSUER,
			audience: config.AUTH_JWT_AUDIENCE,
			subject
		}
	);
	return jwt;
};

type ServiceJwtAuthenticationHandlerResultBase = {
	authenticationMethod: "ServiceJwt";
} & AuthenticationHandlerResultBase;

type ServiceJwtAuthenticationHandlerFailureResult = {
	isAuthenticated: false;
	errorMessage: string;
} & ServiceJwtAuthenticationHandlerResultBase;

const generateFailedResult = (errorMessage: string): ServiceJwtAuthenticationHandlerFailureResult => {
	return {
		authenticationMethod: "ServiceJwt",
		isAuthenticated: false,
		errorMessage
	};
};

type ServiceJwtAuthenticationHandlerSuccessResult<T extends JwtPayloadStandardProps> = {
	isAuthenticated: true;
	jwt: string;
	claims: T;
} & ServiceJwtAuthenticationHandlerResultBase;

export type ServiceJwtAuthenticationHandlerResult<T extends JwtPayloadStandardProps> =
	| ServiceJwtAuthenticationHandlerFailureResult
	| ServiceJwtAuthenticationHandlerSuccessResult<T>;

export type ServiceJwtAuthenticationHandler = <AdditionalJwtClaimsSchema extends ZodObject<ZodRawShape>>(
	context: Context<unknown>,
	event: ServerlessEventObject<unknown>,
	jwtRequestParameter: RequestParameter,
	additionalJwtClaimsSchema: AdditionalJwtClaimsSchema
) => Promise<
	ServiceJwtAuthenticationHandlerResult<JwtPayloadStandardProps & z.infer<typeof additionalJwtClaimsSchema>>
>;

/**
 * Authentication Handler to process JWT parameter passed through the Twilio function event.
 * If JWT is valid, i.e. passes verification is not expired & valid schema, ServiceJwtAuthenticationHandlerSuccessResult
 * result is returned with all claims. Otherwise if invalid or not found ServiceJwtAuthenticationHandlerFailureResult
 * result is returned.
 * NOTE: requires specific JwtConfigSchema Environment variables to be set, see docs for details.
 * failure to set valid Environment variables will lead to an Error being thrown.
 * @param context Twilio function Context that holds the current Environment
 * @param event Twilio function Event that holds the JWT
 * @param jwtRequestParameter details of where the JWT can be located
 * @param additionalJwtClaimsSchema Schema to use to validate additional JWT claims
 * @returns Promise with either ServiceJwtAuthenticationHandlerSuccessResult or ServiceJwtAuthenticationHandlerFailureResult.
 */
export const serviceJwtAuthenticationHandler: ServiceJwtAuthenticationHandler = (
	context,
	event,
	jwtRequestParameter,
	additionalJwtClaimsSchema
) => {
	const config = parseJwtConfigFromEnv(context);

	const jwtFromRequest = getValueFromEvent(jwtRequestParameter, event);
	if (!jwtFromRequest) {
		return Promise.resolve(generateFailedResult("JWT missing from event"));
	}

	let errorMessage: string = "";
	try {
		const privateKey = Buffer.from(config.AUTH_JWT_ENCRYPTION_KEY_HEX_ENCODED, "hex");
		const decoded = verify(jwtFromRequest, privateKey, {
			algorithms: [JWT_ALGORITHM],
			issuer: config.AUTH_JWT_ISSUER,
			audience: config.AUTH_JWT_AUDIENCE
		});
		const sessionParseResult = JwtPayloadStandardPropsSchema.merge(additionalJwtClaimsSchema).safeParse(
			typeof decoded === "string" ? JSON.parse(decoded) : decoded
		);
		if (sessionParseResult.success) {
			const okRes: ServiceJwtAuthenticationHandlerSuccessResult<
				JwtPayloadStandardProps & z.infer<typeof additionalJwtClaimsSchema>
			> = {
				isAuthenticated: true,
				authenticationMethod: "ServiceJwt",
				jwt: jwtFromRequest,
				claims: sessionParseResult.data
			};
			return Promise.resolve(okRes);
		}
		errorMessage = "Failed to parse additionalJwtClaimsSchema";
		console.warn(errorMessage, sessionParseResult.error.flatten());
	} catch (err) {
		if (err instanceof TokenExpiredError) {
			errorMessage = `${err.name} - ${err.message}. Expired At: ${convertToDateOrDefault(err.expiredAt).toISOString()}`;
		} else if (err instanceof NotBeforeError) {
			errorMessage = `${err.name} - ${err.message}. Date: ${convertToDateOrDefault(err.date).toISOString()}`;
		} else if (err instanceof JsonWebTokenError) {
			errorMessage = `${err.name} - ${err.message}`;
		} else {
			errorMessage = "Unexpected Error Parsing JWT";
			console.warn(errorMessage, err);
		}
	}
	return Promise.resolve(generateFailedResult(errorMessage));
};
