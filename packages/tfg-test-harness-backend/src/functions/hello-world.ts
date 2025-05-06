import { ServerlessFunctionSignature } from "@twilio-labs/serverless-runtime-types/types";

export const handler: ServerlessFunctionSignature = function (_context, event, callback) {
	const items = event.request.headers as Record<string, string>;
	const requestSid = items["t-request-id"] ?? "???";
	callback(null, {
		requestSid,
		nodeVersion: process.version,
		message: `Hello World @ ${new Date().toISOString()}!`
	});
};
