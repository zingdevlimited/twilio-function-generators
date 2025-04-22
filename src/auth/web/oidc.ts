import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { URL } from "node:url";
import { Context } from "@twilio-labs/serverless-runtime-types/types";
import { ulid } from "ulidx";
import z from "zod";
import { 
    discoveryRequest, 
    processDiscoveryResponse, 
    Client, 
    ClientSecretPost, 
    generateRandomCodeVerifier, 
    calculatePKCECodeChallenge,
    generateRandomNonce 
} from "oauth4webapi";
import { generateTwilioSidSchema } from "../../helpers";

const OidcConfigSchema = z.object({
    OIDC_SYNC_SERVICE_SID: generateTwilioSidSchema("IS"),
    OIDC_SERVER_ISSUER_IDENTIFIER_URL: z.string().url(),
    OIDC_CLIENT_ID: z.string().min(1),
    OIDC_CLIENT_SECRET: z.string().min(1),
    OIDC_STATE_ENCRYPTION_KEY_IN_HEX: z.string().regex(/^[0-9A-Fa-f]{64}$/, "invalid key, should be 256 bit (32 byte) crypto random key encoded as 64 hexadecimal characters")
});
type OidcConfig = z.infer<typeof OidcConfigSchema>;

const AuthStateSchema = z.object({
    codeVerifier: z.string(),
    nonce: z.string()
});
type AuthState = z.infer<typeof AuthStateSchema>;

const AuthStateSyncDocDataSchema = z.object({
    encryptedState: z.string(),
    iv: z.string(),
    tag: z.string(),
    expEpochMs: z.number()
});
type AuthStateSyncDocData = z.infer<typeof AuthStateSyncDocDataSchema>;

const ENCRYPTION_CIPHER_ALGORITHM = "aes-256-gcm";
const SYNC_DOC_PROP_VALUES_ENCODING = "base64";
const SYNC_DOC_NAME_PREFIX = "AuthState_";
const LOGIN_TIMEOUT_IN_SECONDS = 1800; //30 minutes

const parseOidcConfigFromEnv = (context: Context): OidcConfig => {
    const envParseResult = OidcConfigSchema.safeParse(context);
    if(!envParseResult.success){
        const errorMsg = "ERROR: failed to parse OidcConfig from context env"; 
        console.error(errorMsg, envParseResult.error);
        throw new Error(errorMsg);
    }
    return envParseResult.data;
}

export const generateRedirectUrlToAuthService = async (context: Context): Promise<URL>  => {
    const env = parseOidcConfigFromEnv(context);
    const issuer = new URL(env.OIDC_SERVER_ISSUER_IDENTIFIER_URL);
    
    const discoveryRequestResponse = await discoveryRequest(issuer, {
        algorithm: "oidc"
    });
    const as = await processDiscoveryResponse(issuer, discoveryRequestResponse);
    if(!as.authorization_endpoint){
        throw new Error("authorization_endpoint missing from discovery response");
    }
    const authorizationUrl = new URL(as.authorization_endpoint);

    const codeChallengeMethod = "S256";
    const codeVerifier = generateRandomCodeVerifier();
    const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
    const nonce = generateRandomNonce();
    const scope = "openid";
    const redirectUrl = process.env.NODE_ENV === 'development' ? "http://localhost:3000/auth/redirect" : `https://${context.DOMAIN_NAME}/auth/redirect`;

    const authStateKey = ulid();
    const exp = new Date();
    exp.setSeconds(exp.getSeconds() + LOGIN_TIMEOUT_IN_SECONDS);

    const authState: AuthState = {
        codeVerifier,
        nonce
    };

    const privateKey = Buffer.from(env.OIDC_STATE_ENCRYPTION_KEY_IN_HEX, "hex");
    const ivBuffer = randomBytes(12);
    const cipher = createCipheriv(
        ENCRYPTION_CIPHER_ALGORITHM,
        privateKey,
        ivBuffer
    );

    const syncDocData: AuthStateSyncDocData = {
        encryptedState: cipher.update(JSON.stringify(authState), "utf8", SYNC_DOC_PROP_VALUES_ENCODING) + cipher.final(SYNC_DOC_PROP_VALUES_ENCODING),
        iv: ivBuffer.toString(SYNC_DOC_PROP_VALUES_ENCODING),
        tag: cipher.getAuthTag().toString(SYNC_DOC_PROP_VALUES_ENCODING),
        expEpochMs: exp.valueOf()
    }

    const twilioClient = context.getTwilioClient({
        autoRetry: true,
        maxRetries: 4,
        maxRetryDelay: 2000
    });

    await twilioClient.sync.v1.services(env.OIDC_SYNC_SERVICE_SID)
    .documents.create({
        uniqueName: `${SYNC_DOC_NAME_PREFIX}${authStateKey}`,
        data: syncDocData,
        ttl: LOGIN_TIMEOUT_IN_SECONDS
    });

    authorizationUrl.searchParams.set("client_id", env.OIDC_CLIENT_ID);
    authorizationUrl.searchParams.set("redirect_uri", redirectUrl);
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set("response_mode", "form_post");
    authorizationUrl.searchParams.set("scope", scope);
    authorizationUrl.searchParams.set("code_challenge", codeChallenge);
    authorizationUrl.searchParams.set("code_challenge_method", codeChallengeMethod);
    authorizationUrl.searchParams.set("nonce", nonce);
    authorizationUrl.searchParams.set("state", authStateKey);
    return authorizationUrl;
}
