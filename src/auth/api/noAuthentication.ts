import { AuthenticationHandlerResultBase } from "./base";

export type NoAuthenticationHandlerResult = {
	authenticationMethod: "None";
	isAuthenticated: false;
} & AuthenticationHandlerResultBase;

export type NoAuthenticationHandler = () => Promise<NoAuthenticationHandlerResult>;

export const noAuthenticationHandler: NoAuthenticationHandler = () => {
	return Promise.resolve({
		authenticationMethod: "None",
		isAuthenticated: false
	});
};
