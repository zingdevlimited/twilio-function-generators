export type RequestParameterLocation = "Header" | "Cookie" | "QueryStringOrBody";

export type RequestParameter = {
	parameterName: string;
	location: RequestParameterLocation;
	validateHasCaseInsensitivePrefix?: string;
};
