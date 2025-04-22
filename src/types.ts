export type EnvironmentValue = {
    key: string
    hashAlgorithm: "none" | "sha256"
    encoding: "utf8" | "hex" | "base64"
}

type RequestValueLocation = "Header" | "Cookie" | "QueryStringOrBody";

export type RequestValue = {
    location: RequestValueLocation,
    parameterName: string;
    prefixCaseInsensitive?: string;
}
