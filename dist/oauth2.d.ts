import { OAuth2Client } from "google-auth-library";
export declare const createOAuth2Client: (queryConfig?: Record<string, any>) => OAuth2Client | null;
export declare const launchAuthServer: (oauth2Client: OAuth2Client) => Promise<unknown>;
export declare const validateCredentials: (oauth2Client: OAuth2Client) => Promise<boolean>;
