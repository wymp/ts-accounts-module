import { SimpleLoggerInterface } from "ts-simple-interfaces";

export type AccountsModuleConfig = {
  expires: {
    sessionHour: number;
    sessionTokenMin: number;
    verificationCodeMin: number;
    loginCodeMin: number;
  };
};

export interface IoInterface {
  consumeVerificationCode(
    code: string,
    userGeneratedToken: string | null,
    log: SimpleLoggerInterface
  ): Promise<Auth.Db.VerificationCode>;

  markEmailVerified(
    email: string,
    log: SimpleLoggerInterface
  ): Promise<void>;

  getVerificationByCode(
    code: string,
    log: SimpleLoggerInterface,
    thrw: true
  ): Promise<Auth.Db.VerificationCode>;
  getVerificationByCode(
    code: string,
    log: SimpleLoggerInterface,
    thrw?: false
  ): Promise<Auth.Db.VerificationCode | undefined>;

  getUserByEmail(
    email: string,
    log: SimpleLoggerInterface,
    thrw: true
  ): Promise<Auth.Db.User & Auth.LoginEmailAttributes & { loginEmailCreatedMs: number }>;
  getUserByEmail(
    email: string,
    log: SimpleLoggerInterface,
    thrw?: false
  ): Promise<
    (Auth.Db.User & Auth.LoginEmailAttributes & { loginEmailCreatedMs: number }) | undefined
  >;

  invalidateVerificationCodesFor(
    type: string,
    email: string,
    log: SimpleLoggerInterface
  ): Promise<void>;

  generateVerificationCode(
    type: "login" | "verification",
    email: string,
    userGeneratedToken: string | null,
    expiresMs: number,
    log: SimpleLoggerInterface
  ): Promise<Auth.Db.VerificationCode & { code: Buffer }>;

  generateSession(
    userId: string,
    userAgent: string | undefined,
    log: SimpleLoggerInterface
  ): Promise<Auth.Api.Authn.Session>;

  insertUser(
    user: Auth.Db.User,
    log: SimpleLoggerInterface
  ): Promise<Auth.Db.User>;

  insertLoginEmail(
    userId: string,
    email: string,
    log: SimpleLoggerInterface
  ): Promise<void>;
}

export interface LibInterface {
  sendVerificationCodeEmail(
    email: string,
    expiresMs: number,
    r: { io: IoInterface; log: SimpleLoggerInterface; }
  ): Promise<void>;

  sendLoginCodeEmail(
    email: string,
    userGeneratedToken: string,
    expiresMs: number,
    r: { io: IoInterface; log: SimpleLoggerInterface; }
  ): Promise<void>;

  generateVerificationCode(
    type: "login" | "verification",
    email: string,
    userGeneratedToken: string | null,
    expiresMs: number,
    r: { io: IoInterface; log: SimpleLoggerInterface; }
  ): Promise<Auth.Db.VerificationCode & { code: Buffer }>;

  generateSession(
    userId: string,
    userAgent: string | undefined,
    r: { io: IoInterface; log: SimpleLoggerInterface; config: AccountsModuleConfig }
  ): Promise<Auth.Api.Authn.Session>;
}

export namespace Auth {
  /**
   * This structure represents the expected authn/z info that may be attached to any request made
   * against the system. Keys are as follows:
   *
   * k = clientId
   * a = authorized (true if the request contained a secret key that was valid, false if it did not
   *     provide a secret key. Invalid secret keys should produce an error response.)
   * r = client roles - An array of string role names that this client has, to be used to validate
   *     that the client does or does not have access to certain functionality
   * ip = ip address from which the request originated
   * u.id = user id
   * u.r = user roles - An array of string role names that this user has, to be used to validate
   *       that the user does or does not have access to certain functionality
   * u.s = scopes - An optional array of scopes granted via oauth. If null, then this is a direct
   *       user request and not an oauth request.
   */
  export type ReqInfo = {
    k: string;
    a: boolean;
    r: Array<Globals.ClientRoles>;
    ip: string;
    u?: {
      id: string;
      r: Array<Globals.UserRoles>;
      s: Array<Globals.AuthScopes> | null;
    };
  };

  /**
   * Our concept of organizations is very primitive currently. Consider this a stub for future
   * development.
   */
  export type OrganizationAttributes = {
    name: string;
    createdMs: number;
  };

  /**
   * Client belong to organizations. Clients will be, e.g., "My Android App", "My Website", etc...
   */
  export type ClientAttributes = {
    secretHash: string;
    name: string;
    rateLimit: number;
    requireUser: 0 | 1;
    redirectUri: string;
    createdMs: number;
  };

  /**
   * The server may restrict certain clients in certain ways. Users who manage clients may request
   * that clients be restricted by ip address and/or host name, and the server may optionally
   * restrict client access to certain specific APIs.
   */
  export enum ClientAccessRestrictionTypes {
    Ip = "ip",
    Host = "host",
    Api = "api",
  }
  export type ClientAccessRestrictionAttributes = {
    type: ClientAccessRestrictionTypes;
    value: string;
    createdMs: number;
  };

  /**
   * Our
   */
  export enum LoginMethods {
    Email = "email",
    Password = "password",
  }
  export type UserAttributes = {
    name: string;
    passwordHash: string | null;
    banned: 0 | 1;
    loginMethod: LoginMethods;
    "2fa": 0 | 1;
    createdMs: number;
  };

  export type LoginEmailAttributes = {
    email: string;
    verified: 0 | 1;
    createdMs: number;
  };

  export type VerificationCodeAttributes = {
    codeSha256: Buffer;
    type: "login" | "verification";
    email: string;
    userGeneratedToken: string | null;
    createdMs: number;
    expiresMs: number;
    consumedMs: number | null;
    invalidatedMs: number | null;
  };

  export type UserRoleAttributes = {
    roleId: Globals.UserRoles;
  };

  export type SessionAttributes = {
    userAgent: string | null;
    ip: string;
    refreshTokenSha256: Buffer;
    invalidated: 0 | 1;
    createdMs: number;
    expiresMs: number;
  };

  /**
   *
   *
   * API namespace
   *
   *
   */
  export namespace Api {
    /**
     * User registration/verification
     */
    export type PostUser = {
      name: string;
      email: string;
      password?: string;
      passwordConf?: string;
    };

    /**
     *
     * Authentication Flow Types
     *
     */

    export namespace Authn {
      export enum Types {
        Email = "email",
        Password = "password",
        Code = "code",
        Totp = "totp",
      }

      export type Request = {
        idType: Types.Email | Types.Code;
        idValue: string;
        state: string;
        secret?: string;
      };

      export type Step = {
        t: "step";
        step: Types;
        code: string;
        state: string;
      };

      export type Session = {
        t: "session";
        token: string;
        refresh: string;
      };

      export type Response = Step | Session;
    }
  }

  /**
   *
   *
   * Database namespace
   *
   *
   */
  export namespace Db {
    // Apis are identified by their domain and version, so no formal "id" property here
    export type Api = ApiAttributes;
    export type Organization = { id: string } & OrganizationAttributes;
    export type Client = ClientAttributes & {
      id: string;
      organizationId: string;
    };
    export type ClientAccessRestrictions = { id: string } & ClientAccessRestrictionAttributes;
    export type User = { id: string } & UserAttributes;
    export type LoginEmail = { userId: string } & LoginEmailAttributes;
    export type VerificationCode = VerificationCodeAttributes;
    export type UserRole = { userId: string } & UserRoleAttributes;
    export type Session = { id: string; userId: string } & SessionAttributes;
    export type SessionToken = {
      tokenSha256: Buffer;
      sessionId: string;
      expiresMs: number;
    };
  }
}
