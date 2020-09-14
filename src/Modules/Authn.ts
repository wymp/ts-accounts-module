import * as E from "@openfinanceio/http-errors";
import { ModDeps, Auth, isPromise } from "../Types";

declare type SendLoginEmailDeps = Pick<ModDeps, "io" | "log" | "config" | "accountsLib">;
export const sendLoginEmail = async (
  email: string,
  state: string,
  r: SendLoginEmailDeps,
  hooks?: {
    postSendVerificationCodeEmail?: (verification: Auth.Db.VerificationCode & { code: string }, r: SendLoginEmailDeps) => (Promise<unknown> | unknown),
  }
): Promise<void> => {
  r.log.debug(`Getting user by email`);
  const user = await r.io.getUserByEmail(email, r.log);

  // If we didn't find a user for this email, throw NotFound
  if (!user) {
    throw new E.NotFound(
      `Your email was not found on our platform. Please try registering an account.`
    );
  }

  const verification = await r.accountsLib.sendLoginCodeEmail(user.email, state, r);
  if (hooks && hooks.postSendVerificationCodeEmail) {
    const hook = hooks.postSendVerificationCodeEmail(verification, r);
    if (isPromise<unknown>(hook)) {
      await hook;
    }
  }
};

declare type ProcessCodeStepDeps = Pick<ModDeps, "io" | "log" | "config" | "accountsLib">;
export const processCodeStep = async (
  code: string,
  userGeneratedToken: string,
  userAgent: string | undefined,
  ip: string,
  r: ProcessCodeStepDeps,
  hooks?: {
    postConsumeVerification?: (verification: Auth.Db.VerificationCode, r: ProcessCodeStepDeps) => (Promise<unknown> | unknown),
    postGenerateVerificationCode?: (verification: Auth.Db.VerificationCode & { code: string }, r: ProcessCodeStepDeps) => (Promise<unknown> | unknown),
    postGenerateSession?: (session: Auth.Api.Authn.Session, r: ProcessCodeStepDeps) => (Promise<unknown> | unknown),
  }
): Promise<Auth.Api.Authn.Response> => {
  const verification = await r.io.consumeVerificationCode(code, userGeneratedToken, r.log);
  if (hooks && hooks.postConsumeVerification) {
    const hook = hooks.postConsumeVerification(verification, r);
    if (isPromise<unknown>(hook)) {
      await hook;
    }
  }

  const user = await r.io.getUserByEmail(verification.email, r.log, true);

  // If the user has 2fa enabled, generate a new code and send it back for the TOTP step
  if (user["2fa"] === 1) {
    r.log.info(`User has 2fa enabled. Returning TOTP step.`);
    const newVerification = await r.accountsLib.generateVerificationCode(
      "login",
      verification.email,
      userGeneratedToken,
      Date.now() + 1000 * 60 * r.config.expires.loginCodeMin,
      r
    );
    if (hooks && hooks.postGenerateVerificationCode) {
      const hook = hooks.postGenerateVerificationCode(newVerification, r);
      if (isPromise<unknown>(hook)) {
        await hook;
      }
    }

    return {
      t: "step",
      step: Auth.Api.Authn.Types.Totp,
      code: newVerification.code,
      state: userGeneratedToken!,
    };
  }

  // Otherwise, generate and return session
  const session = await r.accountsLib.generateSession(user.id, userAgent, ip, r);
  if (hooks && hooks.postGenerateSession) {
    const hook = hooks.postGenerateSession(session, r);
    if (isPromise<unknown>(hook)) {
      await hook;
    }
  }

  return session
};

declare type ProcessPasswordStepDeps = Pick<ModDeps, "io" | "log" | "config" | "cache" | "bcrypt" | "accountsLib">;
export const processPasswordStep = async (
  email: string,
  password: string,
  userGeneratedToken: string,
  userAgent: string | undefined,
  ip: string,
  r: ProcessPasswordStepDeps,
  hooks?: {
    postGenerateVerificationCode?: (verification: Auth.Db.VerificationCode & { code: string }, r: ProcessPasswordStepDeps) => (Promise<unknown> | unknown),
    postGenerateSession?: (session: Auth.Api.Authn.Session, r: ProcessPasswordStepDeps) => (Promise<unknown> | unknown),
  }
): Promise<Auth.Api.Authn.Response> => {
  const user = await r.io.getUserByEmail(email, r.log, true);
  const success = await compareSecret(password, user.passwordHash, r);
  if (!success) {
    throw new E.Unauthorized(`The password you've supplied is not correct.`);
  }

  // If the user has 2fa enabled, generate a new code and send it back for the TOTP step
  if (user["2fa"] === 1) {
    r.log.info(`User has 2fa enabled. Returning TOTP step.`);
    const newVerification = await r.accountsLib.generateVerificationCode(
      "login",
      email,
      userGeneratedToken,
      Date.now() + 1000 * 60 * r.config.expires.loginCodeMin,
      r
    );
    if (hooks && hooks.postGenerateVerificationCode) {
      const hook = hooks.postGenerateVerificationCode(newVerification, r);
      if (isPromise<unknown>(hook)) {
        await hook;
      }
    }

    return {
      t: "step",
      step: Auth.Api.Authn.Types.Totp,
      code: newVerification.code,
      state: userGeneratedToken!,
    };
  }

  // Otherwise, generate and return session
  const session = await r.accountsLib.generateSession(user.id, ip, userAgent, r);
  if (hooks && hooks.postGenerateSession) {
    const hook = hooks.postGenerateSession(session, r);
    if (isPromise<unknown>(hook)) {
      await hook;
    }
  }

  return session;
};

/**
 * Authenticate the passed in credentials against what's in the database, caching result for 5
 * minutes
 */
export const compareSecret = async (
  secret: string | null,
  secretHash: string | null,
  r: Pick<ModDeps, "log" | "cache" | "bcrypt">
): Promise<boolean> => {
  const key = `${secret}:${secretHash}`;
  const authenticated = await r.cache.get<boolean>(
    key,
    async () => {
      if (!secret || !secretHash) {
        return false;
      }
      try {
        return await r.bcrypt.compare(secret, secretHash);
      } catch (e) {
        r.log.error(
          "Found a malformed apikey/secret hash in database: " +
            secretHash +
            "; Message: " +
            e.message
        );
        return false;
      }
    },
    300000
  );
  return authenticated;
};

