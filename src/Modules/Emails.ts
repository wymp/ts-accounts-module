import * as E from "@openfinanceio/http-errors";
import { ModDeps, Auth, isPromise } from "../Types";

/**
 * Verify email address using passed in code
 */
declare type VerifyEmailDeps = Pick<ModDeps, "io" | "log" | "accountsLib">;
export const verifyEmail = async (
  code: string,
  r: VerifyEmailDeps,
  hooks?: {
    postConsumeVerificationCode?: (verification: Auth.Db.VerificationCode, r: VerifyEmailDeps) => (Promise<unknown> | unknown),
    postMarkEmailVerified?: (email: string, r: VerifyEmailDeps) => (Promise<unknown> | unknown),
  }
): Promise<void> => {
  r.log.info(`Verifying email using code ${code}`);
  const verification = await r.io.consumeVerificationCode(code, null, r.log);
  if (hooks && hooks.postConsumeVerificationCode) {
    const hook = hooks.postConsumeVerificationCode(verification, r);
    if (isPromise<unknown>(hook)) {
      await hook;
    }
  }
  r.log.info(`Code successfully consumed`);

  await r.io.markEmailVerified(verification.email, r.log);
  if (hooks && hooks.postMarkEmailVerified) {
    const hook = hooks.postMarkEmailVerified(verification.email, r);
    if (isPromise<unknown>(hook)) {
      await hook;
    }
  }
  r.log.info(`Email marked verified`);
};

/**
 * Resend email verification code
 */
declare type ResendVerificationDeps = Pick<ModDeps, "log" | "io" | "accountsLib" | "config">;
export const resendVerification = async (
  payload: { t: "email"; email: string } | { t: "code"; code: string },
  userId: string | null,
  r: ResendVerificationDeps,
  hooks?: {
    postSendVerificationCodeEmail?: (verification: Auth.Db.VerificationCode & { code: string }, r: ResendVerificationDeps) => (Promise<unknown> | unknown),
  }
): Promise<void> => {
  let email: string;
  // If they passed a code, try to find it and validate it
  if (payload.t === "code") {
    r.log.debug(`Code submitted`);
    const verification = await r.io.getVerificationByCode(payload.code, r.log, true);
    if (verification.invalidatedMs !== null) {
      throw new E.BadRequest(
        `The verification code you've provided doesn't exist.`,
        `CODE-NOT-FOUND`
      );
    }
    r.log.notice(`Found valid verification code. Resending email.`);
    email = verification.email;
  } else {
    // If they didn't pass a code, then they must be within an active session and the email
    // passed must be one of their registered email addresses
    if (!userId) {
      throw new E.BadRequest(
        `You must have an active session to use this endpoint, or submit a valid ` +
          `prior verification code as { data: { code: string; }  } in the request body.`,
        `LOGIN-REQUIRED`
      );
    }

    // If we didn't find a user or it's not the right user, throw
    const user = await r.io.getUserByEmail(payload.email, r.log);
    if (!user || user.id !== userId) {
      throw new E.BadRequest(
        `This email is not associated with your account`,
        `UNREGISTERED-EMAIL`
      );
    }

    // If the email is already verified, throw
    if (user.verifiedMs !== null) {
      throw new E.BadRequest(`This email has already been verified`, `ALREADY-VERIFIED`);
    }

    email = payload.email;
  }

  r.log.info(`Resending verification email`);
  const verification = await r.accountsLib.sendVerificationCodeEmail(
    email,
    r
  );
  if (hooks && hooks.postSendVerificationCodeEmail) {
    const hook = hooks.postSendVerificationCodeEmail(verification, r);
    if (isPromise<unknown>(hook)) {
      await hook;
    }
  }
};

