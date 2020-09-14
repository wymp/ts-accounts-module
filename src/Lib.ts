import { createHash, randomBytes } from "crypto";
import { SimpleLoggerInterface } from "ts-simple-interfaces";
import * as uuid  from "uuid";
import * as E from "@openfinanceio/http-errors";
import { IoInterface, LibInterface, emailPattern, AccountsModuleConfig, Auth } from "./Types";

/**
 * We're encapsulating our library as a class so that dependents can easily override methods to
 * achieve finely-tuned final functionality.
 *
 * **NOTE: THIS IS NOT A STATEFUL LIBRARY. It is only a class to make it easier to override certain
 * functionality.**
 */
declare type LogDeps = { log: SimpleLoggerInterface };
export abstract class Lib<VerLinkDeps extends LogDeps, SendCodeEmailDeps extends LogDeps> implements LibInterface<VerLinkDeps, SendCodeEmailDeps> {
  /**
   * Email verifications for user creation
   */
  public validateEmail(email: string): Array<E.ObstructionInterface> {
    if (!email.match(new RegExp(emailPattern, "i"))) {
      return [{
        code: "Invalid Email",
        text: "The email address you've provided doesn't appear valid according to our standards.",
        params: {
          input: email,
          regex: emailPattern,
        },
      }];
    }
    return [];
  }

  /**
   * Validate password length
   */
  public validatePasswordLength(password: string): Array<E.ObstructionInterface> {
    const obstructions: Array<E.ObstructionInterface> = [];
    if (password.length < 8) {
      obstructions.push({
        code: "Password",
        text: "Must be at least 8 characters long",
        params: { passwordLength: password.length },
      });
    }
    if (password.length > 72) {
      obstructions.push({
        code: "Password",
        text: "Cannot exceed 72 characters",
        params: { passwordLength: password.length },
      });
    }
    return obstructions;
  }

  /**
   * Validate password entropy
   */
  public validatePasswordEntropy(password: string): Array<E.ObstructionInterface> {
    const obstructions: Array<E.ObstructionInterface> = [];
    let m = password.match(/([a-z])/);
    if (m === null || m.length < 2) {
      obstructions.push({
        code: "Password",
        text: "Must have at least 2 lower-case letters",
      });
    }
    m = password.match(/([A-Z])/);
    if (m === null || m.length < 2) {
      obstructions.push({
        code: "Password",
        text: "Must have at least 2 upper-case letters",
      });
    }
    m = password.match(/([0-9])/);
    if (m === null || m.length < 2) {
      obstructions.push({
        code: "Password",
        text: "Must have at least 2 numbers",
      });
    }
    m = password.match(/([^a-zA-Z0-9])/);
    if (m === null || m.length < 2) {
      obstructions.push({
        code: "Password",
        text: "Must have at least 2 non alpha-numeric characters",
      });
    }
    return obstructions;
  }

  /**
   * Send a new email verification code to the given email, invalidating all others already sent.
   *
   * Note that this works for both verification codes and logins
   */
  public async sendVerificationCodeEmail(
    email: string,
    r: VerLinkDeps & SendCodeEmailDeps & { io: IoInterface; config: AccountsModuleConfig; }
  ): Promise<Auth.Db.VerificationCode & { code: string }> {
    r.log.debug(`Running sendVerificationCodeEmail`);
    return await this.sendLoginOrVerCodeEmail(
      email,
      "verification",
      null,
      Date.now() + 1000 * 60 * r.config.expires.verificationCodeMin,
      r
    );
  }

  public async sendLoginCodeEmail(
    email: string,
    userGeneratedToken: string,
    r: VerLinkDeps & SendCodeEmailDeps & { io: IoInterface; config: AccountsModuleConfig; }
  ): Promise<Auth.Db.VerificationCode & { code: string }> {
    r.log.debug(`Running sendLoginCodeEmail`);
    return await this.sendLoginOrVerCodeEmail(
      email,
      "login",
      userGeneratedToken,
      Date.now() + 1000 * 60 * r.config.expires.loginCodeMin,
      r
    );
  }

  public async generateVerificationCode(
    type: "login" | "verification",
    email: string,
    userGeneratedToken: string | null,
    expiresMs: number,
    r: { io: IoInterface; log: SimpleLoggerInterface; }
  ): Promise<Auth.Db.VerificationCode & { code: string }> {
    r.log.debug(`Generating new verification code`);

    // Generate
    const code = randomBytes(32);
    const codeSha256 = createHash("sha256")
      .update(code)
      .digest();
    const createdMs = Date.now();

    // Wrap in a new object
    const verification = {
      codeSha256,
      type,
      email,
      userGeneratedToken,
      createdMs,
      expiresMs,
      consumedMs: null,
      invalidatedMs: null,
    };

    await r.io.saveVerificationCode(verification, r.log);

    return { code: code.toString("hex"), ...verification };
  }

  /**
   * Generates a new session, stores it, and returns the details
   */
  public async generateSession(
    userId: string,
    userAgent: string | undefined,
    ip: string,
    r: { io: IoInterface; log: SimpleLoggerInterface; config: AccountsModuleConfig }
  ): Promise<Auth.Api.Authn.Session> {
    // Create session
    r.log.notice(`Generating a new session`);

    const refreshToken = randomBytes(32).toString("hex");
    const sessionToken = randomBytes(32).toString("hex");
    const session = await r.io.insertSession(
      {
        id: uuid.v4(),
        userAgent: userAgent || null,
        ip,
        userId: userId,
        refreshTokenSha256: createHash("sha256")
          .update(refreshToken)
          .digest(),
        invalidatedMs: null,
        createdMs: Date.now(),
        expiresMs: Date.now() + 1000 * 60 * 60 * r.config.expires.sessionHour,
      },
      r.log
    );
    await r.io.insertSessionToken(
      {
        tokenSha256: createHash("sha256")
          .update(sessionToken)
          .digest(),
        sessionId: session.id,
        createdMs: Date.now(),
        expiresMs: Date.now() + 1000 * 60 * r.config.expires.sessionTokenMin,
      },
      r.log
    );

    return {
      t: "session",
      token: sessionToken,
      refresh: refreshToken,
    };
  }

  protected async sendLoginOrVerCodeEmail(
    email: string,
    type: "login" | "verification",
    userGeneratedToken: string | null,
    expiresMs: number,
    r: VerLinkDeps & SendCodeEmailDeps & { io: IoInterface }
  ): Promise<Auth.Db.VerificationCode & { code: string }> {
    r.log.debug(`Running sendLoginOrVerCodeEmail`);

    // Invalidate current verifications
    r.log.debug(`Invalidating existing ${type} codes and getting user by email`);
    const [user] = await Promise.all([
      r.io.getUserByEmail(email, r.log, true),
      r.io.invalidateVerificationCodesFor(type, email, r.log),
    ]);

    const verification = await this.generateVerificationCode(
      type,
      email,
      userGeneratedToken,
      expiresMs,
      r
    );

    const verificationLink = this.generateVerificationLink(type, verification.code, userGeneratedToken, r);

    // Send email
    await this.sendCodeEmail(type, email, user, verificationLink, r);

    return verification;
  }

  protected abstract generateVerificationLink(
    type: "login" | "verification",
    code: string,
    userGeneratedToken: string | null,
    r: VerLinkDeps
  ): string;

  protected abstract sendCodeEmail(
    type: string,
    toEmail: string,
    user: Auth.Db.User,
    verificationLink: string,
    r: SendCodeEmailDeps
  ): Promise<unknown>;
}
