import { createHash, randomBytes } from "crypto";
import { SimpleLoggerInterface } from "ts-simple-interfaces";
import { IoInterface, LibInterface } from "./Types";

/**
 * We're encapsulating our library as a class so that dependents can easily override methods to
 * achieve finely-tuned final functionality.
 */
export abstract class Lib implements LibInterface {
  /**
   * Send a new email verification code to the given email, invalidating all others already sent.
   *
   * Note that this works for both verification codes and logins
   */
  public async sendVerificationCodeEmail(
    email: string,
    r: { io: IoInterface; log: SimpleLoggerInterface; config: AccountsModuleConfig; }
  ): Promise<void> => {
    r.log.debug(`Running sendVerificationCodeEmail`);
    await this.sendLoginOrVerCodeEmail(
      email,
      "verification",
      null,
      Date.now() + 1000 * 60 * r.config.expires.verificationCodeMin,
      r);
  }

  public async sendLoginCodeEmail(
    email: string,
    userGeneratedToken: string,
    expiresMs: number,
    r: { io: IoInterface; log: SimpleLoggerInterface; }
  ): Promise<void> {
    r.log.debug(`Running sendLoginCodeEmail`);
    await this.sendLoginOrVerCodeEmail(
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
  ): Promise<Auth.Db.VerificationCode & { code: Buffer }> {
    log.debug(`Generating new verification code`);

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

    await r.io.insertVerificationCode(verification, r.log);

    return { code, ...verification };
  }

  /**
   * Generates a new session, stores it, and returns the details
   */
  public async generateSession(
    userId: string,
    userAgent: string | undefined,
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
        ip: auth.ip,
        userId: userId,
        refreshTokenSha256: createHash("sha256")
          .update(refreshToken)
          .digest(),
        invalidated: 0,
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
    r: { io: IoInterface; log: SimpleLoggerInterface; }
  ): Promise<void> => {
    r.log.debug(`Running sendLoginOrVerCodeEmail`);

    // Invalidate current verifications
    r.log.debug(`Invalidating existing ${type} codes and getting user by email`);
    const [user] = await Promise.all([
      r.io.getUserByEmail(email, r.log, true),
      r.io.invalidateVerificationCodesFor(type, email),
    ]);

    const verification = await this.generateVerificationCode(
      type,
      email,
      userGeneratedToken,
      expiresMs,
      r.log
    );

    const codeStr = verification.code.toString("hex");
    const verificationLink = this.generateVerificationLink(type, codeStr, userGeneratedToken, r.log);

    // Send email
    await this.sendCodeEmail(type, email, user, verificationLink, r.log);
  }

  protected abstract generateVerificationLink(
    type: "login" | "verification",
    code: string,
    userGeneratedToken: string | undefined,
    log: SimpleLoggerInterface
  ): string;

  protected abstract sendCodeEmail(
    type: string,
    toEmail: string,
    user: Auth.Db.User,
    verificationLink: string,
    log: SimpleLoggerInterface
  );
}
