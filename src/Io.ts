import { createHash } from "crypto";
import { SimpleLoggerInterface, SimpleSqlDbInterface } from "ts-simple-interfaces";
import { CacheInterface } from "@openfinanceio/cache";
import * as E from "@openfinanceio/http-errors";
import { Auth, IoInterface } from "./Types";

/**
 * This class abstracts all io access into generalized or specific declarative method calls
 */
export class Io implements IoInterface {
  public constructor(
    protected db: SimpleSqlDbInterface,
    protected _cache?: CacheInterface
  ) {}

  /**
   * 'Cache' methods for dealing with when we don't actually have a cache
   */
  protected getCached<T>(key: string, log?: SimpleLoggerInterface): T | undefined;
  protected getCached<T>(key: string, q: (() => T) | (() => Promise<T>), ttlSec?: number, log?: SimpleLoggerInterface): Promise<T>;
  protected getCached<T>(
    key: string,
    q?: (() => T) | (() => Promise<T>) | undefined | SimpleLoggerInterface,
    ttlSec?: number,
    log?: SimpleLoggerInterface
  ): T | Promise<T> | undefined {
    if (this._cache) {
      if (typeof q === "function") {
        return this._cache.get<T>(key, q, ttlSec, log);
      } else {
        return this._cache.get<T>(key, q);
      }
    } else if (typeof q === "function") {
      return q();
    }
    return undefined;
  }

  protected clearCached(key?: string | RegExp, log?: SimpleLoggerInterface): void {
    if (this._cache) {
      this._cache.clear(key, log);
    }
  }

  protected obfuscateEmail(email: string): string {
    return email.replace(/^(.{1,3}).*(@.*)$/, "$1...$2");
  }

  /**
   * Insert a new user
   */
  public async insertUser(
    user: Auth.Db.User,
    log: SimpleLoggerInterface
  ): Promise<Auth.Db.User> {
    log.debug(`Inserting user ${user.name} (${user.id}) into database`);
    await this.db.query("INSERT INTO `users` VALUES (?)", [
      [
        user.id,
        user.name,
        user.passwordHash,
        user.banned,
        user.loginMethod,
        user["2fa"],
        user.createdMs,
      ],
    ]);
    return user;
  }

  /**
   * Get user by email
   */
  public getUserByEmail(
    email: string,
    log: SimpleLoggerInterface,
    thrw: true
  ): Promise<Auth.Db.User & Auth.LoginEmailAttributes & { loginEmailCreatedMs: number }>;
  public getUserByEmail(
    email: string,
    log: SimpleLoggerInterface,
    thrw?: false
  ): Promise<
    (Auth.Db.User & Auth.LoginEmailAttributes & { loginEmailCreatedMs: number }) | undefined
  >;
  public getUserByEmail(
    email: string,
    log: SimpleLoggerInterface,
    thrw?: boolean
  ): Promise<
    (Auth.Db.User & Auth.LoginEmailAttributes & { loginEmailCreatedMs: number }) | undefined
  > {
    log.debug(`Getting user by email`);
    const user = this.getCached<
      (Auth.Db.User & Auth.LoginEmailAttributes & { loginEmailCreatedMs: number }) | undefined
    >(
      `user-by-email-${email}`,
      async () => {
        const { rows } = await this.db.query<
          Auth.Db.User & Auth.LoginEmailAttributes & { loginEmailCreatedMs: number }
        >(
          "SELECT `u`.*, `e`.`email`, `e`.`verifiedMs`, `e`.`createdMs` as `loginEmailCreatedMs` " +
            "FROM `users` `u` JOIN `login-emails` `e` ON (`u`.`id` = `e`.`userId`) " +
            "WHERE `e`.`email` = ?",
          [email]
        );

        return rows[0];
      },
      undefined,
      log
    );

    if (!user && thrw) {
      throw new E.NotFound(`No users with email ${email} exist in our system. Try signing up.`);
    } else {
      return user;
    }
  }

  /**
   * Insert a new login email
   *
   * This function additionally sends a verification email to the given address
   */
  public async insertLoginEmail(
    userId: string,
    email: string,
    log: SimpleLoggerInterface
  ): Promise<Auth.Db.LoginEmail> {
    log.debug(`Running insertLoginEmail`);
    const existingUser = await this.getUserByEmail(email, log);
    const obf = this.obfuscateEmail(email);

    const loginEmail = {
      email,
      userId,
      verifiedMs: null,
      createdMs: Date.now(),
    }

    // If we don't already have that email registered, register it
    if (!existingUser) {
      log.debug(`No user found with this email. Inserting email ${obf} for user ${userId}`);
      await this.db.query(
        "INSERT INTO `login-emails` " +
        "(`email`, `userId`, `verifiedMs`, `createdMs`) " +
        "VALUES (?)",
        [[ loginEmail.email, loginEmail.userId, loginEmail.verifiedMs, loginEmail.createdMs]]
      );
    } else {
      // If we found a user with this email, make sure the id is the same
      log.debug(
        `User found with email ${obf}: ${existingUser.id}. Checking for match against userId ` +
          `${userId}.`
      );
      if (existingUser.id !== userId) {
        throw new E.DuplicateResource(
          `Email ${email} is already in use by another user on the platform.`
        );
      }
      log.debug(`Passed`);
    }

    // Clear cache for this user
    this.clearCached(`user-by-email-${email}`);

    return loginEmail;
  }

  /**
   * Invalidate verification codes of the given type for the given email
   */
  public async invalidateVerificationCodesFor(
    type: string,
    email: string,
    log: SimpleLoggerInterface
  ): Promise<void> {
    await this.db.query(
      "UPDATE `verification-codes` SET `invalidatedMs` = ? " +
      "WHERE `type` = ? && `email` = ? && `invalidatedMs` IS NULL && `consumedMs` IS NULL",
      [Date.now(), type, email]
    );
  }

  /**
   * Save the given verification code to the database
   */
  public async saveVerificationCode(
    verification: Auth.Db.VerificationCode,
    log: SimpleLoggerInterface
  ): Promise<Auth.Db.VerificationCode> {
    // Insert
    await this.db.query(
      "INSERT INTO `verification-codes` " +
      "(`codeSha256`, `type`, `email`, `userGeneratedToken`, `createdMs`, `expiresMs`, " +
      "`consumedMs`, `invalidatedMs`) " +
      "VALUES (?)",
      [[
        verification.codeSha256,
        verification.type,
        verification.email,
        verification.userGeneratedToken,
        verification.createdMs,
        verification.expiresMs,
        verification.consumedMs,
        verification.invalidatedMs,
      ]]
    );
    return verification;
  }

  /**
   * Get verification data
   */
  public async getVerificationByCode(
    code: string,
    log: SimpleLoggerInterface,
    thrw: true
  ): Promise<Auth.Db.VerificationCode>;
  public async getVerificationByCode(
    code: string,
    log: SimpleLoggerInterface,
    thrw?: false
  ): Promise<Auth.Db.VerificationCode | undefined>;
  public async getVerificationByCode(
    code: string,
    log: SimpleLoggerInterface,
    thrw?: boolean
  ): Promise<Auth.Db.VerificationCode | undefined> {
    log.info(`Getting verification code ${code}`);
    const codeSha256 = createHash("sha256")
      .update(Buffer.from(code, "hex"))
      .digest();
    const { rows } = await this.db.query<Auth.Db.VerificationCode>(
      "SELECT * FROM `verification-codes` WHERE `codeSha256` = ?",
      [codeSha256]
    );
    if (!rows[0] && thrw) {
      throw new E.BadRequest(
        `The verification code you've provided doesn't exist.`,
        `CODE-NOT-FOUND`
      );
    } else {
      return rows[0];
    }
  }

  /**
   * Consume verification code
   */
  public async consumeVerificationCode(
    code: string,
    userGeneratedToken: string | null,
    log: SimpleLoggerInterface
  ): Promise<Auth.Db.VerificationCode> {
    const verification = await this.getVerificationByCode(code, log, true);

    // Make sure we _can_ consume the code
    if (verification.consumedMs !== null) {
      throw new E.BadRequest(
        `This verification code has already been consumed! You don't need to do anything else.`,
        `CODE_CONSUMED`
      );
    }
    if (verification.invalidatedMs !== null) {
      throw new E.BadRequest(
        `This verification code has been invalidated. Please try requesting another email.`,
        `RESEND`
      );
    }
    if (verification.expiresMs < Date.now()) {
      throw new E.BadRequest(
        `This verification code has expired. Please try requesting another email.`,
        `RESEND`
      );
    }
    if (verification.userGeneratedToken !== userGeneratedToken) {
      throw new E.BadRequest(
        `The state parameter you've passed does not match with the one used when creating ` +
          `this authentication code. Please try again.`,
        `RESEND`
      );
    }

    // Now update the records
    await this.db.query("UPDATE `verification-codes` SET `consumedMs` = ? WHERE `codeSha256` = ?", [
      Date.now(),
      verification.codeSha256,
    ]);

    return verification;
  }

  /**
   * Mark email verified
   */
  public async markEmailVerified(
    email: string,
    log: SimpleLoggerInterface
  ): Promise<void> {
    this.db.query(
      "UPDATE `login-emails` SET `verifiedMs` = ? WHERE `email` = ?",
      [Date.now(), email]
    );
  }

  /**
   * Insert a new session into the db
   */
  public async insertSession(
    session: Auth.Db.Session,
    log: SimpleLoggerInterface
  ): Promise<Auth.Db.Session> {
    log.debug(`Inserting session ${session.id} into database`);
    await this.db.query(
      "INSERT INTO `sessions` " +
      "(`id`, `userAgent`, `ip`, `userId`, `refreshTokenSha256`, `invalidatedMs`, `createdMs`, `expiresMs`) " +
      "VALUES (?)",
      [[
        session.id,
        session.userAgent,
        session.ip,
        session.userId,
        session.refreshTokenSha256,
        session.invalidatedMs,
        session.createdMs,
        session.expiresMs,
      ]]
    );
    return session;
  }

  /**
   * Insert session token
   */
  public async insertSessionToken(
    token: Auth.Db.SessionToken,
    log: SimpleLoggerInterface
  ): Promise<Auth.Db.SessionToken> {
    log.debug(`Inserting session token into database for session ${token.sessionId}`);
    await this.db.query(
      "INSERT INTO `session-tokens` " +
      "(`tokenSha256`, `sessionId`, `createdMs`, `expiresMs`) " +
      "VALUES (?)",
      [[
        token.tokenSha256,
        token.sessionId,
        token.createdMs,
        token.expiresMs
      ]]
    );
    return token;
  }
}
