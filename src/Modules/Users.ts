import * as uuid from "uuid";
import * as E from "@openfinanceio/http-errors";
import { ModDeps, Auth } from "../Types";

/**
 *
 *
 *
 *
 * Functions
 *
 *
 *
 *
 */

/**
 * Create a user, send verification email, and return a new session
 *
 * TODO: Break into smaller pieces for better testing
 */
declare type CreateUserDeps = Pick<ModDeps, "config" | "log" | "io" | "accountsLib" | "bcrypt">;
export const createUser = async (
  postUser: Auth.Api.PostUser & { id?: string | null | undefined },
  userAgent: string | undefined,
  ip: string,
  r: CreateUserDeps,
  hooks?: {
    postInsertUser?: (user: Auth.Db.User, r: CreateUserDeps) => (Promise<unknown> | unknown),
    postInsertLoginEmail?: (loginEmail: Auth.Db.LoginEmail, r: CreateUserDeps) => (Promise<unknown> | unknown),
    postSendVerificationCodeEmail?: (verification: Auth.Db.VerificationCode & { code: string }, r: CreateUserDeps) => (Promise<unknown> | unknown),
    postGenerateSession?: (session: Auth.Api.Authn.Session, r: CreateUserDeps) => (Promise<unknown> | unknown),
  }
): Promise<Auth.Api.Authn.Session> => {
  r.log.debug(`Called Wymp createUser`);

  // Check to see if payload looks good
  let obstructions = r.accountsLib.validateEmail(postUser.email);

  // If password provided, validate password
  if (postUser.password) {
    obstructions = obstructions.concat(
      r.accountsLib.validatePasswordLength(postUser.password),
      r.accountsLib.validatePasswordEntropy(postUser.password)
    );

    // Confirmation
    if (!postUser.passwordConf) {
      obstructions.push({
        code: "Missing Password Confirmation",
        text: "You must fill out the 'Password confirmation' (passwordConf) field",
      });
    } else {
      if (postUser.password !== postUser.passwordConf) {
        obstructions.push({
          code: "Invalid Password Confirmation",
          text: "The password confirmation you passed doesn't match the password you've specified",
        });
      }
    }
  }

  if (obstructions.length > 0) {
    const e = new E.BadRequest("Couldn't create user", "USER_DATA_INVALID");
    e.obstructions = obstructions;
    throw e;
  }

  // Check to see if user already exists
  if (await r.io.getUserByEmail(postUser.email, r.log)) {
    const e = new E.DuplicateResource("A user with this email already exists", "DUPLICATE");
    e.obstructions = [
      {
        code: "Duplicate User",
        text:
          `Email ${postUser.email} is already registered to a user in our system. Please try ` +
          `logging in.`,
      },
    ];
    throw e;
  }

  r.log.info(`New user passed validation`);

  // Hash password, if present
  let passwordHash: string | null = null;
  if (postUser.password) {
    r.log.debug(`Hashing password`);
    passwordHash = await r.bcrypt.hash(postUser.password, 10);
  }

  // Insert user into database
  const user = await r.io.insertUser(
    {
      id: postUser.id || uuid.v4(),
      name: postUser.name,
      passwordHash,
      banned: 0,
      loginMethod: postUser.password ? Auth.LoginMethods.Password : Auth.LoginMethods.Email,
      "2fa": 0,
      createdMs: Date.now(),
    },
    r.log
  );
  if (hooks && hooks.postInsertUser) {
    const hook = hooks.postInsertUser(user, r);
    if (isPromise<unknown>(hook)) {
      await hook;
    }
  }

  // Insert login email
  const loginEmail = await r.io.insertLoginEmail(user.id, postUser.email, r.log);
  if (hooks && hooks.postInsertLoginEmail) {
    const hook = hooks.postInsertLoginEmail(loginEmail, r);
    if (isPromise<unknown>(hook)) {
      await hook;
    }
  }

  // Send verification email
  const verification = await r.accountsLib.sendVerificationCodeEmail(postUser.email, r);
  if (hooks && hooks.postSendVerificationCodeEmail) {
    const hook = hooks.postSendVerificationCodeEmail(verification, r);
    if (isPromise<unknown>(hook)) {
      await hook;
    }
  }

  // Generate and return session
  const session = await r.accountsLib.generateSession(user.id, userAgent, ip, r);
  if (hooks && hooks.postGenerateSession) {
    const hook = hooks.postGenerateSession(session, r);
    if (isPromise<unknown>(hook)) {
      await hook;
    }
  }

  return session;
};

const isPromise = <T>(f: any): f is Promise<T> => {
  return typeof f.then === "function";
}
