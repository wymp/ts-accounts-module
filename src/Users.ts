import * as bcrypt from "bcrypt";
import * as rt from "runtypes";
import { SimpleHttpServerMiddleware } from "ts-simple-interfaces";
import * as uuid from "uuid";
import { Auth } from "@openfinanceio/data-model-specification";
import * as E from "@openfinanceio/http-errors";
import { Http } from "@openfinanceio/service-lib";
import { tag } from "../../Lib";
import { AppDeps, emailPattern } from "../../Types";
import * as Lib  from "./Lib";

const assertAuthdReq: typeof Http["assertAuthdReq"] = Http.assertAuthdReq;
const OPENFINANCE_NS = uuid.v5("openfinance.io", uuid.v5.DNS);

/**
 *
 *
 *
 *
 * Handlers
 *
 *
 *
 *
 */

const PostUser = rt.Record({
  data: rt.Record({
    name: rt.String,
    email: rt.String,
    password: rt.Union(rt.Undefined, rt.String),
    passwordConf: rt.Union(rt.Undefined, rt.String),
  }),
});

export const postUsers = (
  r: Pick<AppDeps, "config" | "log" | "io">
): SimpleHttpServerMiddleware => {
  return async (req, res, next) => {
    const log = tag(r.log, req, res);
    try {
      assertAuthdReq(req);
      const validation = PostUser.validate(req.body);
      if (!validation.success) {
        throw new E.BadRequest(
          `The body of your request does not appear to conform to the documented input for this ` +
            `endpoint. Please read the docs: https://docs.openfinance.io/system/v3/api.html.\n\n` +
            `Error: ${validation.key ? `${validation.key}: ` : ``}${validation.message}`
        );
      }
      const user = await createUser(validation.value.data, req.get("user-agent"), req.auth, {
        ...r,
        log,
      });
      res.status(201).send({ data: user });
    } catch (e) {
      next(e);
    }
  };
};

export const patchUsers = (r: Pick<AppDeps, "log">): SimpleHttpServerMiddleware => {
  return (req, res, next) => {
    next(new E.NotImplemented(`${req.method} ${req.path} is not yet implemented`));
  };
};

export const postLoginEmails = (r: Pick<AppDeps, "log">): SimpleHttpServerMiddleware => {
  return (req, res, next) => {
    next(new E.NotImplemented(`${req.method} ${req.path} is not yet implemented`));
  };
};

export const deleteLoginEmails = (r: Pick<AppDeps, "log">): SimpleHttpServerMiddleware => {
  return (req, res, next) => {
    next(new E.NotImplemented(`${req.method} ${req.path} is not yet implemented`));
  };
};

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
 * Create a user and return a session for the user
 *
 * TODO: Break into smaller pieces for better testing
 */
export const createUser = async (
  postUser: Auth.Api.PostUser,
  userAgent: string | undefined,
  auth: Auth.ReqInfo,
  r: Pick<AppDeps, "config" | "log" | "io" | "accountsLib">
): Promise<Auth.Api.Authn.Session> => {
  r.log.debug(`Called createUser`);

  const obstructions: Array<E.ObstructionInterface> = [];

  // Check to see if payload looks good
  if (!postUser.email.match(new RegExp(emailPattern, "i"))) {
    obstructions.push({
      code: "Invalid Email",
      text: "The email address you've provided doesn't appear valid according to our standards.",
      params: {
        input: postUser.email,
        regex: emailPattern,
      },
    });
  }

  if (postUser.password) {
    // Strength
    let m: Array<string> | null = null;
    if (postUser.password.length < 8) {
      obstructions.push({
        code: "Password",
        text: "Must be at least 8 characters long",
      });
    }
    if (postUser.password.length > 72) {
      obstructions.push({
        code: "Password",
        text: "Cannot exceed 72 characters",
      });
    }
    m = postUser.password.match(/([a-z])/);
    if (m === null || m.length < 2) {
      obstructions.push({
        code: "Password",
        text: "Must have at least 2 lower-case letters",
      });
    }
    m = postUser.password.match(/([A-Z])/);
    if (m === null || m.length < 2) {
      obstructions.push({
        code: "Password",
        text: "Must have at least 2 upper-case letters",
      });
    }
    m = postUser.password.match(/([0-9])/);
    if (m === null || m.length < 2) {
      obstructions.push({
        code: "Password",
        text: "Must have at least 2 numbers",
      });
    }
    m = postUser.password.match(/([^a-zA-Z0-9])/);
    if (m === null || m.length < 2) {
      obstructions.push({
        code: "Password",
        text: "Must have at least 2 non alpha-numeric characters",
      });
    }

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
    passwordHash = await bcrypt.hash(postUser.password, 10);
  }

  // Insert user into database
  const user = await r.io.insertUser(
    {
      id: uuid.v5(postUser.email, OPENFINANCE_NS),
      name: postUser.name,
      passwordHash,
      banned: 0,
      loginMethod: postUser.password ? Auth.LoginMethods.Password : Auth.LoginMethods.Email,
      "2fa": 0,
      createdMs: Date.now(),
    },
    auth,
    r.log
  );

  // Insert login email
  await r.io.insertLoginEmail(user.id, postUser.email, auth, r.log);

  // Send verification email
  await r.accountsLib.sendVerificationCodeEmail(
    postUser.email,
    { ...r, log }
  );

  // Generate and return session
  return await r.io.generateSession(user.id, userAgent, auth, r.log);
};
