import * as bcrypt from "bcrypt";
import * as rt from "runtypes";
import { SimpleHttpServerMiddleware } from "ts-simple-interfaces";
import { Auth } from "@openfinanceio/data-model-specification";
import * as E from "@openfinanceio/http-errors";
import { Http } from "@openfinanceio/service-lib";
import { tag } from "../../Lib";
import { AppDeps, emailPattern } from "../../Types";

const assertAuthdReq: typeof Http["assertAuthdReq"] = Http.assertAuthdReq;

/**
 *
 *
 *
 * Handler
 *
 *
 *
 */

const AuthnEmail = rt.Record({
  idType: rt.Literal("email"),
  idValue: rt.String,
  state: rt.String,
});
const AuthnCode = rt.Record({
  idType: rt.Literal("code"),
  idValue: rt.String,
  state: rt.String,
});
const AuthnPassword = rt.Record({
  idType: rt.Literal("email"),
  idValue: rt.String,
  state: rt.String,
  secret: rt.String,
});
/*
const AuthnTotp = rt.Record({
  idType: rt.Literal("code"),
  idValue: rt.String,
  state: rt.String,
  secret: rt.String,
});
 */

const validateEmail = (email: string) => {
  if (!email.match(new RegExp(emailPattern, "i"))) {
    const e = new E.BadRequest("Invalid authentication payload");
    e.obstructions.push({
      code: "Invalid Email",
      text: "The email address you've provided doesn't appear valid according to our standards.",
      params: {
        input: email,
        regex: emailPattern,
      },
    });
    throw e;
  }
};

export const postAuthn = (
  r: Pick<AppDeps, "io" | "log" | "config" | "cache">
): SimpleHttpServerMiddleware => {
  return async (req, res, next) => {
    const log = tag(r.log, req, res);
    try {
      assertAuthdReq(req);
      const baseErr =
        `The body of your request does not appear to conform to the documented ` +
        `input for this endpoint. Please read the docs: ` +
        `https://docs.openfinance.io/system/v3/api.html.\n\n`;

      switch (req.params.type as Auth.Api.Authn.Types) {
        // EMAIL LOGIN
        case Auth.Api.Authn.Types.Email: {
          log.info(`Initiating email authn`);

          const val = AuthnEmail.validate(req.body);
          if (!val.success) {
            throw new E.BadRequest(
              baseErr + `Error: ${val.key ? `${val.key}: ` : ``}${val.message}`
            );
          }
          const payload = val.value;
          validateEmail(payload.idValue);

          await sendLoginEmail(payload.idValue, payload.state, req.auth, { ...r, log });
          res.status(200).send({ data: null });
          return;
        }

        // PASSWORD LOGIN
        case Auth.Api.Authn.Types.Password: {
          log.info(`Initiating Authn password step`);
          const val = AuthnPassword.validate(req.body);
          if (!val.success) {
            throw new E.BadRequest(
              baseErr + `Error: ${val.key ? `${val.key}: ` : ``}${val.message}`
            );
          }
          const payload = val.value;

          const response: Auth.Api.Authn.Response = await processPasswordStep(
            payload.idValue,
            payload.secret,
            payload.state,
            req.get("user-agent"),
            req.auth,
            { ...r, log }
          );

          res.status(200).send(response);
          return;
        }

        // CODE STEP
        case Auth.Api.Authn.Types.Code: {
          log.info(`Initiating Authn code step`);
          const val = AuthnCode.validate(req.body);
          if (!val.success) {
            throw new E.BadRequest(
              baseErr + `Error: ${val.key ? `${val.key}: ` : ``}${val.message}`
            );
          }
          const payload = val.value;

          const response: Auth.Api.Authn.Response = await processCodeStep(
            payload.idValue,
            payload.state,
            req.get("user-agent"),
            req.auth,
            { ...r, log }
          );

          res.status(200).send(response);
          return;
        }

        // TOTP STEP
        case Auth.Api.Authn.Types.Totp: {
          log.info(`Initiating Authn TOTP step`);
          throw new E.NotImplemented(`TOTP authentication is not yet implemented`);
          /*
          const val = AuthnTotp.validate(req.body);
          if (!val.success) {
            throw new E.BadRequest(
              baseErr + `Error: ${val.key ? `${val.key}: ` : ``}${val.message}`
            );
          }
           */
        }
      }

      // If we fell through, it's a bad request
      throw new E.BadRequest(
        `Unknown authentication type ${req.params.type}. Please read the docs.`
      );
    } catch (e) {
      next(e);
    }
  };
};

/**
 *
 *
 *
 * Functions
 *
 *
 *
 */
const sendLoginEmail = async (
  email: string,
  state: string,
  auth: Auth.ReqInfo,
  r: Pick<AppDeps, "io" | "log" | "config">
): Promise<void> => {
  r.log.debug(`Getting user by email`);
  const user = await r.io.getUserByEmail(email, r.log);

  // If we didn't find a user for this email, throw NotFound
  if (!user) {
    throw new E.NotFound(
      `Your email was not found on our platform. Please try registering an account.`
    );
  }

  await r.io.sendVerificationCodeEmail(
    user.email,
    "login",
    state,
    Date.now() + 1000 * 60 * r.config.expires.loginCodeMin,
    auth,
    r.log
  );
};

const processCodeStep = async (
  code: string,
  userGeneratedToken: string,
  userAgent: string | undefined,
  auth: Auth.ReqInfo,
  r: Pick<AppDeps, "io" | "log" | "config">
): Promise<Auth.Api.Authn.Response> => {
  const verification = await r.io.consumeVerificationCode(code, userGeneratedToken, r.log);

  const user = await r.io.getUserByEmail(verification.email, r.log, true);

  // If the user has 2fa enabled, generate a new code and send it back for the TOTP step
  if (user["2fa"] === 1) {
    r.log.info(`User has 2fa enabled. Returning TOTP step.`);
    const newVerification = await r.io.generateVerificationCode(
      "login",
      verification.email,
      userGeneratedToken,
      Date.now() + 1000 * 60 * r.config.expires.loginCodeMin,
      auth,
      r.log
    );
    return {
      t: "step",
      step: Auth.Api.Authn.Types.Totp,
      code: newVerification.code.toString("hex"),
      state: userGeneratedToken!,
    };
  }

  // Otherwise, generate and return session
  return await r.io.generateSession(user.id, userAgent, auth, r.log);
};

const processPasswordStep = async (
  email: string,
  password: string,
  userGeneratedToken: string,
  userAgent: string | undefined,
  auth: Auth.ReqInfo,
  r: Pick<AppDeps, "io" | "log" | "config" | "cache">
): Promise<Auth.Api.Authn.Response> => {
  const user = await r.io.getUserByEmail(email, r.log, true);
  const success = await compareSecret(password, user.passwordHash, r);
  if (!success) {
    throw new E.Unauthorized(`The password you've supplied is not correct.`);
  }

  // If the user has 2fa enabled, generate a new code and send it back for the TOTP step
  if (user["2fa"] === 1) {
    r.log.info(`User has 2fa enabled. Returning TOTP step.`);
    const newVerification = await r.io.generateVerificationCode(
      "login",
      email,
      userGeneratedToken,
      Date.now() + 1000 * 60 * r.config.expires.loginCodeMin,
      auth,
      r.log
    );
    return {
      t: "step",
      step: Auth.Api.Authn.Types.Totp,
      code: newVerification.code.toString("hex"),
      state: userGeneratedToken!,
    };
  }

  // Otherwise, generate and return session
  return await r.io.generateSession(user.id, userAgent, auth, r.log);
};

/**
 * Authenticate the passed in credentials against what's in the database
 */
export const compareSecret = async (
  secret: string | null,
  secretHash: string | null,
  r: Pick<AppDeps, "log" | "cache">
): Promise<boolean> => {
  const key = `${secret}:${secretHash}`;
  const authenticated = await r.cache.get<boolean>(
    key,
    async () => {
      if (!secret || !secretHash) {
        return false;
      }
      try {
        return await bcrypt.compare(secret, secretHash);
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
