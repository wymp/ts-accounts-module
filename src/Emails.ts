import * as rt from "runtypes";
import { SimpleHttpServerMiddleware } from "ts-simple-interfaces";
import { Auth } from "@openfinanceio/data-model-specification";
import * as E from "@openfinanceio/http-errors";
import { Http } from "@openfinanceio/service-lib";
import { tag } from "../../Lib";
import { AppDeps } from "../../Types";

const assertAuthdReq: typeof Http["assertAuthdReq"] = Http.assertAuthdReq;

export const postVerifyEmail = (r: Pick<AppDeps, "log" | "io">): SimpleHttpServerMiddleware => {
  return async (req, res, next) => {
    const log = tag(r.log, req, res);
    try {
      assertAuthdReq(req);
      const validation = rt
        .Record({
          data: rt.Record({ type: rt.Literal("codes"), code: rt.String }),
        })
        .validate(req.body);
      if (!validation.success) {
        throw new E.BadRequest(
          `The body of your request does not appear to conform to the documented input for this ` +
            `endpoint. Please read the docs: https://docs.openfinance.io/system/v3/api.html.\n\n` +
            `Error: ${validation.key ? `${validation.key}: ` : ``}${validation.message}`
        );
      }
      await verifyEmail(validation.value.data.code, req.auth, { ...r, log });
      res.status(200).send({ data: null });
    } catch (e) {
      next(e);
    }
  };
};

const ResendVerificationPayload = rt.Record({
  data: rt.Union(
    rt.Record({
      type: rt.Literal("codes"),
      code: rt.String,
    }),
    rt.Record({
      type: rt.Literal("emails"),
      email: rt.String,
    })
  ),
});

export const postResendVerification = (
  r: Pick<AppDeps, "log" | "io">
): SimpleHttpServerMiddleware => {
  return async (req, res, next) => {
    const log = tag(r.log, req, res);
    try {
      assertAuthdReq(req);

      const validation = ResendVerificationPayload.validate(req.body);

      if (!validation.success) {
        throw new E.BadRequest(
          `The body of your request does not appear to conform to the documented input for this ` +
            `endpoint. Please read the docs: https://docs.openfinance.io/system/v3/api.html.\n\n` +
            `Error: ${validation.key ? `${validation.key}: ` : ``}${validation.message}`
        );
      }

      log.info(`Passed payload validation. Executing functionality.`);
      await resendVerification(validation.value.data, req.auth, { ...r, log });

      res.status(200).send({ data: null });
    } catch (e) {
      next(e);
    }
  };
};

/**
 * Verify email address using passed in code
 */
export const verifyEmail = async (
  code: string,
  auth: Auth.ReqInfo,
  r: Pick<AppDeps, "io" | "log">
): Promise<void> => {
  r.log.info(`Verifying email using code ${code}`);
  const verification = await r.io.consumeVerificationCode(code, null, r.log);
  r.log.info(`Code successfully consumed`);
  await r.io.markEmailVerified(verification.email, auth, r.log);
  r.log.info(`Email marked verified`);
};

/**
 * Resend email verification code
 */
export const resendVerification = async (
  payload: rt.Static<typeof ResendVerificationPayload>["data"],
  auth: Auth.ReqInfo,
  r: Pick<AppDeps, "log" | "io">
): Promise<void> => {
  let email: string;
  // If they passed a code, try to find it and validate it
  if (payload.type === "codes") {
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
    if (!auth.u) {
      throw new E.BadRequest(
        `You must have an active session to use this endpoint, or submit a valid ` +
          `prior verification code as { data: { code: string; }  } in the request body.`,
        `LOGIN-REQUIRED`
      );
    }

    // If we didn't find a user or it's not the right user, throw
    const user = await r.io.getUserByEmail(payload.email, r.log);
    if (!user || user.id !== auth.u.id) {
      throw new E.BadRequest(
        `This email is not associated with your account`,
        `UNREGISTERED-EMAIL`
      );
    }

    // If the email is already verified, throw
    if (user.verified === 1) {
      throw new E.BadRequest(`This email has already been verified`, `ALREADY-VERIFIED`);
    }

    email = payload.email;
  }

  r.log.info(`Resending verification email`);
  await r.io.sendVerificationCodeEmail(
    email,
    "verification",
    null,
    Date.now() + 1000 * 60 * 20,
    auth,
    r.log
  );
};
