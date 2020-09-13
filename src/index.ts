import { SimpleHttpServerMiddleware } from "ts-simple-interfaces";
import * as E from "@openfinanceio/http-errors";
import { Http } from "@openfinanceio/service-lib";
import { AppDeps } from "../../Types";
import * as Orgs from "./Organizations";
import * as Clients from "./Clients";
import * as Users from "./Users";
import * as Authn from "./Authn";
import * as Emails from "./Emails";

/**
 * This module _assumes_ that both CORS and Gateway functionality have already been run. It does
 * not necessarily _require_ that, but because it utilizes the "auth" property of the request to
 * manage permissioning, it will produce errors if that property has not been applied.
 */

const AcceptableContentTypes = ["application/json"];
const JsonBodyParser = Http.BodyParsers.json({
  type: AcceptableContentTypes,
});
const parseBody: SimpleHttpServerMiddleware = (req, res, next) => {
  const contentType = req.get("content-type");
  if (!contentType) {
    next(
      new E.UnsupportedMediaType(
        "Your request must specify a 'Content-Type' header, which must be one of the following: " +
          AcceptableContentTypes.join(`, `)
      )
    );
    return;
  }
  if (!AcceptableContentTypes.includes(contentType)) {
    next(
      new E.UnsupportedMediaType(
        `Your request must have a content type of one of the following: ${AcceptableContentTypes.join(
          `, `
        )}. You passed ${contentType}.`
      )
    );
    return;
  }
  return JsonBodyParser(req, res, next);
};

export const register = (
  r: Pick<AppDeps, "log" | "config" | "http" | "io" | "audit" | "sendgrid" | "cache">
) => {
  r.log.info(`Registering Accounts Module in ${r.config.envName}`);

  // Register endpoints

  // Note that we have to add in some middleware here that's not general across all functionality
  // in this service, so we're doing it per-endpoint.

  // Organizations
  r.log.notice(`Handling POST /accounts/v3/organizations`);
  r.http.post(`/accounts/v3/organizations`, [parseBody, Orgs.postOrganizations(r)]);

  // Clients
  r.log.notice(`Handling POST /accounts/v3/organizations/:id/clients`);
  r.http.post(`/accounts/v3/organizations/:id/clients`, [parseBody, Clients.postClients(r)]);
  r.log.notice(`Handling PATCH /accounts/v3/clients/:id`);
  r.http.patch(`/accounts/v3/clients/:id`, [parseBody, Clients.patchClients(r)]);
  r.log.notice(`Handling POST /accounts/v3/clients/:id/access-restrictions`);
  r.http.post(`/accounts/v3/clients/:id/access-restrictions`, [
    parseBody,
    Clients.postAccessRestrictions(r),
  ]);
  r.log.notice(`Handling DELETE /accounts/v3/clients/:id/access-restrictions`);
  r.http.delete(`/accounts/v3/clients/:id/access-restrictions`, [
    parseBody,
    Clients.deleteAccessRestrictions(r),
  ]);

  // Users
  r.log.notice(`Handling POST /accounts/v3/users`);
  r.http.post(`/accounts/v3/users`, [parseBody, Users.postUsers(r)]);
  r.log.notice(`Handling PATCH /accounts/v3/users/:id`);
  r.http.patch(`/accounts/v3/users/:id`, [parseBody, Users.patchUsers(r)]);
  r.log.notice(`Handling POST /accounts/v3/users/:id/login-emails`);
  r.http.post(`/accounts/v3/users/:id/login-emails`, [parseBody, Users.postLoginEmails(r)]);
  r.log.notice(`Handling DELETE /accounts/v3/users/:id/login-emails`);
  r.http.delete(`/accounts/v3/users/:id/login-emails`, [parseBody, Users.deleteLoginEmails(r)]);

  // Login Emails
  r.log.notice(`Handling POST /accounts/v3/emails/verify`);
  r.http.post(`/accounts/v3/emails/verify`, [parseBody, Emails.postVerifyEmail(r)]);
  r.log.notice(`Handling POST /accounts/v3/emails/resend-verification`);
  r.http.post(`/accounts/v3/emails/resend-verification`, [
    parseBody,
    Emails.postResendVerification(r),
  ]);

  // Authn (Sessions)
  r.log.notice(`Handling POST /accounts/v3/authn/:type`);
  r.http.post(`/accounts/v3/authn/:type`, [parseBody, Authn.postAuthn(r)]);

  // Fallthrough
  r.log.notice(`Handling fallthrough requests for accounts api`);
  r.http.all([`/accounts/v3`, `/accounts/v3/*`], (req, res, next) => {
    next(new E.BadRequest(`Sorry, the ${req.method} ${req.path} endpoint doesn't exist`));
  });
};
