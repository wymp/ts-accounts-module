import { SimpleHttpServerMiddleware } from "ts-simple-interfaces";
import * as E from "@openfinanceio/http-errors";
import { AppDeps } from "../../Types";

export const postClients = (r: Pick<AppDeps, "log">): SimpleHttpServerMiddleware => {
  return (req, res, next) => {
    next(new E.NotImplemented(`${req.method} ${req.path} is not yet implemented`));
  };
};

export const patchClients = (r: Pick<AppDeps, "log">): SimpleHttpServerMiddleware => {
  return (req, res, next) => {
    next(new E.NotImplemented(`${req.method} ${req.path} is not yet implemented`));
  };
};

export const postAccessRestrictions = (r: Pick<AppDeps, "log">): SimpleHttpServerMiddleware => {
  return (req, res, next) => {
    next(new E.NotImplemented(`${req.method} ${req.path} is not yet implemented`));
  };
};

export const deleteAccessRestrictions = (r: Pick<AppDeps, "log">): SimpleHttpServerMiddleware => {
  return (req, res, next) => {
    next(new E.NotImplemented(`${req.method} ${req.path} is not yet implemented`));
  };
};
