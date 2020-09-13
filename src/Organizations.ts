import { SimpleLoggerInterface, SimpleHttpServerMiddleware } from "ts-simple-interfaces";
import * as E from "@openfinanceio/http-errors";

export const postOrganizations = (r: { log: SimpleLoggerInterface }): SimpleHttpServerMiddleware => {
  return (req, res, next) => {
    next(new E.NotImplemented(`${req.method} ${req.path} is not yet implemented`));
  };
};
