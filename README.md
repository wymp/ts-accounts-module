Accounts Module
=========================================================================

> :warning: **NOTE: This library is in active alpha development and is not yet ready for 
>  production.**

**The goal of this module is to provide a foundation for the creation of an enterprise-grade
accounts management system, including concepts of users, organizations, clients (api keys), and
login sessions.**

Module functionality depends on an Io abstraction interface so that you may store objects in
whatever way you wish. The module additionally provides a ready-made database schema and Io
implementation that should work out of the box.

It also depends on a Lib interface with an accompanying implementation that was constructed to allow
dependents to extend it (or façade it) to provide variations on its functionality. In the event that
extending or façading is insufficient, you may also choose to simply implement the interface from
scratch.

In the worst case scenario, I hope that this module at least serves as an example of how to put
together an enterprise-grade auth and session management system. You may feel free to just
copy/paste code directly from the library into your own work if it makes things easier for you.

Following is a more in-depth description of how the concepts comprising the system and an example
of how to make it work.

## TL;DR

1. `npm install @wymp/accounts-module`
2. Hook up endpoint handlers for endpoints such as the following:
  * `POST /organizations` - Create new organizations
  * `POST /organizations/:id/clients` - Create new client for a given organization
  * `PATCH /clients/:id` - Update the given client
  * `POST /clients/:id/access-restrictions` - Add access restrictions for a client
  * `DELETE /clients/:id/access-restrictions` - Remove access restrictions for a client
  * `POST /users` - Create new user
  * `PATCH /users/:id` - Update the given user
  * `POST /users/:id/login-emails` - Add one or more login emails
  * `DELETE /users/:id/login-emails` - Delete on or more login emails
  * `POST /emails/verify` - Verify a login email using a verification code received via email
  * `POST /emails/resend-verification` - Resend a verification code to an email
  * `POST /authn/:type` - Get a new login session for a user
3. Do whatever request validation and verification you wish to do in your handlers. **(NOTE: This
   library additionally provides handler logic, which you may choose to use if you wish. If you
   do not, it is encouraged that you study the logic and be sure that you cover all of the
   necessary validations for enterprise-grade security.)**
4. Hook your handlers up to the correct library functions.

## Concepts

....

## Notes to Self

* Can we pass in type definitions for the primary objects (User, Session, Organization, Client,
  etc.), rather than enforcing concrete types that are defined by the library? The library could
  then define an Io implementation according to its own concrete types, but be adaptable to other
  definitions of users, etc.
* **The current implementation doesn't type-check on dependencies to for the accounts lib.** Need
  to jump through a few more hoops for that to work.
