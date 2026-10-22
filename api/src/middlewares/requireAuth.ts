// Le middleware qui protège une route : il exige un jeton valide dans l'en-tête Authorization.
// Il se pose PAR ROUTE, avant validate(...) : router.post('/', requireAuth, validate(TeamSchema), handler).
// Hier au J0 : le pare-feu de Symfony (security.yaml) faisait ce travail pour vous.
import type { RequestHandler } from 'express';
import { HttpError } from '../errors.js';
import {verifyAccessToken} from "../auth/auth.service.js";

/**
 * TODO 4 (TD JWT, étape 3) :
 *   1. lire req.headers.authorization ; attendu : « Bearer <jeton> » (sinon → HttpError(401, 'Unauthorized'))
 *   2. verifyAccessToken(jeton) (qui lève lui-même 401 'Token expired' ou 'Invalid token')
 *   3. ranger le résultat dans res.locals.user (le handler le lira), puis next()
 * Les 401 portent toujours l'en-tête WWW-Authenticate: Bearer : errorHandler s'en charge.
 */
export const requireAuth: RequestHandler = (_req, _res, _next) => {

  // const match =/Bearer(\$+)/.exec(_req.header(.authorization ?? ''));
  //
  // if(!match)
  //
  if(!_req.headers.authorization || !/^Bearer [A-Za-z0-9._-]+$/.test(_req.headers.authorization))  {
    throw new HttpError(401, 'Unauthorized');
  }

  const authHeader = _req.headers.authorization;

  const token = authHeader.split(' ')[1];

  _res.locals.user = verifyAccessToken(token);
  _next();
};
