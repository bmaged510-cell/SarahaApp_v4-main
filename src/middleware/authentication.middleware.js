import { ForbiddenException, UnAuthorizedException } from "../common/exceptions/error.exception.js";
import { decodeToken } from "../common/security/token.security.js";
import { TokenTypeEnum } from "./../common/enum/index.js";
export const authentication = (tokenType = TokenTypeEnum.ACCESS) => {
  return async (req, res, next) => {
    const { authorization } = req.headers;
    if (!authorization) {
      throw UnAuthorizedException("Unauthorized account ");
    }
  
    const [key, token] = authorization.split(" ") ?? [];
    console.log({ key, token });
    switch (key) {
      
      case "Bearer":
        const { user, payload } = await decodeToken({authorization:token,tokenType});
        req.user = user
        req.payload = payload
        break;
      default:
        next(new Error("invalid authentication schema" ,{cause:{status:400}}))
        break;
    }
    next();
  };
};

export const authorization = (accessRoles) => {
  return async (req, res, next) => {
    if (!accessRoles.includes(req.user.role)) {
      throw ForbiddenException("Forbbiden account ");
    }
    next();
  };
};
