const { findBy } = require("../users/users-model");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets"); // use this secret!

const nErr = (status, message) => {
  return { status: status, message: message };
}; //!experiment

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        next({ status: 401, message: "Token invalid" });
      } else {
        req.decodedJwt = decoded;
        next();
      }
    });
  } else {
    next(nErr(401, "Token required"));
  }
};

const only = (role_name) => (req, _res, next) => {
  req.decodedJwt.role_name === role_name
    ? next()
    : next(nErr(403, "This is not for you"));
};

const checkUsernameExists = (req, _res, next) => {
  const username = req.body.username;
  findBy({ username })
    .then(([user]) => {
      if (user) {
        req.foundUser = user;
        next();
      } else {
        next(nErr(401, "Invalid credentials"));
      }
    })
    .catch(next);
};

const validateRoleName = (req, _res, next) => {
  let role = req.body.role_name?.trim();
  if (!role) {
    role = "student";
  } else if (role.length > 32) {
    next(nErr(422, "Role name can not be longer than 32 chars"));
  } else if (role === "admin") {
    return next(nErr(422, "Role name can not be admin"));
  }
  req.body.role_name = role;
  next();
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
