const router = require("express").Router();
const Users = require("../users/users-model");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");

const bcrypt = require("bcrypt");
const { BCRYPT_ROUNDS } = require("../secrets"); // use this secret!
const buildToken = require("./buildToken");

router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;
  const rounds = BCRYPT_ROUNDS;
  const hash = bcrypt.hashSync(user.password, rounds);

  user.password = hash;

  Users.add(user)
    .then(([newUser]) => {
      res.status(201).json(newUser);
    })
    .catch(next);
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  let { username, password } = req.body;

  const { password: hash } = req.foundUser;
  if (bcrypt.compareSync(password, hash)) {
    const token = buildToken(req.foundUser);
    res.status(200).json({ message: `${username} is back!`, token: token });
  }
});

module.exports = router;
