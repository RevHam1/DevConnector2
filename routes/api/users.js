const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const keys = require("../../config/keys");
const passport = require("passport");

//Load Input Validation
const validateRegisterInput = require("../../validation/register");
const validateLoginInput = require("../../validation/login");

//Load User model
const User = require("../../models/User");

// @route   GET api/users/test = to /test below
// @desc    what it does Tests users route
// @access  Public
router.get("/test", (req, res) => {
  res.json({ msg: "Users Works" });
});

// @route   POST api/users/register = to /test below
// @desc    what it does Register a user
// @access  Public
router.post("/register", (req, res) => {
  const { errors, isValid } = validateRegisterInput(req.body);

  //Check Validation; 1st line of validation, then email validation below
  if (!isValid) {
    return res.status(400).json(errors);
  }

  User.findOne({ email: req.body.email }).then(user => {
    // 1. Before registering user: Search if email already exists
    if (user) {
      errors.email = "Email already exists"; //adds email key to errors obj with value "Email already exists"
      return res.status(400).json(errors);
    } else {
      // 3. For Email: Pass email to gravatar to set image
      const avatar = gravatar.url(req.body.email, {
        s: "200", // Size
        r: "pg", // Rating
        d: "mm" // Default if there is no avatar
      });
      // 2. Create new user
      const newUser = new User({
        name: req.body.name,
        email: req.body.email,
        avatar, //Can just put avatar since both are the same avatar: avatar
        password: req.body.password
      });
      // 4. For Password: Generate salt & hash password through bcrypt, then save user
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;
          newUser
            .save()
            .then(user => res.json(user))
            .catch(err => console.log(err));
        });
      });
    }
  });
});

// @route   GET api/users/login
// @desc    Login User / Returning JWT Token
// @access  Public
router.post("/login", (req, res) => {
  const { errors, isValid } = validateLoginInput(req.body);

  //Check Validation
  if (!isValid) {
    return res.status(400).json(errors);
  }

  //-Put email & password into variables
  const email = req.body.email;
  const password = req.body.password;

  //1. Verifing user's email & password
  User.findOne({ email }).then(user => {
    //1a. Verify user through email
    if (!user) {
      errors.email = "User not found"; //adds email key to errors obj with value "User not found"
      return res.status(404).json(errors);
    }

    //1b. Verify user password
    bcrypt.compare(password, user.password).then(isMatch => {
      if (isMatch) {
        //-Assign payload below to a varible object
        const payload = { id: user.id, name: user.name, avatar: user.avatar }; // Create JWT Payload

        //2. Create a Token with jsonwebtoken since email & password is verified
        jwt.sign(
          payload, //2a payload
          keys.secretOrKey, //2b Screct stored in the config/keys file
          { expiresIn: 3600 }, //2c Expiration, this is An hour

          //3a Send token through Arrow function
          (err, token) => {
            res.json({
              success: true,
              token: "Bearer " + token //3b Format token for the header
            });
          }
        );
      } else {
        errors.password = "Password is not correct";
        return res.status(400).json(errors);
      }
    });
  });
});

// @route   GET api/users/current
// @desc    Return current user
// @access  Private
router.get(
  "/current",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({
      id: req.user.id,
      name: req.user.name,
      email: req.user.email
    });
  }
);

module.exports = router;
