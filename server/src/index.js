require('dotenv/config');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { verify } = require('jsonwebtoken');
const { hash, compare } = require('bcryptjs');
const {fakeDB} = require('./fakeDB.js')
const { createAccessToken, createRefreshToken, sendAccessToken, sendRefreshToken } = require('./token.js');
const { isAuth } = require('./isAuth.js');
const server = express();

//use express middleware for easier cookie handling
server.use(cookieParser());
server.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true,
  }),
);
server.use(express.json()) // to support json encoded bodies
server.use(express.urlencoded({ extended: true })); // support url encoded bodies

//register a user
server.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {

    const user = fakeDB.find( user => user.email == email);
    if(user) throw new Error('User already exist');

    const hashedPassword = await hash(password, 10);

    fakeDB.push({
      id: fakeDB.length,
      email,
      password: hashedPassword
    })

    res.send({ message: 'User created '});
    console.log(fakeDB);

  } catch (e) {

    res.send({
      error: `${e.message}`
    })

  }
});

// login
server.post('/login', async (req, res) => {

  const { email, password } = req.body;
  try {

    const user = fakeDB.find( user => user.email == email );
    if(!user) throw new Error("user does not exist");

    const valid = await compare(password, user.password)
    if(!valid) throw new Error("Password not correct");

    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);

    user.refreshtoken = refreshtoken;
    console.log(fakeDB);

    sendRefreshToken(res, refreshtoken);
    sendAccessToken(req, res, accesstoken);

  } catch (e) {
    res.send({
      error: `${e.message}`
    })
  }
});

//logout

server.post('/logout', (req, res) => {
  res.clearCookie('refreshtoken', { path: '/refresh_token' });
  return res.send({
    message: 'Logged out'
  })
});

// protected

server.post('/protected', async (req, res) => {
  try {
    const userId = isAuth(req);
    if(userId !== null){
      res.send({
        data: "this is protected data"
      })
    }
  } catch (e) {
    res.send({
      error: `${e.message}`
    })
  }
});

// get new access token

server.post('/refresh_token', (req, res) => {
  const token = req.cookies.refreshtoken;

  if(!token) return res.send({ accesstoken: ' ' });

  let payload = null;
  try {
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (e) {
    return res.send({ accesstoken: ' ' });
  }

  const user = fakeDB.find(user => user.id === payload.userId);
  if(!user) return res.send({ accesstoken: ' ' });

  if(user.refreshtoken !== token) {
    return res.send({ accesstoken: ' ' });
  }

  const accesstoken = createAccessToken(user.id);
  const refreshtoken = createRefreshToken(user.id);

  user.refreshtoken = refreshtoken;
  sendRefreshToken(res, refreshtoken);

  return res.send({ accesstoken });
});

server.listen(process.env.PORT, () => console.log(`Server listening on port ${process.env.PORT}`));
