const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { APP_SECRET, getUserId } = require('../utils');

function post(root, { url, description }, context, info) {
  const userId = getUserId(context);
  return context.db.mutation.createLink({
    data: {
      description,
      url,
      postedBy: { connect: { id: userId } },
    },
  }, info);
}

async function signup(parent, { email, name, password }, context, info) {
  const passwordHashed = await bcrypt.hash(password, 10);
  const user = await context.db.mutation.createUser({
    data: { email, name, password: passwordHashed },
  }, `{ id }`);
  const token = jwt.sign({ userId: user.id }, APP_SECRET);
  return {
    token,
    user,
  };
}

async function login(parent, { email, password }, context, info) {
  const user = await context.db.query.user({ where: { email } }, `{ id password }`);
  if (!user) {
    throw new Error('No such user found');
  }

  const isValid = await bcrypt.compare(password, user.password);
  if(!isValid) {
    throw new Error('Invalid Password');
  }

  const token = jwt.sign({ userId: user.id }, APP_SECRET);

  return {
    token,
    user,
  };
}

module.exports = {
  signup,
  login,
  post,
};
