import { model } from "mongoose";
import { create, findOne } from "../../common/repository/db.repository.js";
import { UserModel } from "../../DB/model/user.model.js";
import {
  BadException,
  ConflictException,
  NotFoundException,
  TooManyRequestException,
} from "../../common/exceptions/index.js";
import {
  decryption,
  encryption,
  compare,
  hash,
  generateToken,
  createLoginCredentials,
  createRevoketoken,
  userBaseRevokeToken,
} from "../../common/security/index.js";
import jwt from "jsonwebtoken";
import {
  ACCESS_TOKEN_EXPIRESIN,
  REFRESH_TOKEN_EXPIRESIN,
  REFRESH_USER_TOKEN_SIGNATURE,
  WEB_CLIENT_IDS,
} from "../../config.js";
import { ProviderEnum, RoleEnum } from "../../common/enum/user.enum.js";
import { OAuth2Client } from "google-auth-library";
import { incrBy, keys, set, ttl,get , del, expire } from "../../common/services/cache.service.js";
import {
  sendEmail,
  userEmailKey,
  userEmailTrialsKey,
} from "../../common/utils/Email/send.email.js";
import { emailEvent } from "../../common/events/email.event.js";
import { EmailSubjectEnum } from "../../common/enum/email.enum.js";
import { createOtp } from "../../common/utils/otp.js";

const client = new OAuth2Client();
async function verifyGoogleAccount(idToken) {
  const ticket = await client.verifyIdToken({
    idToken,
    audience: WEB_CLIENT_IDS, // Specify the CLIENT_ID of the app that accesses the backend
  });
  const payload = ticket.getPayload();
  if (!payload.email_verified) {
    throw BadException("not verified email");
  }
  return payload;
}

export const signupWithGmail = async ({ idToken, issuer }) => {
 
  const { email, name, picture } = await verifyGoogleAccount(idToken);
  const existAccount = await findOne({
    model: UserModel,
    filter: { email },
  });
  if (existAccount) {
    if (existAccount.provider != ProviderEnum.GOOGLE) {
      throw ConflictException("invalid account provider");
    }
    return {
      status: 200,
      data: await createLoginCredentials({ user: existAccount, issuer }),
    };
  }
  const user = await create({
    model: UserModel,
    data: {
      email,
      username: name,
      image: picture,
      confirmEmail: new Date(),
      provider: ProviderEnum.GOOGLE,
    },
  });
  return {
    status: 201,
    data: await createLoginCredentials({ user: existAccount, issuer }),
  };
};

const sendEmailOtp = async ({ email, subject , expiresIn=120 , maxTrials=3 , blockIn=300}) => {
  const existOtp_ttl = await ttl({key: userEmailKey({ email, subject })})
  if(existOtp_ttl>0){
    throw ConflictException(`sorry we cannot create otp while the old one still valid, please try again after ${existOtp_ttl}`)
  }
  const oldTrials = await get({key:userEmailTrialsKey(email,subject)})
  if(oldTrials >=maxTrials){
    throw TooManyRequestException("Max otp trials has been reached")
  }
  const code = createOtp();
  await set({
    key: userEmailKey({ email, subject }),
    value: await hash({ plainText: code.toString() }), 
    ttl: expiresIn,
  });
  const currentTrials=await incrBy({key:userEmailTrialsKey(email,subject)})
 
  if(currentTrials == 3){
    await expire({key:userEmailTrialsKey(email,subject) , ttl:blockIn}) 
  }
  emailEvent.emit("sendEmail", {
    recipient: { to: email },
    subject: EmailSubjectEnum.CONFIRM_EMAIL,
    data: { code },
  });
};
export const signup = async (inputs) => {
  const { username, email, password, phone, age, role } = inputs;
  const existingUser = await findOne({
    filter: { email },
    options: { select: "email" },
    model: UserModel,
  });
  if (existingUser) {
    throw ConflictException("Email exist");
  }
  const user = await create({
    data: {
      username,
      email,
      password: await hash({ plainText: password }), 
      phone: await encryption(phone), 
      age,
      role,
    },
    model: UserModel,
  });
 await sendEmailOtp({email , subject:EmailSubjectEnum.CONFIRM_EMAIL})
  return user;
};

export const confirmEmail = async (inputs) => {
  const { otp, email } = inputs;
  const account = await findOne({
    filter: {
      email,
      provider: ProviderEnum.SYSTEM,
      confirmEmail: { $exists: false },
    },
    options: { select: "email" },
    model: UserModel,
  });
  if (!account) {
    throw NotFoundException("Invalid email or account already confirmed");
  }
  const hashOtp = await get({
    key: userEmailKey({ email, subject: EmailSubjectEnum.CONFIRM_EMAIL }),
  });
  if (!hashOtp || !(await compare(otp.toString(), hashOtp))) {
    
    throw BadException("Invalid OTP");
  }
  account.confirmEmail = new Date();
  await account.save();
  await del({
    key: await keys({prefix:userEmailKey({email,subject:EmailSubjectEnum.CONFIRM_EMAIL})}),
  }); 
  return;
};

export const resendConfirmEmail = async (inputs) => {
  const { email } = inputs;
  const account = await findOne({
    filter: {
      email,
      provider: ProviderEnum.SYSTEM,
      confirmEmail: { $exists: false },
    },
    options: { select: "email" },
    model: UserModel,
  });
  if (!account) {
    throw NotFoundException("Invalid email or account already confirmed");
  }
  await sendEmailOtp({email,subject:EmailSubjectEnum.CONFIRM_EMAIL})
  return;
};

export const requestForgotPasswordCode = async (inputs) => {
  const { email } = inputs;
  const account = await findOne({
    filter: {
      email,
      provider: ProviderEnum.SYSTEM,
      confirmEmail: { $exists: true },
    },
    options: { select: "email" },
    model: UserModel,
  });
  if (!account) {
    throw NotFoundException("Invalid email or account already confirmed");
  }
  await sendEmailOtp({email,subject:EmailSubjectEnum.FORGET_PASSWORD})
  return;
};
export const verifyForgotPasswordCode = async (inputs) => {
  const { otp, email } = inputs;
  const account = await findOne({
    filter: {
      email,
      provider: ProviderEnum.SYSTEM,
      confirmEmail: { $exists: true },
    },
    options: { select: "email" },
    model: UserModel,
  });
  if (!account) {
    throw NotFoundException("Invalid email or account already confirmed");
  }
  const hashOtp = await get({
    key: userEmailKey({ email, subject: EmailSubjectEnum.FORGET_PASSWORD }),
  });
  if (!hashOtp || !(await compare(otp.toString(), hashOtp))) {
  
    throw BadException("Invalid OTP");
  }
  return account;
};
export const resetForgotPassword = async (inputs) => {
  const { otp, email , password } = inputs;
  const account = await verifyForgotPasswordCode({otp , email})
  account.password = hash({plainText:password})
  account.changeCredentialsTime = new Date()
  await account.save()
  const result = await Promise.all([keys({prefix:userBaseRevokeToken({userId:account._id})}) , keys({prefix:userEmailKey({email,subject:EmailSubjectEnum.FORGET_PASSWORD})}) ])
  await del({
    key: [...result[0] , ...result[1]]
  });
  return;
};
export const login = async (inputs, issuer) => {
  const { email, password } = inputs;
  const existingUser = await findOne({
    filter: {
      email,
      provider: ProviderEnum.SYSTEM,
      confrimEmail: { $exists: true },
    },
    model: UserModel,
  });
  if (!existingUser) {
    throw NotFoundException("invalid login credentials"); 
  }
  const match = await compare(password, existingUser.password); 
  if (!match) {
    throw NotFoundException("invalid login credentials");
  }
  return await createLoginCredentials({ user: existingUser, issuer });
};
