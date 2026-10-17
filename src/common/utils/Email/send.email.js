import nodemailer from "nodemailer";
import { APP_EMAIL, APP_PASSWORD } from "../../../config.js";
import { BadException } from "../../exceptions/error.exception.js";


export const userEmailKey =  ({email, subject})=>{
  return `User::${email}::${subject}::OTP`
}
export const userEmailTrialsKey =  ({email, subject})=>{
  return `${userEmailKey({email , subject})}::Trials`
}

// Create a transporter using SMTP
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: APP_EMAIL,
    pass: APP_PASSWORD,
  },
});

export const sendEmail = async ({
  to, 
  subject, 
  cc,
  bcc,
  text, 
  html, 
  attachments = [],
} = {}) => {
  try {
    if (!to?.length && !cc?.length && !bcc?.length) {
      throw BadException("invalid reciepients");
    }
    if (!html?.length && !text?.length && !attachments?.length) {
      throw BadException("invalid email payload");
    }

    const info = await transporter.sendMail({
      from: ` "Bavly Maged" <${APP_EMAIL}>`, 
      to, 
      cc,
      bcc,
      subject, 
      text, 
      html, 
      attachments
    });

    console.log("Message sent: %s", info.messageId);
    
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
  } catch (err) {
    console.error("Error while sending mail:", err);
  }
};
