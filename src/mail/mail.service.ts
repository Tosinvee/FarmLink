/* eslint-disable prettier/prettier */
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer'
import { MailOptions } from './interface/mailOptions';

@Injectable()
export class MailService {
    private transporter:nodemailer.Transporter 
    constructor(private readonly configService:ConfigService){
        const mailConfig = this.configService.get('mail')
        this.transporter = nodemailer.createTransport({
          service:mailConfig.service,
          auth:{
            user:mailConfig.user,
            pass: mailConfig.pass,
          }  
        })
    }
async sendMail(mailOptions:MailOptions){
    try{
        await this.transporter.sendMail(mailOptions)
        return 'Email sent sucessfully'
    }catch(error){
        console.error(error)
        return 'Error sending the email'
    }
}

async format(otp: string, content: string) {
    return `<div
      style="
        font-family: 'Raleway', sans-serif;
        max-width: 400px;
        margin: 0 auto;
        padding: 20px;
        background-color: #f4f4f4;
        border-radius: 8px;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      "
    >
      <h1 style="font-size: 24px; color: #333; margin-bottom: 10px">
        ${content}
      </h1>
      <p style="font-size: 16px; color: #666; margin-bottom: 20px">
        Kindly use this OTP for Verification.
      </p>
      <h1 style="font-size: 28px; color: #007bff; margin: 20px 0">
        ${otp}
      </h1>
      <p style="font-size: 16px; color: #666">It will expire in 30 minutes</p>
    </div>`;
  }

  generateOtp(max:number): string{
    return Math.floor(max + Math.random() * 900000).toString()
  }

  verifyOtpTime(createdAt: Date): boolean {
    const createdDate = new Date(createdAt);
    const currentTime = new Date();
    const differenceInMs = currentTime.getTime() - createdDate.getTime();
    const differenceInMin = differenceInMs / (1000 * 60);

    return differenceInMin < 30
  }
}

