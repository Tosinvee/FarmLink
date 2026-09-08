/* eslint-disable prettier/prettier */
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { Transporter } from 'nodemailer';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private readonly transporter: Transporter;

  constructor(private readonly configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.getOrThrow<string>('MAIL_HOST'),
      port: 465,
      secure: true,
      auth: {
        user: this.configService.getOrThrow<string>('SMTP_USERNAME'),
        pass: this.configService.getOrThrow<string>('SMTP_PASSWORD'),
      },
    });
  }

  async sendVerificationCode(to: string, name: string, code: string) {
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;">
        <h2 style="color: #2f7d32;">FarmLink</h2>
        <p>Hi ${name},</p>
        <p>Your email verification code is:</p>
        <p style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #2f7d32;">${code}</p>
        <p>This code expires in a few minutes. Use it to complete your registration.</p>
      </div>`;

    try {
      await this.transporter.sendMail({
        from: this.configService.getOrThrow<string>('SMTP_USERNAME'),
        to,
        subject: 'FarmLink - Verify your email',
        html,
      });
    } catch (err) {
      this.logger.error(`Failed to send email to ${to}: ${err.message}`);
      throw err;
    }
  }
}