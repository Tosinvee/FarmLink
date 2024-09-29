/* eslint-disable prettier/prettier */
import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { ConfigModule } from '@nestjs/config';
import mailConfig from './mail.config';
 
@Module({
  providers: [MailService],
  exports:[MailService],
  imports:[ConfigModule.forFeature(mailConfig)]
})
export class MailModule {}
