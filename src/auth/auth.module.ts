/* eslint-disable prettier/prettier */
import { forwardRef, Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/user/user.entity';
import { UserModule } from 'src/user/user.module';
import { JwtModule } from '@nestjs/jwt'; 
import { MailModule } from 'src/mail/mail.module';
//import jwtConfig from './jwt.config';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { ConfigService } from '@nestjs/config';

@Module({
  imports:[TypeOrmModule.forFeature([User]),
  forwardRef(()=> UserModule),
  JwtModule.registerAsync({
    inject: [ConfigService],
    useFactory: (configService: ConfigService) => ({
      secret: configService.get<string>('jwt.secret') , 
      signOptions: { expiresIn: configService.get<string>('jwt.signOptions.expiresIn') }, 
    }),
  }),

  MailModule
],
  providers: [AuthService,JwtStrategy,LocalStrategy],
  controllers: [AuthController],
  exports: [AuthService, JwtStrategy],
  
})
export class AuthModule {}
