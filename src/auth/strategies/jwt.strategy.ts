/* eslint-disable prettier/prettier */
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService:ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('jwt.secret') || "ilovejesus"
    });
    console.log('JWT secret:', configService.get<string>('jwt.secret'));
 
  }

  async validate(payload: any) {
    console.log('JWT payload:', payload);
    return { id: payload.sub, email: payload.email, role: payload.role };
  }
}
