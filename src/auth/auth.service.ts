/* eslint-disable prettier/prettier */
import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { RedisService } from '../redis/redis.service';
import { MailService } from '../mail/mail.service';
import { UserService } from '../user/user.service';
import { PrismaService } from '../prisma/prisma.service';
import { TokenPayload } from './interface/token.interface';
import { SignupDto } from './dto/signup.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';

const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const REFRESH_TTL_MS = REFRESH_TTL_SECONDS * 1000;

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly mailService: MailService,
  ) {}

  generateRefreshToken(): string {
    return crypto.randomBytes(64).toString('hex');
  }

  hashForRedis(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  async hashForDb(token: string): Promise<string> {
    return bcrypt.hash(token, 10);
  }

  generateCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }
  async signup(body: SignupDto) {
    const existingUser = await this.userService.findByEmail(body.email);
    if (existingUser) {
      throw new BadRequestException('User already exist');
    }

    const passwordHash = await this.userService.hashPassword(body.password);
    const code = this.generateCode();

    const signupData = {
      email: body.email,
      firstName: body.firstName,
      passwordHash,
      role: body.role ?? 'CONSUMER',
    };

    const ttl = Number(process.env.SIGNUP_TTL) || 600;

    await this.redisService.set(
      `signup:${code}`,
      JSON.stringify(signupData),
      ttl,
    );
    await this.redisService.set(`signup:email:${body.email}`, code, ttl);

    try {
      await this.mailService.sendVerificationCode(
        body.email,
        body.firstName,
        code,
      );
      return {
        success: true,
        message: 'Please check your email to complete registration',
      };
    } catch (e) {
      await this.redisService.del(`signup:${code}`);
      await this.redisService.del(`signup:email:${body.email}`);
      throw new InternalServerErrorException(
        `An error occurred sending email: ${e.message}`,
      );
    }
  }

  async verifyEmail(body: VerifyEmailDto) {
    const raw = await this.redisService.get(`signup:${body.code}`);
    if (!raw) {
      throw new BadRequestException('Invalid or expired code');
    }

    const pending = JSON.parse(raw) as {
      email: string;
      firstName: string;
      passwordHash: string;
      role: string;
    };

    if (pending.email !== body.email) {
      throw new BadRequestException('Code does not match this email');
    }

    const existingUser = await this.userService.findByEmail(body.email);
    if (existingUser) {
      throw new BadRequestException('User already exist');
    }

    await this.userService.createUser({
      email: pending.email,
      firstName: pending.firstName,
      passwordHash: pending.passwordHash,
      role: pending.role as 'CONSUMER' | 'FARMER',
    });

    await this.redisService.del(`signup:${body.code}`);
    await this.redisService.del(`signup:email:${body.email}`);

    return { success: true, message: 'Email verified, you can now log in' };
  }

  async verifyUser(email: string, password: string): Promise<User> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException('Credentials are not valid');
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      throw new UnauthorizedException('Credentials are not valid');
    }

    return user;
  }

  async saveRefreshToken(userId: string, token: string) {
    const dbHash = await this.hashForDb(token);
    const redisHash = this.hashForRedis(token);

    const refreshToken = await this.prisma.refreshToken.create({
      data: {
        userId,
        tokenHash: dbHash,
        expiresAt: new Date(Date.now() + REFRESH_TTL_MS),
      },
    });

    await this.redisService.set(
      `refresh:${redisHash}`,
      refreshToken.id,
      REFRESH_TTL_SECONDS,
    );
  }

  async login(user: User) {
    const payload: TokenPayload = { userId: user.id, email: user.email };

    const accessToken = this.jwtService.sign(payload);

    const refreshToken = this.generateRefreshToken();
    await this.saveRefreshToken(user.id, refreshToken);

    return { accessToken, refreshToken };
  }

  async refresh(refreshToken: string) {
    const redisHash = this.hashForRedis(refreshToken);

    const tokenId = await this.redisService.get(`refresh:${redisHash}`);
    if (!tokenId) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const tokenRecord = await this.prisma.refreshToken.findUnique({
      where: { id: tokenId },
    });

    if (!tokenRecord || tokenRecord.revoked) {
      throw new UnauthorizedException('Refresh token already revoked');
    }

    if (new Date(tokenRecord.expiresAt) < new Date()) {
      throw new UnauthorizedException('Refresh token expired');
    }

    const revoked = await this.prisma.refreshToken.updateMany({
      where: { id: tokenId, revoked: false },
      data: { revoked: true },
    });

    if (revoked.count === 0) {
      throw new UnauthorizedException('Refresh token already revoked');
    }

    await this.redisService.del(`refresh:${redisHash}`);

    const newRefreshToken = this.generateRefreshToken();
    await this.saveRefreshToken(tokenRecord.userId, newRefreshToken);

    const user = await this.userService.findById(tokenRecord.userId);
    if (!user) {
      throw new UnauthorizedException('User no longer exists');
    }

    const accessToken = this.jwtService.sign({
      userId: user.id,
      email: user.email,
    });

    return { accessToken, refreshToken: newRefreshToken };
  }

  async logout(refreshToken: string) {
    const redisHash = this.hashForRedis(refreshToken);

    const tokenId = await this.redisService.get(`refresh:${redisHash}`);
    if (tokenId) {
      await this.prisma.refreshToken.updateMany({
        where: { id: tokenId, revoked: false },
        data: { revoked: true },
      });
    }
    await this.redisService.del(`refresh:${redisHash}`);

    return { message: 'User logged out successfully' };
  }
}
