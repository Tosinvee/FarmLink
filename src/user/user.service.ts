/* eslint-disable prettier/prettier */
import {
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { UpdateUserDto } from './dto/update-user.dto';

const userSelect = {
  id: true,
  email: true,
  firstName: true,
  lastName: true,
  phone: true,
  role: true,
  emailVerified: true,
  createdAt: true,
  updatedAt: true,
  deletedAt: true,
} as const;

export type SafeUser = Prisma.UserGetPayload<{ select: typeof userSelect }>;

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email, deletedAt: null },
    });
  }

  async findById(id: string) {
    return this.prisma.user.findUnique({
      where: { id, deletedAt: null },
      select: userSelect,
    });
  }

  async findAll() {
    return this.prisma.user.findMany({
      where: { deletedAt: null },
      orderBy: { createdAt: 'desc' },
      select: userSelect,
    });
  }

  async hashPassword(password: string) {
    const salt = await bcrypt.genSalt();
    return bcrypt.hash(password, salt);
  }

  async createUser(data: {
    email: string;
    passwordHash: string;
    firstName: string;
    role: 'CONSUMER' | 'FARMER';
  }) {
    if (data.role === 'FARMER') {
      return this.prisma.user.create({
        data: {
          email: data.email,
          password: data.passwordHash,
          firstName: data.firstName,
          emailVerified: true,
          role: 'FARMER',
          farmer: {
            create: {
              displayName: data.firstName,
            },
          },
        },
      });
    }

    return this.prisma.user.create({
      data: {
        email: data.email,
        password: data.passwordHash,
        firstName: data.firstName,
        emailVerified: true,
        role: 'CONSUMER',
      },
    });
  }

  async update(id: string, dto: UpdateUserDto) {
    try {
      return await this.prisma.user.update({
        where: { id, deletedAt: null },
        data: dto,
        select: userSelect,
      });
    } catch {
      throw new NotFoundException('User not found');
    }
  }

  async softDelete(id: string) {
    try {
      await this.prisma.user.update({
        where: { id, deletedAt: null },
        data: { deletedAt: new Date() },
      });
    } catch {
      throw new NotFoundException('User not found');
    }

    await this.prisma.refreshToken.updateMany({
      where: { userId: id, revoked: false },
      data: { revoked: true },
    });

    return { success: true, message: 'User deleted' };
  }
}