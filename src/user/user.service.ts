/* eslint-disable prettier/prettier */
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  async findByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }

  async findById(id: string) {
    return this.prisma.user.findUnique({ where: { id } });
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
              location: '',
              phone: '',
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
}