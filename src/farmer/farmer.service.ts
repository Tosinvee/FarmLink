/* eslint-disable prettier/prettier */
import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SafeUser } from '../user/user.service';
import { UpdateFarmerDto } from './dto/update-farmer.dto';

const farmerInclude = {
  user: {
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      phone: true,
    },
  },
  farm: true,
  _count: {
    select: { products: true },
  },
} as const;

@Injectable()
export class FarmerService {
  constructor(private readonly prisma: PrismaService) {}

  private async getFarmerByUserId(userId: string) {
    const farmer = await this.prisma.farmer.findUnique({
      where: { userId },
      include: farmerInclude,
    });
    if (!farmer) {
      throw new NotFoundException('Farmer profile not found');
    }
    return farmer;
  }

  findAll() {
    return this.prisma.farmer.findMany({
      where: { user: { deletedAt: null } },
      include: farmerInclude,
      orderBy: { createdAt: 'desc' },
    });
  }

  findById(userId: string) {
    return this.getFarmerByUserId(userId);
  }

  async update(user: SafeUser, dto: UpdateFarmerDto) {
    if (user.role !== 'FARMER') {
      throw new ForbiddenException('Only farmer accounts can update a profile');
    }
    const farmer = await this.getFarmerByUserId(user.id);
    return this.prisma.farmer.update({
      where: { id: farmer.id },
      data: dto,
      include: farmerInclude,
    });
  }
}